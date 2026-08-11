import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.templating import Jinja2Templates
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from backend.core.config import get_settings
from backend.core.rate_limit import limiter
from backend.services.ip_service import is_ip_blocked
from backend.monitoring.prediction import start_monitor, stop_monitor
from backend.ai.agents import run_periodic_email_report_loop
from backend.api import dashboard, security_ops, scanner, agent
from backend.api import settings as settings_router
from backend.api import pages
from backend.api import playbooks as playbooks_router
from backend.api import advanced_features as advanced_features_router

_cfg = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from backend.api.dashboard import global_traffic_broadcaster
    start_monitor()
    broadcaster_task = asyncio.create_task(global_traffic_broadcaster())
    email_report_task = asyncio.create_task(run_periodic_email_report_loop())
    yield
    broadcaster_task.cancel()
    email_report_task.cancel()
    stop_monitor()


app = FastAPI(
    title="Sentinel IDS",
    description="Intelligent Intrusion Detection System",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

_origins = [o.strip() for o in _cfg.ALLOWED_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins if _origins != ["*"] else ["*"],
    allow_credentials=_origins != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])
BASE_DIR = Path(__file__).resolve().parent
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

app.include_router(dashboard.router)
app.include_router(settings_router.router)
app.include_router(security_ops.router)
app.include_router(pages.router)
app.include_router(agent.router)
app.include_router(scanner.router)
app.include_router(playbooks_router.router)
app.include_router(advanced_features_router.router)

_templates = Jinja2Templates(directory="templates")


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    path = request.url.path
    skip_ip_check = (
        path.startswith("/static")
        or path.startswith("/docs")
        or path.startswith("/redoc")
        or path.startswith("/openapi")
        or path.startswith("/api/ws")
        or path.startswith("/ws")
        or "live-traffic" in path
        or path == "/blocked"
    )

    _SECURITY_HEADERS = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }

    if skip_ip_check:
        response = await call_next(request)
        for k, v in _SECURITY_HEADERS.items():
            response.headers[k] = v
        return response

    client_ip = request.client.host if request.client else None
    if client_ip and await is_ip_blocked(client_ip):
        accept = request.headers.get("accept", "")
        if "text/html" in accept:
            from backend.db.database import SessionLocal
            from backend.db.models import BlockedIP
            db = SessionLocal()
            try:
                row = db.query(BlockedIP).filter(BlockedIP.ip_address == client_ip).first()
                blocked_at = row.blocked_at.strftime("%Y-%m-%d %H:%M:%S") if row and row.blocked_at else "N/A"
                reason = getattr(row, "reason", "MANUAL") if row else "MANUAL"
                attack_type = getattr(row, "attack_type", "Unknown") if row else "Unknown"
            finally:
                db.close()
            return _templates.TemplateResponse(
                "blocked.html",
                {
                    "request": request,
                    "client_ip": client_ip,
                    "blocked_at": blocked_at,
                    "reason": reason,
                    "attack_type": attack_type,
                },
                status_code=403,
            )
        base_url = str(request.base_url).rstrip("/")
        block_page_url = f"{base_url}/blocked"
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Access denied. Your IP has been blocked by Sentinel IDS.",
                "blocked": True,
                "client_ip": client_ip,
                "block_page_url": block_page_url,
                "redirect_url": block_page_url,
            },
        )


    response = await call_next(request)
    for k, v in _SECURITY_HEADERS.items():
        response.headers[k] = v
    return response
