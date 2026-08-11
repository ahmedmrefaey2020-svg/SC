from fastapi import APIRouter, Request, Depends, status, HTTPException
import secrets
from backend.core.security import _get_api_token
from urllib.parse import unquote
from backend.db.schemas import BlockIPSchema, ExternalIngestPayload
from backend.core.security import verify_api_agent_mode
from backend.core.config import get_settings
from backend.core.rate_limit import limiter
from backend.services.ip_service import block_ip, unblock_ip, invalidate_blocked_ip_cache
from backend.monitoring.prediction import ingest_external_batch
from backend.db.database import get_settings_db, SessionLocal
from backend.db.models import BlockedIP

_cfg = get_settings()
router = APIRouter(prefix="/api", tags=["security"])


@router.post("/block-ip", status_code=status.HTTP_200_OK)
@limiter.limit(_cfg.API_RATE_LIMIT_BLOCK)
async def block_ip_endpoint(request: Request, data: BlockIPSchema):
    # Determine whether caller provided a valid API agent token
    provided = (request.headers.get("token") or request.query_params.get("token") or "").strip()
    stored = _get_api_token()
    is_api_agent = False
    try:
        if provided and stored and secrets.compare_digest(provided, stored):
            is_api_agent = True
    except Exception:
        is_api_agent = False

    reason = "AUTO" if is_api_agent else "MANUAL"
    attack_type = "API Agent Block" if is_api_agent else "Manual Administrator Block"

    added = await block_ip(
        ip=data.ip,
        protocol="TCP",
        port=0,
        src_bytes=0.0,
        reason=reason,
        attack_type=attack_type,
    )
    if added:
        return {"status": "success", "message": f"IP {data.ip} has been manually blocked."}
    return {"status": "info", "message": "IP already blocked."}


@router.post("/unblock-ip", status_code=status.HTTP_200_OK)
@limiter.limit(_cfg.API_RATE_LIMIT_BLOCK)
async def unblock_ip_endpoint(request: Request, data: BlockIPSchema):
    removed = await unblock_ip(data.ip)
    if removed:
        return {"status": "success", "message": f"IP {data.ip} has been unblocked."}
    return {"status": "info", "message": "IP was not in the blocklist."}


@router.get("/blocked-ips", status_code=status.HTTP_200_OK)
async def get_blocked_ips_endpoint():
    db = SessionLocal()
    try:
        rows = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).all()
        return [
            {
                "id": r.id,
                "ip_address": r.ip_address,
                "protocol": r.protocol or "TCP",
                "port": r.port or 0,
                "src_bytes": round(r.src_bytes or 0.0, 2),
                "blocked_at": r.blocked_at.strftime("%Y-%m-%d %H:%M:%S") if r.blocked_at else "N/A",
                "reason": getattr(r, "reason", "MANUAL") or "MANUAL",
                "attack_type": getattr(r, "attack_type", "Unknown") or "Unknown",
                "block_source": "Automatic" if (getattr(r, "reason", "MANUAL") or "MANUAL").upper() == "AUTO" else "Manual",
            }
            for r in rows
        ]
    finally:
        db.close()


@router.delete("/blocked-ips/{ip}", status_code=status.HTTP_200_OK)
async def delete_blocked_ip_endpoint(ip: str):
    decoded_ip = unquote(ip)
    removed = await unblock_ip(decoded_ip)
    if removed:
        return {"status": "success", "message": f"IP {decoded_ip} has been unblocked."}
    raise HTTPException(status_code=404, detail=f"IP {decoded_ip} not found in blocklist.")


@router.delete("/blocked-ips", status_code=status.HTTP_200_OK)
async def delete_all_blocked_ips_endpoint():
    db = SessionLocal()
    try:
        count = db.query(BlockedIP).count()
        db.query(BlockedIP).delete()
        db.commit()
        invalidate_blocked_ip_cache()
        return {"status": "success", "message": f"Unblocked all {count} IPs."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.post("/external-data-ingest")
@limiter.limit(_cfg.API_RATE_LIMIT_INGEST)
async def ingest_external_data(
    request: Request,
    payload: ExternalIngestPayload,
    _token: str = Depends(verify_api_agent_mode),
):
    from backend.services.ip_service import is_ip_blocked_sync

    client_ip = request.client.host if request.client else ""
    base_url = str(request.base_url).rstrip("/")
    block_page_url = f"{base_url}/blocked"

    # If calling IP is blocked
    if client_ip and is_ip_blocked_sync(client_ip):
        raise HTTPException(
            status_code=403,
            detail={
                "detail": "Access denied. Your IP has been blocked by Sentinel IDS.",
                "blocked": True,
                "client_ip": client_ip,
                "block_page_url": block_page_url,
                "redirect_url": block_page_url,
            }
        )

    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        active_model = "rf" if db_settings.active_model == "ml" else db_settings.active_model
    finally:
        db.close()

    records_features = [r.to_feature_list() for r in payload.records]
    metadata = [r.metadata() for r in payload.records]
    result = ingest_external_batch(records_features, metadata, active_model)

    # Collect blocked IPs from batch or cache
    blocked_srcs = [
        meta.get("src") for meta in metadata
        if meta.get("src") and is_ip_blocked_sync(meta.get("src"))
    ]

    return {
        "status": "analyzed",
        "result": result,
        "blocked_ips": list(set(blocked_srcs)),
        "block_page_url": block_page_url,
        "redirect_url": block_page_url,
    }

