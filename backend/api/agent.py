import io
import os
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import StreamingResponse
from backend.core.security import verify_agent_token

router = APIRouter(prefix="/api", tags=["agent"])

_AGENT_TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "..", "core", "agent_template.py")


@router.get("/download-agent")
async def download_agent(
    request: Request,
    _token: str = Depends(verify_agent_token),
):
    base_url = str(request.base_url).rstrip("/")
    if not os.path.exists(_AGENT_TEMPLATE_PATH):
        raise HTTPException(status_code=404, detail="Agent template not found.")

    with open(_AGENT_TEMPLATE_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    content = content.replace("REPLACE_WITH_USER_TOKEN", _token)
    content = content.replace("REPLACE_WITH_YOUR_SITE_URL", base_url)

    return StreamingResponse(
        io.BytesIO(content.encode()),
        media_type="text/x-python",
        headers={"Content-Disposition": "attachment; filename=sentinel_agent.py"},
    )
