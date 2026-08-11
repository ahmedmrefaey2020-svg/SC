from fastapi import APIRouter, Request
from backend.db.database import get_settings_db, SessionLocal, invalidate_settings_cache, sync_system_settings
from backend.core.security import invalidate_token_cache
from backend.db.schemas import SettingsSchema
from backend.core.config import get_settings
from backend.core.rate_limit import limiter

_cfg = get_settings()
router = APIRouter(prefix="/api", tags=["settings"])


def _mask_token(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}{'*' * (len(token) - 8)}{token[-4:]}"


@router.post("/update-settings")
@limiter.limit(_cfg.API_RATE_LIMIT_SETTINGS)
async def update_settings(request: Request, settings: SettingsSchema):
    settings_dict = {
        "org_name": settings.orgName,
        "admin_email": settings.adminEmail,
        "timezone": settings.timezone,
        "push_notifications": settings.pushNotifications,
        "email_alerts": settings.emailAlerts,
        "auto_block": settings.autoBlock,
        "block_mode": settings.blockMode,
        "active_model": settings.activeModel,
        "confidence_threshold": settings.confidence,
        "api_key": settings.token,
        "monitoring_mode": settings.monitoringMode,
        "report_interval_minutes": settings.reportInterval,
        "theme_mode": settings.themeMode,
        "smtp_server": settings.smtpServer,
        "smtp_port": settings.smtpPort,
        "smtp_user": settings.smtpUser,
        "smtp_pass": settings.smtpPass,
        "smtp_use_tls": settings.smtpUseTls,
        "linked_site_url": settings.linkedSiteUrl,
        "linked_site_token": settings.linkedSiteToken,
    }
    sync_system_settings(settings_dict)
    invalidate_settings_cache()
    invalidate_token_cache()

    return {
        "status": "success",
        "monitoringMode": settings.monitoringMode,
        "hasToken": bool(settings.token),
        "reportInterval": settings.reportInterval,
        "themeMode": settings.themeMode,
        "blockMode": settings.blockMode,
    }


@router.get("/get-settings")
async def get_settings_endpoint():
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        token = (db_settings.api_key or "").strip()
        mode = "api_agent" if token else "scapy"
        return {
            "orgName": db_settings.org_name,
            "adminEmail": db_settings.admin_email,
            "timezone": db_settings.timezone,
            "pushNotifications": db_settings.push_notifications,
            "emailAlerts": db_settings.email_alerts,
            "autoBlock": db_settings.auto_block,
            "blockMode": getattr(db_settings, "block_mode", "auto") or "auto",
            "activeModel": "rf" if db_settings.active_model == "ml" else db_settings.active_model,
            "confidence": db_settings.confidence_threshold,
            "token": token,
            "tokenPreview": _mask_token(token),
            "monitoringMode": mode,
            "hasToken": bool(token),
            "reportInterval": getattr(db_settings, "report_interval_minutes", 30) or 30,
            "themeMode": getattr(db_settings, "theme_mode", "dark") or "dark",
            "smtpServer": getattr(db_settings, "smtp_server", "") or "",
            "smtpPort": getattr(db_settings, "smtp_port", 587) or 587,
            "smtpUser": getattr(db_settings, "smtp_user", "") or "",
            "smtpPass": getattr(db_settings, "smtp_pass", "") or "",
            "smtpUseTls": getattr(db_settings, "smtp_use_tls", True) if getattr(db_settings, "smtp_use_tls", None) is not None else True,
            "linkedSiteUrl": getattr(db_settings, "linked_site_url", "") or "",
            "linkedSiteToken": getattr(db_settings, "linked_site_token", "") or "",
        }
    finally:
        db.close()


@router.post("/send-test-email")
async def send_test_email_endpoint(request: Request):
    from backend.ai.agents import email_report_agent
    db = SessionLocal()
    try:
        settings = get_settings_db(db)
        recipient = settings.admin_email or "admin@network.local"
    finally:
        db.close()

    subject = "Sentinel IDS - SMTP Test Email Verification"
    body = (
        "Hello!\n\n"
        "This is a test verification email from your Sentinel IDS Platform.\n"
        "If you received this message, your SMTP credentials and email delivery system are configured correctly!\n\n"
        "Sentinel Security Team"
    )
    success, detail_msg = email_report_agent.send_email_detailed(recipient, subject, body)
    if success:
        return {"status": "success", "message": f"Test email successfully delivered to {recipient}"}
    return {"status": "error", "message": detail_msg}


