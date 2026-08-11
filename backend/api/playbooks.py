"""
SOAR Playbooks API Router
Provides full CRUD for security response playbooks and a webhook automation execution engine.
Playbooks define IF [condition] THEN [action] rules that fire automatically based on live stats.
"""

import json
import uuid
import asyncio
import requests as http_requests
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from backend.db.database import SessionLocal, log_incident_event
from backend.db.models import Playbook
from backend.monitoring.stats import get_stats
from backend.ai.agents import email_report_agent
from backend.services.ip_service import block_ip

router = APIRouter(prefix="/api", tags=["playbooks"])

# In-memory trigger history log (last 100 events)
_trigger_history: List[dict] = []


# ─── Pydantic Schemas ───────────────────────────────────────────────────

class PlaybookCreate(BaseModel):
    name: str
    description: Optional[str] = ""
    condition_metric: str        # e.g. 'packet_rate', 'risk_score', 'attack_type', 'blocked_ip_count'
    condition_operator: str      # '>', '<', '>=', '<=', '==', 'contains'
    condition_value: str         # threshold value as string
    action_type: str             # 'block_ip', 'send_email', 'webhook', 'log_only'
    action_config: Optional[str] = "{}"  # JSON string with extra config
    webhook_url: Optional[str] = ""
    webhook_method: Optional[str] = "POST"
    enabled: Optional[bool] = True


class PlaybookUpdate(PlaybookCreate):
    pass


# ─── CRUD Endpoints ─────────────────────────────────────────────────────

@router.get("/playbooks", status_code=status.HTTP_200_OK)
async def list_playbooks():
    """Returns all configured playbooks sorted by creation date."""
    db = SessionLocal()
    try:
        playbooks = db.query(Playbook).order_by(Playbook.created_at.desc()).all()
        return [_serialize_playbook(p) for p in playbooks]
    finally:
        db.close()


@router.post("/playbooks", status_code=status.HTTP_201_CREATED)
async def create_playbook(body: PlaybookCreate):
    """Creates a new SOAR playbook rule."""
    db = SessionLocal()
    try:
        pb = Playbook(
            id=str(uuid.uuid4()),
            name=body.name,
            description=body.description or "",
            condition_metric=body.condition_metric,
            condition_operator=body.condition_operator,
            condition_value=body.condition_value,
            action_type=body.action_type,
            action_config=body.action_config or "{}",
            webhook_url=body.webhook_url or "",
            webhook_method=body.webhook_method or "POST",
            enabled=body.enabled if body.enabled is not None else True,
            trigger_count=0,
            created_at=datetime.utcnow(),
        )
        db.add(pb)
        db.commit()
        db.refresh(pb)
        return _serialize_playbook(pb)
    finally:
        db.close()


@router.put("/playbooks/{playbook_id}", status_code=status.HTTP_200_OK)
async def update_playbook(playbook_id: str, body: PlaybookUpdate):
    """Updates an existing playbook by ID."""
    db = SessionLocal()
    try:
        pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not pb:
            raise HTTPException(status_code=404, detail="Playbook not found")
        pb.name = body.name
        pb.description = body.description or ""
        pb.condition_metric = body.condition_metric
        pb.condition_operator = body.condition_operator
        pb.condition_value = body.condition_value
        pb.action_type = body.action_type
        pb.action_config = body.action_config or "{}"
        pb.webhook_url = body.webhook_url or ""
        pb.webhook_method = body.webhook_method or "POST"
        pb.enabled = body.enabled if body.enabled is not None else True
        db.commit()
        db.refresh(pb)
        return _serialize_playbook(pb)
    finally:
        db.close()


@router.delete("/playbooks/{playbook_id}", status_code=status.HTTP_200_OK)
async def delete_playbook(playbook_id: str):
    """Deletes a playbook by ID."""
    db = SessionLocal()
    try:
        pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not pb:
            raise HTTPException(status_code=404, detail="Playbook not found")
        db.delete(pb)
        db.commit()
        return {"success": True, "message": f"Playbook '{pb.name}' deleted"}
    finally:
        db.close()


@router.post("/playbooks/{playbook_id}/toggle", status_code=status.HTTP_200_OK)
async def toggle_playbook(playbook_id: str):
    """Toggles the enabled/disabled state of a playbook."""
    db = SessionLocal()
    try:
        pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not pb:
            raise HTTPException(status_code=404, detail="Playbook not found")
        pb.enabled = not pb.enabled
        db.commit()
        db.refresh(pb)
        return {"success": True, "enabled": pb.enabled, "playbook": _serialize_playbook(pb)}
    finally:
        db.close()


@router.post("/playbooks/{playbook_id}/test", status_code=status.HTTP_200_OK)
async def test_playbook(playbook_id: str):
    """Manually triggers a playbook test run using current live stats."""
    db = SessionLocal()
    try:
        pb = db.query(Playbook).filter(Playbook.id == playbook_id).first()
        if not pb:
            raise HTTPException(status_code=404, detail="Playbook not found")

        current_stats = get_stats()
        result = await _execute_playbook(pb, current_stats, force=True, db=db)
        return {
            "success": True,
            "playbook_name": pb.name,
            "test_result": result,
            "stats_snapshot": {
                "packet_rate": current_stats.get("packet_rate", 0),
                "risk_score": current_stats.get("score", 0),
                "connections": current_stats.get("connections", 0),
            },
        }
    finally:
        db.close()


@router.get("/playbooks/history", status_code=status.HTTP_200_OK)
async def get_playbook_history():
    """Returns the last 100 playbook trigger history events."""
    return {"history": _trigger_history[-100:]}


# ─── Execution Engine ────────────────────────────────────────────────────

def _evaluate_condition(metric_value, operator: str, threshold: str) -> bool:
    """
    Evaluates a playbook condition: metric_value [operator] threshold.
    Returns True if the condition is met, False otherwise.
    """
    try:
        if operator == "contains":
            return str(threshold).lower() in str(metric_value).lower()
        numeric_val = float(metric_value) if metric_value is not None else 0.0
        threshold_val = float(threshold)
        if operator == ">":
            return numeric_val > threshold_val
        elif operator == "<":
            return numeric_val < threshold_val
        elif operator == ">=":
            return numeric_val >= threshold_val
        elif operator == "<=":
            return numeric_val <= threshold_val
        elif operator == "==":
            return numeric_val == threshold_val
        # Unknown operator — default to False
        return False
    except (ValueError, TypeError):
        # Fallback to string comparison for non-numeric values
        return str(metric_value).lower() == str(threshold).lower()


async def _execute_playbook(pb: Playbook, stats: dict, force: bool = False, db=None) -> dict:
    """
    Executes the action defined in a playbook.
    Supports: block_ip, send_email, webhook, log_only.
    """
    action_result = {"action": pb.action_type, "status": "executed"}

    try:
        config = json.loads(pb.action_config or "{}")
    except json.JSONDecodeError:
        config = {}

    timestamp = datetime.utcnow().isoformat()

    if pb.action_type == "send_email":
        # Send notification email via Sentinel email agent
        email_to = config.get("email", "admin@network.local")
        subject = f"[Sentinel SOAR] Playbook Triggered: {pb.name}"
        body = (
            f"Sentinel SOAR Alert\n\n"
            f"Playbook: {pb.name}\n"
            f"Condition: {pb.condition_metric} {pb.condition_operator} {pb.condition_value}\n"
            f"Action: Send Email\n"
            f"Timestamp: {timestamp}\n\n"
            f"Current Stats Snapshot:\n"
            f"  Packet Rate: {stats.get('packet_rate', 0)} pps\n"
            f"  Risk Score: {stats.get('score', 0)}%\n"
            f"  Active Connections: {stats.get('connections', 0)}\n"
            f"  Is Anomaly: {stats.get('is_anomaly', False)}\n"
        )
        try:
            email_report_agent.send_email(email_to, subject, body)
            action_result["status"] = "email_sent"
            action_result["recipient"] = email_to
        except Exception as e:
            action_result["status"] = f"email_failed: {e}"

    elif pb.action_type == "webhook":
        # Fire HTTP webhook with JSON payload
        webhook_url = pb.webhook_url or config.get("url", "")
        if webhook_url:
            payload = {
                "event": "playbook_triggered",
                "playbook_id": pb.id,
                "playbook_name": pb.name,
                "condition": f"{pb.condition_metric} {pb.condition_operator} {pb.condition_value}",
                "action_taken": pb.action_type,
                "timestamp": timestamp,
                "stats_snapshot": {
                    "packet_rate": stats.get("packet_rate", 0),
                    "risk_score": stats.get("score", 0),
                    "connections": stats.get("connections", 0),
                    "is_anomaly": stats.get("is_anomaly", False),
                },
            }
            try:
                method = (pb.webhook_method or "POST").upper()
                if method == "GET":
                    resp = http_requests.get(webhook_url, params=payload, timeout=8)
                else:
                    resp = http_requests.post(
                        webhook_url, json=payload,
                        headers={"Content-Type": "application/json", "User-Agent": "Sentinel-IDS/3.0"},
                        timeout=8,
                    )
                action_result["status"] = f"webhook_fired (HTTP {resp.status_code})"
                action_result["webhook_url"] = webhook_url
            except Exception as e:
                action_result["status"] = f"webhook_failed: {e}"
        else:
            action_result["status"] = "webhook_skipped (no URL)"

    elif pb.action_type == "block_ip":
        # Actually block the IP via the shared IP service (persists to blocked_ips table).
        target_ip = config.get("ip") or stats.get("anomaly_ip") or ""
        if target_ip:
            was_blocked = await block_ip(target_ip, reason="PLAYBOOK", attack_type=f"SOAR: {pb.name}")
            action_result["status"] = "ip_blocked" if was_blocked else "ip_already_blocked"
            action_result["target_ip"] = target_ip
        else:
            action_result["status"] = "block_skipped (no target IP available)"
            action_result["target_ip"] = None

    elif pb.action_type == "log_only":
        action_result["status"] = "logged"

    # Record trigger history
    history_entry = {
        "id": str(uuid.uuid4()),
        "playbook_id": pb.id,
        "playbook_name": pb.name,
        "condition": f"{pb.condition_metric} {pb.condition_operator} {pb.condition_value}",
        "action": pb.action_type,
        "result": action_result["status"],
        "triggered_at": timestamp,
        "forced": force,
    }
    _trigger_history.append(history_entry)
    if len(_trigger_history) > 100:
        _trigger_history.pop(0)

    # Record on the real incident timeline (replaces the old mock timeline entries)
    _severity_by_action = {"block_ip": "High", "webhook": "Medium", "send_email": "Medium", "log_only": "Info"}
    log_incident_event(
        event_type="SOAR Playbook",
        title=f"Playbook '{pb.name}' triggered",
        severity=_severity_by_action.get(pb.action_type, "Info"),
        details=(
            f"Condition: {pb.condition_metric} {pb.condition_operator} {pb.condition_value} | "
            f"Action: {pb.action_type} | Result: {action_result['status']}"
        ),
        source="playbooks",
    )

    # Update playbook trigger stats in DB
    if db:
        pb.trigger_count = (pb.trigger_count or 0) + 1
        pb.last_triggered = datetime.utcnow()
        db.commit()

    return action_result


async def evaluate_playbooks(current_stats: dict) -> None:
    """
    Evaluates all enabled playbooks against current live system statistics.
    Called periodically by monitoring loops. Opens a fresh DB session per
    matched playbook so each execution is independent and thread-safe.
    """
    db = SessionLocal()
    try:
        playbooks = db.query(Playbook).filter(Playbook.enabled == True).all()
        # Snapshot the playbook data (id, condition, action) before closing db
        matched_ids = []
        for pb in playbooks:
            metric_key_map = {
                "packet_rate": current_stats.get("packet_rate", 0),
                "risk_score": current_stats.get("score", 0),
                "connections": current_stats.get("connections", 0),
                "blocked_ip_count": current_stats.get("blocked_count", 0),
                "is_anomaly": current_stats.get("is_anomaly", False),
                "attack_type": current_stats.get("attack_type", ""),
            }
            metric_value = metric_key_map.get(pb.condition_metric, 0)
            if _evaluate_condition(metric_value, pb.condition_operator, pb.condition_value):
                matched_ids.append(pb.id)
    finally:
        db.close()

    # Execute each matched playbook in its own fresh DB session
    for pb_id in matched_ids:
        async def _run_one(pid: str):
            fresh_db = SessionLocal()
            try:
                pb_obj = fresh_db.query(Playbook).filter(Playbook.id == pid).first()
                if pb_obj:
                    await _execute_playbook(pb_obj, current_stats, db=fresh_db)
            finally:
                fresh_db.close()
        asyncio.create_task(_run_one(pb_id))


# ─── Helper ─────────────────────────────────────────────────────────────

def _serialize_playbook(pb: Playbook) -> dict:
    """Converts a Playbook ORM object to a JSON-serializable dict."""
    return {
        "id": pb.id,
        "name": pb.name,
        "description": pb.description or "",
        "condition_metric": pb.condition_metric,
        "condition_operator": pb.condition_operator,
        "condition_value": pb.condition_value,
        "action_type": pb.action_type,
        "action_config": pb.action_config or "{}",
        "webhook_url": pb.webhook_url or "",
        "webhook_method": pb.webhook_method or "POST",
        "enabled": pb.enabled,
        "trigger_count": pb.trigger_count or 0,
        "last_triggered": pb.last_triggered.isoformat() if pb.last_triggered else None,
        "created_at": pb.created_at.isoformat() if pb.created_at else None,
    }