import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Form
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from backend.db.database import get_settings_db, SessionLocal, get_latest_network_stats
from backend.ai.xai import compute_dynamic_xai
from backend.core.ws_manager import manager
from backend.db.models import NetworkFlow, LLMChatSession, LLMChatMessage
from backend.db.schemas import NetworkFlowOut
from backend.monitoring.external_time import get_last_external_time, is_agent_offline
from backend.monitoring.stats import get_stats
from backend.ai.llm import get_ai_response
from backend.ai.speech import speech_to_text, text_to_speech
from backend.ai.upload import process_uploaded_file
from backend.ai.agents import (
    network_analyzer_agent,
    attack_observation_agent,
    auto_block_agent,
    email_report_agent,
    site_security_audit_agent,
)

router = APIRouter(prefix="/api", tags=["dashboard"])


class ChatRequest(BaseModel):
    message: str
    history: list[dict] | None = None
    session_id: Optional[str] = None


class NewChatRequest(BaseModel):
    title: Optional[str] = "New Chat"


async def get_dashboard_data():
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        active_model = "rf" if db_settings.active_model == "ml" else db_settings.active_model
        token = (db_settings.api_key or "").strip()
        mode = "api_agent" if token else "scapy"
        admin_email = db_settings.admin_email or "admin@network.local"
        auto_block = bool(db_settings.auto_block)
        block_mode = getattr(db_settings, "block_mode", "auto") or ("auto" if auto_block else "manual")
        confidence_thresh = db_settings.confidence_threshold or 85
    finally:
        db.close()

    is_fallback_active = mode == "api_agent" and is_agent_offline()
    data = get_latest_network_stats(model_type=active_model) or {}

    if "active_connections" in data and "connections" not in data:
        data["connections"] = data["active_connections"]
    elif "connections" in data and "active_connections" not in data:
        data["active_connections"] = data["connections"]

    if "risk_score" in data and "score" not in data:
        data["score"] = data["risk_score"]
    elif "score" in data and "risk_score" not in data:
        data["risk_score"] = data["score"]

    if "risk_message" in data and "message" not in data:
        data["message"] = data["risk_message"]
    elif "message" in data and "risk_message" not in data:
        data["risk_message"] = data["message"]

    stats = get_stats()
    analysis = network_analyzer_agent.analyze(stats)
    observation = attack_observation_agent.observe(stats, analysis)
    autoblock_res = auto_block_agent.enforce(stats, observation, auto_block)

    model_score = data.get("risk_score", 15)
    model_verdict = "Anomaly" if model_score > confidence_thresh else "Normal"
    agent_verdict = analysis.get("verdict", "Normal")

    match_status = (
        "MATCH - Agreement"
        if (model_verdict == "Normal" and agent_verdict == "Normal")
        or (model_verdict != "Normal" and agent_verdict != "Normal")
        else "DIVERGENCE - Verification Required"
    )

    comparison = {
        "detection_model": {
            "name": f"Detection Model ({active_model.upper()})",
            "active_model": active_model,
            "verdict": model_verdict,
            "score": model_score,
            "threshold": confidence_thresh,
            "status_badge": "danger" if model_verdict != "Normal" else "success",
        },
        "analyzing_agent": {
            "name": network_analyzer_agent.name,
            "verdict": agent_verdict,
            "analysis_text": analysis.get("analysis", "Network monitoring normal."),
            "threat_level": analysis.get("threat_level", "Low"),
            "confidence": analysis.get("confidence", 95),
            "status_badge": "danger" if agent_verdict == "Malicious" else ("warning" if agent_verdict == "Suspicious" else "success"),
        },
        "comparison_matrix": {
            "status": match_status,
            "is_match": "MATCH" in match_status,
            "summary": f"Model ({active_model.upper()}): {model_verdict} | Agent: {agent_verdict}",
            "agreement": analysis.get("agreement", True),
        },
    }

    data["monitoring_mode"] = mode
    data["is_fallback_active"] = is_fallback_active
    data["active_model"] = active_model
    data["has_api_token"] = bool(token)
    data["user_api_token"] = token[:8] if token else ""
    data["agent_last_seen"] = get_last_external_time()
    data["xai_explanation"] = compute_dynamic_xai(data, active_model)
    data["agent_analysis"] = analysis
    data["agent_observation"] = observation
    data["agent_autoblock"] = autoblock_res
    data["admin_email"] = admin_email
    data["auto_block"] = auto_block
    data["block_mode"] = block_mode
    data["comparison"] = comparison
    return data


@router.get("/dashboard-data")
async def get_dashboard_data_endpoint():
    return await get_dashboard_data()


@router.get("/dataset-explorer-data", response_model=list[NetworkFlowOut])
async def get_explorer_data():
    loop = asyncio.get_running_loop()

    def _query():
        db = SessionLocal()
        try:
            return db.query(NetworkFlow).order_by(NetworkFlow.id.desc()).limit(500).all()
        finally:
            db.close()

    flows = await loop.run_in_executor(None, _query)
    return flows


@router.get("/agents/status")
async def get_agents_status_endpoint():
    stats = get_stats()
    analysis = network_analyzer_agent.analyze(stats)
    observation = attack_observation_agent.observe(stats, analysis)

    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        interval_minutes = getattr(db_settings, "report_interval_minutes", 30) or 30
        email_alerts = bool(db_settings.email_alerts)
    finally:
        db.close()

    return {
        "analyzer": analysis,
        "observation": observation,
        "email_agent": {
            "name": email_report_agent.name,
            "interval_minutes": interval_minutes,
            "status": "Active" if email_alerts else "Disabled",
        },
    }


@router.post("/agents/send-report")
async def send_agent_report_endpoint():
    db = SessionLocal()
    try:
        settings = get_settings_db(db)
        admin_email = settings.admin_email or "admin@network.local"
    finally:
        db.close()

    stats = get_stats()
    analysis = network_analyzer_agent.analyze(stats)
    observation = attack_observation_agent.observe(stats, analysis)
    result = email_report_agent.generate_report(admin_email, stats, analysis, observation)
    return result


@router.post("/agents/site-audit")
async def run_site_audit_endpoint():
    """Run full codebase + linked site security audit on demand."""
    loop = asyncio.get_running_loop()

    def _do_audit():
        codebase_result = site_security_audit_agent.scan_codebase(".")
        linked_result = None
        try:
            db = SessionLocal()
            try:
                s = get_settings_db(db)
                linked_url = getattr(s, "linked_site_url", "") or ""
                linked_token = getattr(s, "linked_site_token", "") or ""
                if linked_url:
                    linked_result = site_security_audit_agent.scan_linked_site(linked_url, linked_token)
            finally:
                db.close()
        except Exception:
            pass

        return {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "codebase_audit": codebase_result,
            "linked_site_audit": linked_result,
            "total_vulnerabilities": (
                codebase_result.get("vulnerabilities_count", 0) +
                (len(linked_result.get("vulnerabilities", [])) if linked_result else 0)
            ),
        }

    result = await loop.run_in_executor(None, _do_audit)
    return result


# ─── LLM Chat Session Endpoints ───────────────────────────────────────────────

@router.post("/chats/new")
async def create_new_chat(req: NewChatRequest = NewChatRequest()):
    """Create a new chat session and return its UUID."""
    db = SessionLocal()
    try:
        session = LLMChatSession(title=req.title or "New Chat")
        db.add(session)
        db.commit()
        db.refresh(session)
        return {
            "session_id": session.id,
            "title": session.title,
            "created_at": session.created_at.isoformat(),
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.get("/chats")
async def list_chats():
    """List all past chat sessions."""
    db = SessionLocal()
    try:
        sessions = db.query(LLMChatSession).order_by(LLMChatSession.updated_at.desc()).all()
        return [
            {
                "session_id": s.id,
                "title": s.title,
                "created_at": s.created_at.isoformat(),
                "updated_at": s.updated_at.isoformat() if s.updated_at else s.created_at.isoformat(),
            }
            for s in sessions
        ]
    finally:
        db.close()


@router.get("/chats/{session_id}")
async def get_chat_history(session_id: str):
    """Get all messages in a chat session."""
    db = SessionLocal()
    try:
        session = db.query(LLMChatSession).filter(LLMChatSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Chat session not found")
        messages = [
            {
                "id": m.id,
                "role": m.role,
                "content": m.content,
                "created_at": m.created_at.isoformat(),
            }
            for m in session.messages
        ]
        return {
            "session_id": session.id,
            "title": session.title,
            "messages": messages,
        }
    finally:
        db.close()


@router.delete("/chats/{session_id}")
async def delete_chat(session_id: str):
    """Delete a chat session and all its messages."""
    db = SessionLocal()
    try:
        session = db.query(LLMChatSession).filter(LLMChatSession.id == session_id).first()
        if not session:
            raise HTTPException(status_code=404, detail="Chat session not found")
        db.delete(session)
        db.commit()
        return {"status": "success", "message": "Chat session deleted"}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


@router.post("/chat")
async def chat_endpoint(req: ChatRequest):
    try:
        history = req.history or []
        session_id = req.session_id

        if session_id:
            db = SessionLocal()
            try:
                session = db.query(LLMChatSession).filter(LLMChatSession.id == session_id).first()
                if not session:
                    # Auto-create session if ID provided but missing in DB
                    title = req.message[:60] + ("..." if len(req.message) > 60 else "") if req.message else "New Chat"
                    session = LLMChatSession(id=session_id, title=title)
                    db.add(session)
                    db.commit()
                    db.refresh(session)
                
                db_history = [
                    {"role": m.role, "content": m.content}
                    for m in session.messages
                ]
                if not history:
                    history = db_history
                
                if session.title in ("New Chat", "Untitled Chat") and req.message:
                    session.title = req.message[:60] + ("..." if len(req.message) > 60 else "")
                    session.updated_at = datetime.utcnow()
                    db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()

        reply = await get_ai_response(req.message, history=history)

        # Save user message and AI reply to DB
        if session_id:
            db = SessionLocal()
            try:
                session = db.query(LLMChatSession).filter(LLMChatSession.id == session_id).first()
                if session:
                    user_msg = LLMChatMessage(session_id=session_id, role="user", content=req.message)
                    ai_msg = LLMChatMessage(session_id=session_id, role="assistant", content=reply)
                    db.add(user_msg)
                    db.add(ai_msg)
                    session.updated_at = datetime.utcnow()
                    db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()

        return {"reply": reply, "response": reply, "session_id": session_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/speech-to-text")
async def stt_endpoint(file: UploadFile = File(...)):
    try:
        text = await speech_to_text(file)
        ai_response = await get_ai_response(text)
        audio_url = await text_to_speech(ai_response)
        return {
            "user_text": text,
            "ai_text": ai_response,
            "reply": ai_response,
            "response": ai_response,
            "audio_url": audio_url,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/upload-file")
async def upload_file_endpoint(
    file: UploadFile = File(...),
    prompt: str = Form("Analyze this file for any security threats or anomalies."),
):
    try:
        file_content = await process_uploaded_file(file)
        combined_message = f"{prompt}\n\nFile Content:\n{file_content}"
        ai_response = await get_ai_response(combined_message)
        audio_url = await text_to_speech(ai_response)
        return {
            "file_name": file.filename,
            "ai_text": ai_response,
            "reply": ai_response,
            "response": ai_response,
            "audio_url": audio_url,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.websocket("/live-traffic")
@router.websocket("/ws/live-traffic")
async def websocket_live_traffic(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            try:
                await asyncio.wait_for(websocket.receive_text(), timeout=2.0)
            except asyncio.TimeoutError:
                pass
    except WebSocketDisconnect:
        await manager.disconnect(websocket)
    except Exception:
        await manager.disconnect(websocket)


async def global_traffic_broadcaster():
    while True:
        await asyncio.sleep(2)
        if manager.active_count > 0:
            try:
                data = await get_dashboard_data()
                await manager.broadcast(data)
            except Exception:
                pass
