import time
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool
from backend.db.models import Base, SystemSetting, BlockedIP, IncidentEvent, HoneypotLog
from backend.core.config import get_settings

_cfg = get_settings()

scapy_engine = create_engine(
    _cfg.DATABASE_URL,
    connect_args={"check_same_thread": False, "timeout": 60},
    poolclass=NullPool,
    pool_pre_ping=True,
)

api_engine = create_engine(
    _cfg.API_DATABASE,
    connect_args={"check_same_thread": False, "timeout": 60},
    poolclass=NullPool,
    pool_pre_ping=True,
)


@event.listens_for(scapy_engine, "connect")
@event.listens_for(api_engine, "connect")
def set_sqlite_pragma(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA busy_timeout = 60000")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA cache_size=-64000")
    cursor.execute("PRAGMA temp_store=MEMORY")
    cursor.close()


ScapySessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=scapy_engine)
ApiSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=api_engine)

Base.metadata.create_all(bind=scapy_engine)
Base.metadata.create_all(bind=api_engine)


def _migrate_sqlite_columns():
    for engine in (scapy_engine, api_engine):
        try:
            with engine.connect() as conn:
                for stmt in [
                    "ALTER TABLE system_settings ADD COLUMN report_interval_minutes INTEGER DEFAULT 30",
                    "ALTER TABLE system_settings ADD COLUMN theme_mode VARCHAR DEFAULT 'dark'",
                    "ALTER TABLE system_settings ADD COLUMN smtp_server VARCHAR DEFAULT ''",
                    "ALTER TABLE system_settings ADD COLUMN smtp_port INTEGER DEFAULT 587",
                    "ALTER TABLE system_settings ADD COLUMN smtp_user VARCHAR DEFAULT ''",
                    "ALTER TABLE system_settings ADD COLUMN smtp_pass VARCHAR DEFAULT ''",
                    "ALTER TABLE system_settings ADD COLUMN smtp_use_tls BOOLEAN DEFAULT 1",
                    "ALTER TABLE system_settings ADD COLUMN linked_site_url VARCHAR DEFAULT ''",
                    "ALTER TABLE system_settings ADD COLUMN linked_site_token VARCHAR DEFAULT ''",
                    "ALTER TABLE blocked_ips ADD COLUMN reason VARCHAR DEFAULT 'MANUAL'",
                    "ALTER TABLE blocked_ips ADD COLUMN attack_type VARCHAR DEFAULT 'Unknown'",
                    # New tables created via SQLAlchemy metadata, migrations for safety
                    "CREATE TABLE IF NOT EXISTS llm_chat_sessions (id VARCHAR(36) PRIMARY KEY, title VARCHAR(255) NOT NULL DEFAULT 'New Chat', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
                    "CREATE TABLE IF NOT EXISTS llm_chat_messages (id VARCHAR(36) PRIMARY KEY, session_id VARCHAR(36) NOT NULL REFERENCES llm_chat_sessions(id) ON DELETE CASCADE, role VARCHAR(20) NOT NULL, content TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
                    "CREATE TABLE IF NOT EXISTS auto_train_events (id VARCHAR(36) PRIMARY KEY, trigger_reason VARCHAR NOT NULL DEFAULT 'Model divergence detected', models_trained VARCHAR NOT NULL DEFAULT 'lstm,rf,xgboost,lr', triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP, result VARCHAR NOT NULL DEFAULT 'success')",
                    "CREATE TABLE IF NOT EXISTS incident_events (id VARCHAR(36) PRIMARY KEY, event_type VARCHAR NOT NULL, title VARCHAR NOT NULL, severity VARCHAR NOT NULL DEFAULT 'Info', details TEXT DEFAULT '', source VARCHAR DEFAULT 'system', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
                    "CREATE TABLE IF NOT EXISTS honeypot_logs (id VARCHAR(36) PRIMARY KEY, attacker_ip VARCHAR NOT NULL, decoy_service VARCHAR NOT NULL, port INTEGER DEFAULT 0, payload_attempted TEXT DEFAULT '', action_taken VARCHAR DEFAULT 'Logged', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
                ]:
                    try:
                        conn.execute(text(stmt))
                        conn.commit()
                    except Exception:
                        pass
        except Exception:
            pass


_migrate_sqlite_columns()

_settings_cache: dict = {"data": None, "ts": 0.0}
_cfg_cache_ttl = _cfg.SETTINGS_CACHE_TTL


def get_active_mode() -> str:
    if _settings_cache["data"] is not None:
        return _settings_cache["data"][0]
    db = ScapySessionLocal()
    try:
        s = db.query(SystemSetting).first()
        if s and (s.api_key or "").strip():
            return "api_agent"
        return "scapy"
    except Exception:
        return "scapy"
    finally:
        db.close()


def SessionLocal() -> Session:
    mode = get_active_mode()
    if mode == "api_agent":
        return ApiSessionLocal()
    return ScapySessionLocal()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_settings_db(db: Session = None) -> SystemSetting:
    should_close = False
    if db is None:
        db = SessionLocal()
        should_close = True
    try:
        settings = db.query(SystemSetting).first()
        if not settings:
            settings = SystemSetting(
                org_name="Sentinel IDS",
                admin_email="admin@network.local",
                timezone="UTC",
                push_notifications=True,
                email_alerts=True,
                auto_block=False,
                active_model="lstm",
                confidence_threshold=85,
                monitoring_mode="scapy",
                api_key="",
                report_interval_minutes=30,
            )
            db.add(settings)
            try:
                db.commit()
                db.refresh(settings)
            except Exception:
                db.rollback()
                raise
        else:
            if getattr(settings, "report_interval_minutes", None) is None:
                setattr(settings, "report_interval_minutes", 30)
        return settings
    finally:
        if should_close:
            db.close()


def get_cached_monitoring_config() -> tuple[str, str, int, bool, str]:
    """Returns (mode, model, confidence, auto_block, block_mode)"""
    now = time.monotonic()
    if _settings_cache["data"] is None or (now - _settings_cache["ts"]) > _cfg_cache_ttl:
        db = ScapySessionLocal()
        try:
            s = get_settings_db(db)
            has_token = bool((s.api_key or "").strip())
            mode = "api_agent" if has_token else "scapy"
            model = "rf" if s.active_model == "ml" else (s.active_model or "lstm")
            block_mode = getattr(s, "block_mode", "auto") or "auto"
            _settings_cache["data"] = (
                mode,
                model,
                int(s.confidence_threshold or 85),
                bool(s.auto_block),
                block_mode,
            )
            _settings_cache["ts"] = now
        finally:
            db.close()
    return _settings_cache["data"]


def sync_system_settings(settings_dict: dict):
    for sess_factory in (ScapySessionLocal, ApiSessionLocal):
        db = sess_factory()
        try:
            s = db.query(SystemSetting).first()
            if not s:
                s = SystemSetting()
                db.add(s)
            for k, v in settings_dict.items():
                if hasattr(s, k):
                    setattr(s, k, v)
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()


def invalidate_settings_cache():
    _settings_cache["data"] = None
    _settings_cache["ts"] = 0.0
    from backend.services.ip_service import invalidate_blocked_ip_cache
    invalidate_blocked_ip_cache()


def get_latest_network_stats(model_type: str = "lstm") -> dict:
    from backend.monitoring.stats import get_stats

    current_stats = get_stats()

    db = SessionLocal()
    try:
        total_blocked = db.query(BlockedIP).count()
        recent_blocks = db.query(BlockedIP).order_by(BlockedIP.blocked_at.desc()).limit(20).all()
        blocked_list = [
            {
                "time": b.blocked_at.strftime("%H:%M:%S") if b.blocked_at else "N/A",
                "src": b.ip_address,
                "port": b.port,
                "proto": b.protocol,
                "status": "anomaly",
            }
            for b in recent_blocks
        ]
    finally:
        db.close()

    flows = current_stats.get("recent_flows", [])
    anomaly_flows = [f for f in flows if f.get("status") == "anomaly"]

    inbound_bytes = current_stats.get("inbound_bytes", 0)
    outbound_bytes = current_stats.get("outbound_bytes", 0)

    return {
        "active_connections": current_stats["connections"],
        "packet_rate": current_stats["packet_rate"],
        "risk_score": current_stats["score"],
        "risk_message": current_stats["message"],
        "is_anomaly": current_stats["is_anomaly"],
        "network_flows": flows,
        "recent_flows": flows,
        "blocked_list": blocked_list,
        "total_blocked": total_blocked,
        "total_iocs": len(anomaly_flows) + total_blocked,
        "inbound_bytes": inbound_bytes,
        "outbound_bytes": outbound_bytes,
        "inbound_mb": round(inbound_bytes / (1024 * 1024), 2),
        "outbound_mb": round(outbound_bytes / (1024 * 1024), 2),
        "syn_packet_count": current_stats.get("syn_packet_count", 0),
        "ack_packet_count": current_stats.get("ack_packet_count", 0),
        "targeted_attacks": current_stats.get("targeted_attacks", 0),
        "malicious_blocked": current_stats.get("malicious_blocked", 0),
    }


# ─── Incident Timeline (real, DB-backed — replaces in-memory/mock event lists) ───

def log_incident_event(event_type: str, title: str, severity: str = "Info", details: str = "", source: str = "system") -> dict:
    """Persists a real forensic incident event. Called by SOAR playbooks, the AI
    red-team simulator, and auto-block logic. Never seeded with placeholder data."""
    db = SessionLocal()
    try:
        evt = IncidentEvent(event_type=event_type, title=title, severity=severity, details=details, source=source)
        db.add(evt)
        db.commit()
        db.refresh(evt)
        return {
            "id": evt.id,
            "timestamp": evt.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": evt.event_type,
            "title": evt.title,
            "severity": evt.severity,
            "details": evt.details,
        }
    except Exception:
        db.rollback()
        return {}
    finally:
        db.close()


def get_incident_timeline_db(limit: int = 50) -> list[dict]:
    db = SessionLocal()
    try:
        rows = db.query(IncidentEvent).order_by(IncidentEvent.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "timestamp": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "event_type": r.event_type,
                "title": r.title,
                "severity": r.severity,
                "details": r.details,
            }
            for r in reversed(rows)
        ]
    finally:
        db.close()


# ─── Honeypot Logs (real, DB-backed — replaces random-generated mock entries) ───

def log_honeypot_attempt(attacker_ip: str, decoy_service: str, port: int = 0, payload_attempted: str = "", action_taken: str = "Logged") -> dict:
    """Persists a real captured intrusion attempt against a decoy service. This should
    be called by the actual honeypot listener process, not seeded artificially."""
    db = SessionLocal()
    try:
        log = HoneypotLog(
            attacker_ip=attacker_ip,
            decoy_service=decoy_service,
            port=port,
            payload_attempted=payload_attempted or "",
            action_taken=action_taken or "Logged",
        )
        db.add(log)
        db.commit()
        db.refresh(log)
        return {
            "id": log.id,
            "timestamp": log.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "attacker_ip": log.attacker_ip,
            "decoy_service": log.decoy_service,
            "port": log.port,
            "payload_attempted": log.payload_attempted,
            "action_taken": log.action_taken,
        }
    except Exception:
        db.rollback()
        return {}
    finally:
        db.close()


def get_honeypot_logs_db(limit: int = 50) -> list[dict]:
    db = SessionLocal()
    try:
        rows = db.query(HoneypotLog).order_by(HoneypotLog.created_at.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "timestamp": r.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "attacker_ip": r.attacker_ip,
                "decoy_service": r.decoy_service,
                "port": r.port,
                "payload_attempted": r.payload_attempted,
                "action_taken": r.action_taken,
            }
            for r in rows
        ]
    finally:
        db.close()