import threading
from collections import deque
from backend.core.config import get_settings

_cfg = get_settings()

_stats = {
    "connections": 0,
    "packet_rate": 0,
    "total_packets": 0,
    "score": 5.0,
    "message": "System behavior is normal.",
    "is_anomaly": False,
    "recent_flows": deque(maxlen=_cfg.MAX_RECENT_FLOWS),
    "model": "lstm",
    "inbound_bytes": 0,
    "outbound_bytes": 0,
    "dropped_packets": 0,
    "active_iocs": 0,
    "malicious_blocked": 0,
    "targeted_attacks": 0,
    "syn_rate": 0.0,
    "ack_rate": 0.0,
    "syn_packet_count": 0,
    "ack_packet_count": 0,
}

_stats_lock = threading.Lock()


def get_stats() -> dict:
    with _stats_lock:
        recent_flows_list = list(_stats["recent_flows"])

        inb_bytes = _stats.get("inbound_bytes", 0)
        out_bytes = _stats.get("outbound_bytes", 0)
        drop_pkts = _stats.get("dropped_packets", 0)
        iocs = _stats.get("active_iocs", 0)
        blocked = _stats.get("malicious_blocked", 0)
        targeted = _stats.get("targeted_attacks", 0)

        return {
            "connections": _stats["connections"],
            "packet_rate": _stats["packet_rate"],
            "total_packets": _stats.get("total_packets", 0),
            "score": _stats["score"],
            "model": _stats["model"],
            "message": _stats["message"],
            "is_anomaly": _stats["is_anomaly"],
            "recent_flows": recent_flows_list,
            "flows": recent_flows_list,
            "inbound_bytes": inb_bytes,
            "outbound_bytes": out_bytes,
            "dropped_packets": drop_pkts,
            "active_iocs": iocs,
            "malicious_blocked": blocked,
            "targeted_attacks": targeted,
            "syn_rate": _stats.get("syn_rate", 0.0),
            "ack_rate": _stats.get("ack_rate", 0.0),
            "syn_packet_count": _stats.get("syn_packet_count", 0),
            "ack_packet_count": _stats.get("ack_packet_count", 0),
        }


def update_stats(new_data: dict):
    with _stats_lock:
        for key, value in new_data.items():
            if key in _stats:
                _stats[key] = value


def refresh_model_from_db():
    try:
        from backend.db.database import SessionLocal
        from backend.db.models import SystemSetting
        db = SessionLocal()
        try:
            row = db.query(SystemSetting.active_model).first()
            model = row[0] if row and row[0] else "lstm"
            with _stats_lock:
                _stats["model"] = model
        finally:
            db.close()
    except Exception:
        pass
