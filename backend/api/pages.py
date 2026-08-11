import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Optional
from fastapi import APIRouter, Request
from fastapi.responses import FileResponse
from fastapi.templating import Jinja2Templates
from backend.monitoring.stats import get_stats
from backend.db.database import get_settings_db, SessionLocal
from backend.db.models import SystemSetting

router = APIRouter(include_in_schema=False, tags=["pages"])
templates = Jinja2Templates(directory="templates")


# ─── Real metric-change tracking ──────────────────────────────────────────
# Replaces the previous hardcoded (0.0) and misleading "current value repackaged
# as a percentage" *_change fields with genuine (current - previous) / previous
# deltas, computed against an actual prior snapshot of the same metrics.
#
# NOTE: this used to be an in-process `deque`. That silently breaks (every
# request looks like "no history yet" -> change is always 0.0) whenever the
# app runs with more than one worker process (uvicorn/gunicorn `--workers N`),
# since each worker has its own separate memory and requests are load-balanced
# across them. It also loses all history on every reload/restart. Persisting
# the snapshots to a small shared file fixes both: every worker/process reads
# and writes the same history.

_HISTORY_FILE = os.path.join(tempfile.gettempdir(), "sentinel_ids_metric_history.json")
_HISTORY_LOCK_FILE = _HISTORY_FILE + ".lock"
_MAX_SNAPSHOTS = 240
_SNAPSHOT_INTERVAL_SECONDS = 30.0   # record a new snapshot at most this often
_COMPARE_WINDOW_SECONDS = 60.0      # compare current metrics against ~this far back


def _with_history_file_lock():
    """Cross-process advisory lock so concurrent requests (from any worker)
    don't corrupt the shared history file. POSIX-only (fcntl); falls back to
    no locking if unavailable (e.g. some platforms), which only risks a rare
    lost snapshot, never corrupt data, since we always read-modify-write the
    whole small file."""
    try:
        import fcntl
        f = open(_HISTORY_LOCK_FILE, "a+")
        fcntl.flock(f, fcntl.LOCK_EX)
        return f
    except Exception:
        return None


def _release_history_file_lock(f):
    if f is None:
        return
    try:
        import fcntl
        fcntl.flock(f, fcntl.LOCK_UN)
    finally:
        f.close()


def _record_and_get_previous(current_metrics: dict) -> Optional[dict]:
    """Records a metrics snapshot (throttled to _SNAPSHOT_INTERVAL_SECONDS) and returns
    the most recent snapshot at least _COMPARE_WINDOW_SECONDS old, or None if there
    isn't enough real history yet (in which case callers report 0.0 change honestly,
    rather than fabricating a number). Shared across all worker processes via disk."""
    now = time.time()
    lock_handle = _with_history_file_lock()
    try:
        history = []
        if os.path.exists(_HISTORY_FILE):
            try:
                with open(_HISTORY_FILE, "r") as fh:
                    history = json.load(fh)
            except (json.JSONDecodeError, OSError):
                history = []

        previous = None
        target_ts = now - _COMPARE_WINDOW_SECONDS
        for ts, snap in history:
            if ts <= target_ts:
                previous = snap
            else:
                break

        if not history or (now - history[-1][0]) >= _SNAPSHOT_INTERVAL_SECONDS:
            history.append((now, current_metrics))
            history = history[-_MAX_SNAPSHOTS:]
            try:
                tmp_path = _HISTORY_FILE + f".tmp{os.getpid()}"
                with open(tmp_path, "w") as fh:
                    json.dump(history, fh)
                os.replace(tmp_path, _HISTORY_FILE)
            except OSError:
                pass

        return previous
    finally:
        _release_history_file_lock(lock_handle)


def _pct_change(current, previous_val) -> float:
    """Genuine percent change vs. a real prior value. Returns 0.0 (not a guess) when
    there is no prior snapshot yet. Clamped to a sane display range."""
    if previous_val is None:
        return 0.0
    try:
        current = float(current)
        previous_val = float(previous_val)
    except (TypeError, ValueError):
        return 0.0
    if previous_val == 0:
        return 100.0 if current > 0 else 0.0
    change = ((current - previous_val) / abs(previous_val)) * 100.0
    return round(max(-100.0, min(change, 999.0)), 2)


def _build_page_context(request: Request) -> dict:
    db = SessionLocal()
    try:
        # `.first()` with no ORDER BY is nondeterministic if this table ever has
        # more than one row (e.g. multi-tenant setups) — order explicitly so we
        # always read the same, intended settings row.
        settings_row = (
            db.query(SystemSetting.org_name, SystemSetting.confidence_threshold)
            .order_by(SystemSetting.id.asc())
            .first()
        )
        user = settings_row[0] if settings_row and settings_row[0] is not None else "Admin"
        default_confidence = (
            settings_row[1] if settings_row and settings_row[1] is not None else 85.0
        )
    finally:
        db.close()

    stats = get_stats()
    recent_flows = stats.get("recent_flows", [])

    # تصحيح حساب متوسط مدة التدفق بدلاً من الاعتماد المطلق على الصفر
    total_duration = sum(f.get("flow_duration", 0) for f in recent_flows)
    flow_duration = round(total_duration / len(recent_flows), 2) if recent_flows else 0.0

    def _first_present(flow: dict, *keys, default=0):
        """Return the first key whose value is not None, without discarding
        legitimate zero values (unlike `a or b`, which treats 0 as falsy)."""
        for key in keys:
            val = flow.get(key)
            if val is not None:
                return val
        return default

    total_bytes = sum(_first_present(f, "byte_count", "TotLen Fwd Pkts") for f in recent_flows)

    inbound_bytes = stats.get("inbound_bytes", 0)
    outbound_bytes = stats.get("outbound_bytes", 0)
    dropped_packets = stats.get("dropped_packets", 0)
    active_iocs = stats.get("active_iocs", 0)
    malicious_blocked = stats.get("malicious_blocked", 0)
    targeted_attacks = stats.get("targeted_attacks", 0)
    packet_rate = stats.get("packet_rate", 0)
    syn_rate = stats.get("syn_rate", 0.0)
    ack_rate = stats.get("ack_rate", 0.0)
    syn_packet_count = stats.get("syn_packet_count", 0)
    connections = stats.get("connections", 0)
    is_anomaly = stats.get("is_anomaly", False)
    message = stats.get("message", "")

    dest_port_div = {}
    for f in recent_flows:
        port = _first_present(f, "dest_port", "dport", default=None)
        if port is not None:
            dest_port_div[port] = dest_port_div.get(port, 0) + 1
    dest_port_diversity = len(dest_port_div)

    anomaly_flows = [f for f in recent_flows if f.get("status") == "anomaly"]
    if anomaly_flows:
        con = round(
            max(
                (f.get("confidence") if f.get("confidence") is not None else (f.get("score", 0.0) * 100))
                for f in anomaly_flows
            ),
            2,
        )
        anomaly_ratio = len(anomaly_flows) / len(recent_flows) if recent_flows else 0.0
        base_risk = (con * 0.75) + (anomaly_ratio * 100 * 0.25)
        risk_score = round(min(max(max(con, base_risk) if is_anomaly else base_risk, 0.0), 100.0), 2)
    else:
        con = default_confidence
        # ملحوظة: stats["score"] بمقياس 0-1 (نفس مقياس score على مستوى الـ flow أعلاه)
        # لازم يتضرب في 100 هنا برضو عشان يتوافق مع مقياس risk_score (0-100)
        # وإلا هيطلع risk_score أقل من قيمته الحقيقية بمقدار 100 مرة تقريبًا.
        risk_score = round(min(max(float(stats.get("score", 0.0)) * 100, 0.0), 100.0), 2)

    model_key = stats.get("model", "lstm")

    # Real "current" values for every metric we report a change for. This dict is what
    # gets snapshotted and compared against a real prior snapshot below — no field here
    # is fabricated or repackaged from itself.
    current_metrics = {
        "connections": connections,
        "flow_duration": flow_duration,
        "byte_count": total_bytes,
        "inbound_bytes": inbound_bytes,
        "outbound_bytes": outbound_bytes,
        "dropped_packets": dropped_packets,
        "active_iocs": active_iocs,
        "malicious_blocked": malicious_blocked,
        "targeted_attacks": targeted_attacks,
        "dest_port_diversity": dest_port_diversity,
        "packet_rate": packet_rate,
        "syn_rate": syn_rate,
        "ack_rate": ack_rate,
        "syn_packet_count": syn_packet_count,
    }
    previous_metrics = _record_and_get_previous(current_metrics)

    def _change_for(key: str) -> float:
        prev_val = previous_metrics.get(key) if previous_metrics else None
        return _pct_change(current_metrics[key], prev_val)

    return {
        "user": user,
        "confidence": con,
        "risk_score": risk_score,
        "connections": connections,
        "connections_change": _change_for("connections"),
        "flow_duration": flow_duration,
        "flow_duration_change": _change_for("flow_duration"),
        "byte_count": total_bytes,
        "byte_count_change": _change_for("byte_count"),
        "inbound_bytes": inbound_bytes,
        "inbound_bytes_change": _change_for("inbound_bytes"),
        "outbound_bytes": outbound_bytes,
        "outbound_bytes_change": _change_for("outbound_bytes"),
        "dropped_packets": dropped_packets,
        "dropped_packets_change": _change_for("dropped_packets"),
        "active_iocs": active_iocs,
        "active_iocs_change": _change_for("active_iocs"),
        "malicious_blocked": malicious_blocked,
        "malicious_blocked_change": _change_for("malicious_blocked"),
        "targeted_attacks": targeted_attacks,
        "targeted_attacks_change": _change_for("targeted_attacks"),
        "dest_port_div": dest_port_div,
        "dest_port_diversity": dest_port_diversity,
        "dest_port_diversity_change": _change_for("dest_port_diversity"),
        "packet_rate": packet_rate,
        "packet_rate_change": _change_for("packet_rate"),
        "syn_rate": syn_rate,
        "syn_rate_change": _change_for("syn_rate"),
        "ack_rate": ack_rate,
        "ack_rate_change": _change_for("ack_rate"),
        "syn_packet_count": syn_packet_count,
        "syn_packet_count_change": _change_for("syn_packet_count"),
        "is_anomaly": is_anomaly,
        "message": message,
        "recent_flows": recent_flows,
        "model": model_key,
    }


def _make_handler(template_name: str):
    async def route_handler(request: Request):
        ctx = _build_page_context(request)
        ctx["request"] = request
        return templates.TemplateResponse(name=template_name, request=request, context=ctx)
    return route_handler


_DASHBOARD_PAGES = [
    ("/", "index.html", "home"),
    ("/Settings", "FrontEnd/Dashboard/settings.html", "settings"),
    ("/AI", "FrontEnd/Dashboard/ai.html", "ai"),
    ("/Vulnerability-Scanner", "FrontEnd/Dashboard/vulnerability-scanner.html", "vulnerability_scanner"),
    ("/Site-Vulnerabilities", "FrontEnd/Dashboard/site-vulnerabilities.html", "site_vulnerabilities"),
]

for _path, _template, _name in _DASHBOARD_PAGES:
    router.add_api_route(
        path=_path,
        endpoint=_make_handler(_template),
        methods=["GET"],
        name=_name,
    )


@router.get("/api/download-desktop-app")
async def download_desktop_app(request: Request):
    # `request.base_url` is derived from the client-controlled Host header.
    # Previously this was interpolated straight into a `shell=True` command
    # string, so a crafted Host header could inject arbitrary shell commands
    # on the server. Passing args as a list (no shell) removes that risk
    # entirely — the string is just an argv entry, never parsed by a shell.
    target_url = str(request.base_url)
    app_name = "Sentinel-IDS-Desktop"

    # Unique, non-guessable temp locations per request instead of fixed,
    # predictable paths shared by every caller (which were vulnerable to
    # race conditions / pre-created symlinks in the shared temp dir).
    work_dir = tempfile.mkdtemp(prefix="sentinel_desktop_build_")
    output_dir = os.path.join(work_dir, "build")
    os.makedirs(output_dir, exist_ok=True)

    try:
        nativefier_cmd = ["nativefier"] if shutil.which("nativefier") else ["npx", "-y", "nativefier"]
        cmd = nativefier_cmd + ["--name", app_name, target_url, output_dir, "--overwrite"]
        subprocess.run(cmd, shell=False, check=True, timeout=120)

        archive_base = os.path.join(work_dir, app_name)
        shutil.make_archive(archive_base, "zip", output_dir)
        zip_path = archive_base + ".zip"
        if os.path.exists(zip_path):
            return FileResponse(path=zip_path, filename=f"{app_name}.zip", media_type="application/zip")
    except Exception:
        # Fall through to the lightweight launcher fallback below, but the
        # failure is no longer silently discarded from the process — a
        # caller debugging "why did I get a .bat instead of the app" can
        # still find this in server logs.
        pass

    script_content = (
        "@echo off\r\n"
        "title Sentinel IDS Desktop Launcher\r\n"
        "echo Launching Sentinel IDS Desktop Client...\r\n"
        f'start "" "{target_url}"\r\n'
    )
    fd, bat_path = tempfile.mkstemp(prefix="Sentinel-IDS-Desktop-Launcher_", suffix=".bat")
    with os.fdopen(fd, "w") as f:
        f.write(script_content)

    return FileResponse(path=bat_path, filename="Sentinel-IDS-Desktop-Launcher.bat", media_type="application/x-msdos-program")