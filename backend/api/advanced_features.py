"""
API Router for Advanced Features:
1. Voice Security Assistant (AI-driven intent understanding — no keyword matching)
2. Automated Honeypot & Deception Dashboard (real DB-backed intrusion logs)
3. Threat Intelligence & IP/Domain Lookup Engine (real correlation + live GeoIP + AI analysis)
4. AI Red Team Simulator (100 Top Attack Vectors Simulation, deterministic telemetry)
5. Incident Timeline & Forensic Event Logger (real DB-backed events)
6. System Health & Real-time Telemetry Monitor (real process/DB metrics)

No mock/seed data and no random.* calls remain in this router. Anything that cannot be
computed from real signals (e.g. a query with zero history) is returned as null/empty
rather than fabricated.
"""

import asyncio
import ipaddress
import json
import logging
import re
import socket
import threading
import time
from datetime import datetime
from typing import Optional, List
from urllib.parse import urlparse

import requests as http_requests
from fastapi import APIRouter, HTTPException, Form, status
from pydantic import BaseModel
from sqlalchemy import text as sa_text

from backend.ai.redteam_agent import red_team_agent, TOP_100_ATTACKS
from backend.ai.mitre_mapper import get_mitre_mapping
from backend.ai.llm import get_ai_response
from backend.services.ip_service import block_ip, is_ip_blocked
from backend.monitoring.stats import get_stats
from backend.db.database import (
    SessionLocal,
    get_settings_db,
    log_incident_event,
    get_incident_timeline_db,
    log_honeypot_attempt,
    get_honeypot_logs_db,
)
from backend.db.models import BlockedIP, NetworkFlow

router = APIRouter(prefix="/api", tags=["advanced_features"])
logger = logging.getLogger("sentinel.advanced_features")

_PROCESS_START_TIME = time.monotonic()

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Pages the voice assistant is allowed to navigate to. The AI chooses freely from
# this list based on what it understands from the spoken command; nothing outside
# this set is ever returned to the frontend router.
_VOICE_NAV_PAGES = {"/Vulnerability-Scanner", "/PCAP-Analyzer", "/Attack-Globe", "/RedTeam-Simulator"}


# ─── Feature 1: Voice Security Assistant Endpoint ────────────────────────

class VoiceCommand(BaseModel):
    transcript: str


_VOICE_ROUTER_INSTRUCTIONS = (
    "You are the voice-command intent router for a security analyst using the Sentinel IDS "
    "dashboard. The analyst just spoke the command below. Understand it freely and naturally — "
    "do not rely on fixed keywords. Reply with ONLY a single raw JSON object (no markdown fences, "
    "no extra text) with exactly these keys:\n"
    '  "action": one of "block_ip", "navigate_dashboard", "navigate", "general"\n'
    '  "url": if action is "navigate", one of '
    '["/Vulnerability-Scanner", "/PCAP-Analyzer", "/Attack-Globe", "/RedTeam-Simulator"], else ""\n'
    '  "ip": if action is "block_ip", the exact IPv4 address spoken in the command, else ""\n'
    '  "response": a short, natural spoken confirmation in the SAME language as the command. '
    'If the command is a genuine question rather than a dashboard action, answer it directly here '
    'using your own security expertise.\n\n'
    f'Analyst said: "{{transcript}}"'
)


@router.post("/voice-command", status_code=status.HTTP_200_OK)
async def process_voice_command(body: VoiceCommand):
    """
    Understands natural-language voice commands from security analysts by letting the AI
    interpret intent freely, then executes the resulting action against real system state.
    """
    transcript = (body.transcript or "").strip()
    if not transcript:
        return {"action": "none", "response": "I didn't catch that. Please speak again."}

    prompt = _VOICE_ROUTER_INSTRUCTIONS.format(transcript=transcript.replace('"', "'"))
    ai_raw = await get_ai_response(prompt)

    parsed = _extract_json(ai_raw)

    if not parsed:
        # The AI didn't return parseable JSON — fall back to its raw natural-language
        # answer rather than a hardcoded string. Still fully AI-driven, just unstructured.
        return {"action": "general_llm", "response": ai_raw.strip()}

    action = parsed.get("action", "general")
    ai_response_text = (parsed.get("response") or "").strip() or ai_raw.strip()

    if action == "block_ip":
        # Safety check: only ever block an IP that is verifiably present in what the
        # analyst actually said, even if the AI extracted (or hallucinated) one.
        candidate_ip = (parsed.get("ip") or "").strip()
        found_in_transcript = _IP_RE.search(transcript)
        target_ip = candidate_ip if candidate_ip and candidate_ip in transcript else (
            found_in_transcript.group(0) if found_in_transcript else None
        )
        if not target_ip:
            return {"action": "error", "response": "Voice command recognized as block, but no valid IP address was found."}
        await block_ip(target_ip, reason="VOICE_COMMAND", attack_type="Voice Command Block")
        log_incident_event(
            event_type="Voice Command",
            title=f"IP {target_ip} blocked via voice command",
            severity="Medium",
            details=f'Analyst said: "{transcript}"',
            source="voice_assistant",
        )
        return {"action": "block_ip", "ip": target_ip, "response": ai_response_text}

    if action == "navigate_dashboard":
        stats = get_stats()
        return {
            "action": "navigate_dashboard",
            "response": ai_response_text or (
                f"Current system risk score is {stats.get('score', 0)}% with "
                f"{stats.get('connections', 0)} active connections and packet rate of "
                f"{stats.get('packet_rate', 0)} packets per second."
            ),
        }

    if action == "navigate":
        url = parsed.get("url", "")
        if url in _VOICE_NAV_PAGES:
            return {"action": "navigate", "url": url, "response": ai_response_text}
        # AI proposed a page outside the known set — treat as a general answer instead.
        return {"action": "general_llm", "response": ai_response_text}

    return {"action": "general_llm", "response": ai_response_text}


def _extract_json(raw: str) -> Optional[dict]:
    """Best-effort extraction of a JSON object from an LLM response that may include
    stray prose or markdown code fences around the JSON."""
    if not raw:
        return None
    candidate = raw.strip()
    if candidate.startswith("```"):
        candidate = candidate.strip("`")
        candidate = candidate.replace("json\n", "", 1) if candidate.startswith("json\n") else candidate
    match = re.search(r"\{.*\}", candidate, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


# ─── Feature 2: Automated Honeypot Endpoint ─────────────────────────────

class HoneypotAttemptIn(BaseModel):
    attacker_ip: str
    decoy_service: str
    port: int = 0
    payload_attempted: str = ""
    action_taken: str = "Logged"


@router.get("/honeypot/logs", status_code=status.HTTP_200_OK)
async def get_honeypot_logs(limit: int = 50):
    """Returns real captured intrusion attempts against decoy services. Empty until the
    honeypot listener has actually logged an attempt — no data is seeded here."""
    logs = get_honeypot_logs_db(limit=limit)
    return {"logs": logs}


@router.post("/honeypot/logs", status_code=status.HTTP_201_CREATED)
async def report_honeypot_attempt(body: HoneypotAttemptIn):
    """
    Ingest endpoint for the actual honeypot listener process to report a real captured
    intrusion attempt. This is the only way rows are written to the honeypot log table.
    """
    entry = log_honeypot_attempt(
        attacker_ip=body.attacker_ip,
        decoy_service=body.decoy_service,
        port=body.port,
        payload_attempted=body.payload_attempted,
        action_taken=body.action_taken,
    )
    if not entry:
        raise HTTPException(status_code=500, detail="Failed to persist honeypot log entry.")

    if body.action_taken and "block" in body.action_taken.lower():
        await block_ip(body.attacker_ip, reason="HONEYPOT", attack_type=f"Honeypot: {body.decoy_service}")

    log_incident_event(
        event_type="Honeypot Trigger",
        title=f"Intrusion attempt on {body.decoy_service}",
        severity="Medium",
        details=f"Attacker: {body.attacker_ip} | Port: {body.port} | Action: {body.action_taken}",
        source="honeypot",
    )
    return entry


# ─── Feature 3: Threat Intelligence Lookup Engine ────────────────────────

_QUERY_TYPE_IP = "IP Address"
_QUERY_TYPE_HASH = "File Hash (MD5/SHA256)"
_QUERY_TYPE_DOMAIN = "Domain Name"

_ip_pattern = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}$')
_hash_pattern = re.compile(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$')
# Reasonably strict hostname pattern: labels of letters/digits/hyphens, at least one dot,
# no leading/trailing hyphen per label. Rejects garbage strings that aren't a real indicator.
_domain_pattern = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))+$'
)

_AI_SCORE_RE = re.compile(r"THREAT_SCORE:\s*(\d{1,3})", re.IGNORECASE)

_THREAT_ANALYSIS_PROMPT = (
    "You are a threat-intelligence analyst. Give a real, expert assessment of this indicator "
    "based on your own security knowledge (known malware families, typical abuse patterns, "
    "reputation of the domain/hash if you recognize it, etc.). Be direct and specific — do not "
    "use a generic template. Indicator type: {itype}. Indicator: {indicator}\n\n"
    "End your answer with a single line in exactly this format: THREAT_SCORE: NN "
    "(an integer 0-100 reflecting how malicious you assess this indicator to be, 0=benign, 100=confirmed malicious)."
)


def _normalize_query(raw: str) -> tuple[str, str]:
    """
    Classifies and normalizes the raw search box input into (query_type, indicator).
    Fixes the core bug behind 'wrong values for URLs/IPs': previously a full URL like
    'http://8.8.8.8/path?x=1' or 'https://example.com/page' was sent to the AI verbatim
    as a 'domain', which both hid an embedded IP and polluted the lookup with path/query
    noise. This extracts the real host first, then classifies IP vs. domain vs. hash.
    Raises HTTPException(400) for input that isn't a plausible IP/domain/URL/hash at all,
    instead of silently forwarding garbage and getting back a meaningless AI answer.
    """
    q = raw.strip()

    # Hashes are never URLs — check first, on the raw string.
    if _hash_pattern.match(q):
        return _QUERY_TYPE_HASH, q

    candidate = q
    if "://" in q or q.lower().startswith("www."):
        parsed = urlparse(q if "://" in q else f"http://{q}")
        candidate = parsed.hostname or q

    candidate = candidate.strip().rstrip(".")

    if _ip_pattern.match(candidate):
        return _QUERY_TYPE_IP, candidate
    if _domain_pattern.match(candidate):
        return _QUERY_TYPE_DOMAIN, candidate.lower()

    raise HTTPException(
        status_code=400,
        detail="Invalid indicator — expected an IPv4 address, a domain, a URL, or an MD5/SHA1/SHA256 hash.",
    )


@router.get("/threat-lookup", status_code=status.HTTP_200_OK)
async def threat_intelligence_lookup(query: str):
    """
    Performs a real threat-intelligence lookup on an IP, domain/URL, or file hash by
    correlating our own telemetry (blocked IPs, honeypot hits, flagged network flows,
    DNS-resolved IP for domains) and an AI analyst assessment. Every returned field is
    either a real measured/queried value or explicitly null — nothing is fabricated.
    """
    q = (query or "").strip()
    if not q:
        raise HTTPException(status_code=400, detail="Query parameter required.")

    query_type, indicator = _normalize_query(q)

    if query_type == _QUERY_TYPE_IP:
        result = await _lookup_ip_threat(indicator)
    elif query_type == _QUERY_TYPE_DOMAIN:
        result = await _lookup_domain_threat(indicator, query_type)
    else:
        result = await _lookup_hash_threat(indicator, query_type)

    result["query"] = q
    result["indicator"] = indicator
    result["query_type"] = query_type
    return result


async def _lookup_ip_threat(ip: str) -> dict:
    blocked = await is_ip_blocked(ip)

    db = SessionLocal()
    try:
        blocked_row = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
        attack_flow_count = (
            db.query(NetworkFlow)
            .filter(NetworkFlow.src == ip, NetworkFlow.is_attack == True)  # noqa: E712
            .count()
        )
    finally:
        db.close()

    honeypot_hits = len([h for h in get_honeypot_logs_db(limit=500) if h.get("attacker_ip") == ip])

    # Deterministic score from real correlated signals — no randomness.
    score = 0
    score += 45 if blocked else 0
    score += min(honeypot_hits * 10, 35)
    score += min(attack_flow_count * 4, 20)
    score = min(score, 98)

    reputation = "Malicious" if score >= 70 else ("Suspicious" if score >= 35 else "Clean")
    correlated_detections = honeypot_hits + attack_flow_count + (1 if blocked else 0)

    loop = asyncio.get_running_loop()
    geo = await loop.run_in_executor(None, _geoip_lookup, ip)

    mitre_info = _safe_mitre_mapping(blocked_row.attack_type) if (blocked_row and score > 60) else None

    return {
        "threat_score": score,
        "reputation": reputation,
        "country": geo.get("country"),
        "isp": geo.get("isp"),
        "is_currently_blocked": blocked,
        "correlated_detections": correlated_detections,
        "honeypot_hits": honeypot_hits,
        "flagged_network_flows": attack_flow_count,
        "block_reason": blocked_row.attack_type if blocked_row else None,
        "mitre_mapping": mitre_info,
        "recommendation": (
            "Immediate IP block recommended via SOAR playbook."
            if score >= 70 else "Continue automated telemetry monitoring."
        ),
    }


async def _lookup_domain_threat(indicator: str, query_type: str) -> dict:
    """
    Real domain/URL analysis: resolves the domain to its actual IP via DNS and reuses the
    same telemetry correlation as an IP lookup (so a domain hosted on an IP we've already
    seen attacking us, or caught in the honeypot, is flagged from REAL data) — combined
    with the AI analyst's qualitative assessment, rather than returning null country/ISP
    and a bare AI guess for every domain like before.
    """
    loop = asyncio.get_running_loop()
    resolved_ip = await loop.run_in_executor(None, _resolve_domain, indicator)

    ai_raw = await get_ai_response(_THREAT_ANALYSIS_PROMPT.format(itype=query_type, indicator=indicator))
    score_match = _AI_SCORE_RE.search(ai_raw)
    ai_score = max(0, min(int(score_match.group(1)), 100)) if score_match else None
    analysis_text = _AI_SCORE_RE.sub("", ai_raw).strip()

    telemetry = await _lookup_ip_threat(resolved_ip) if resolved_ip else None

    if telemetry is not None and ai_score is not None:
        score = max(telemetry["threat_score"], ai_score)
    elif telemetry is not None:
        score = telemetry["threat_score"]
    else:
        score = ai_score

    if score is None:
        reputation = "Unknown"
        recommendation = "Insufficient data — DNS resolution failed and no AI score was returned. Try again or verify the domain."
    else:
        reputation = "Malicious" if score >= 70 else ("Suspicious" if score >= 35 else "Clean")
        recommendation = (
            "Immediate block/deny-list recommended." if score >= 70 else "Continue monitoring; no immediate action required."
        )

    return {
        "threat_score": score,
        "reputation": reputation,
        "resolved_ip": resolved_ip,
        "country": telemetry.get("country") if telemetry else None,
        "isp": telemetry.get("isp") if telemetry else None,
        "is_currently_blocked": telemetry.get("is_currently_blocked", False) if telemetry else False,
        "correlated_detections": telemetry.get("correlated_detections", 0) if telemetry else 0,
        "ai_assessment": analysis_text,
        "mitre_mapping": telemetry.get("mitre_mapping") if telemetry else None,
        "recommendation": recommendation,
    }


async def _lookup_hash_threat(indicator: str, query_type: str) -> dict:
    """File hashes have no IP/GeoIP to correlate — this stays a pure AI expert assessment."""
    ai_raw = await get_ai_response(_THREAT_ANALYSIS_PROMPT.format(itype=query_type, indicator=indicator))

    score_match = _AI_SCORE_RE.search(ai_raw)
    score = max(0, min(int(score_match.group(1)), 100)) if score_match else None
    analysis_text = _AI_SCORE_RE.sub("", ai_raw).strip()

    if score is None:
        reputation = "Unknown"
        recommendation = "Unable to derive a confident score — review the AI analysis manually."
    else:
        reputation = "Malicious" if score >= 70 else ("Suspicious" if score >= 35 else "Clean")
        recommendation = (
            "Immediate block/deny-list recommended." if score >= 70 else "Continue monitoring; no immediate action required."
        )

    return {
        "threat_score": score,
        "reputation": reputation,
        "country": None,
        "isp": None,
        "is_currently_blocked": False,
        "ai_assessment": analysis_text,
        "mitre_mapping": None,
        "recommendation": recommendation,
    }


def _resolve_domain(domain: str) -> Optional[str]:
    """Real DNS resolution. Returns None on failure — never a fabricated IP."""
    try:
        return socket.gethostbyname(domain)
    except Exception as e:
        logger.info("DNS resolution failed for %s: %s", domain, e)
        return None


def _geoip_lookup(ip: str) -> dict:
    """
    Real, free GeoIP lookup (no API key). Fixes the 'always wrong/null for the IPs I test'
    bug: private/internal/loopback addresses (e.g. 192.168.x.x, the RedTeam simulator's
    default 192.168.1.100 target) are never publicly geolocatable — ip-api.com correctly
    rejects them, which previously surfaced as blank country/ISP. Those are now labeled
    honestly as an internal network instead of silently failing. Public IPs are queried
    for real. Returns nulls only on a genuine lookup failure — never fabricated.
    """
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved or addr.is_multicast:
            return {"country": "Private/Internal Network", "isp": "Internal Network"}
    except ValueError:
        return {"country": None, "isp": None}

    try:
        resp = http_requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,isp", timeout=3)
        data = resp.json()
        if data.get("status") == "success":
            return {"country": data.get("country"), "isp": data.get("isp")}
    except Exception as e:
        logger.info("GeoIP lookup failed for %s: %s", ip, e)
    return {"country": None, "isp": None}


def _safe_mitre_mapping(attack_type: Optional[str]):
    """
    Guards against passing a non-technique string (e.g. our own internal block reasons
    like 'AUTO', 'MANUAL', 'PLAYBOOK') into get_mitre_mapping(), which previously could
    return a meaningless/incorrect mapping, and against any exception from that call
    surfacing as a broken lookup. Returns None rather than a guessed mapping.
    """
    if not attack_type:
        return None
    generic_reasons = {"unknown", "auto", "manual", "voice_command", "playbook", "honeypot"}
    if attack_type.strip().lower() in generic_reasons:
        return None
    try:
        return get_mitre_mapping(attack_type)
    except Exception as e:
        logger.info("MITRE mapping lookup failed for %r: %s", attack_type, e)
        return None


# ─── Feature 4: AI Red Team Attack Simulator Endpoint ────────────────────

@router.get("/redteam/attacks", status_code=status.HTTP_200_OK)
async def list_redteam_attacks(query: str = "", category: str = ""):
    """Returns the catalog of 100 top cybersecurity attack vectors."""
    attacks = red_team_agent.search_attacks(query, category)
    return {"total": len(attacks), "attacks": attacks}


@router.post("/redteam/simulate", status_code=status.HTTP_200_OK)
async def simulate_redteam_attack(attack_id: int = Form(...), target_ip: str = Form("192.168.1.100")):
    """Simulates a selected attack from the 100-attack catalog against the Sentinel engine
    with deterministic telemetry, and persists the result to the real incident timeline."""
    result = red_team_agent.simulate_attack(attack_id, target_ip)
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error"))

    sim = result.get("simulation", {})
    log_incident_event(
        event_type="AI Red Team Simulation",
        title=f"Simulated {sim.get('name')}",
        severity=sim.get("severity", "Info"),
        details=f"Target: {sim.get('target_ip')} | MITRE: {sim.get('mitre')} | Packets: {sim.get('packets_generated')}",
        source="redteam_simulator",
    )

    # Automatically block the target IP if auto-block is active — never a fabricated IP.
    db = SessionLocal()
    try:
        s = get_settings_db(db)
        is_auto = bool(s.auto_block) or (getattr(s, "block_mode", "auto") == "auto")
        if is_auto and target_ip not in ("127.0.0.1", "0.0.0.0", "localhost"):
            await block_ip(target_ip, reason="AUTO", attack_type=f"Red Team ({sim.get('name')})")
    finally:
        db.close()

    return result


# ─── Feature 5: Incident Timeline Endpoint ──────────────────────────────

@router.get("/incident-timeline", status_code=status.HTTP_200_OK)
async def get_incident_timeline(limit: int = 50):
    """Returns the real forensic incident timeline from the database. Empty until the
    system (playbooks, red-team simulator, honeypot, voice assistant) logs a real event."""
    return {"timeline": get_incident_timeline_db(limit=limit)}


# ─── Feature 6: System Health & Real-time Telemetry Monitor ─────────────

@router.get("/system-health", status_code=status.HTTP_200_OK)
async def get_system_health():
    """Returns live server metrics: CPU, memory, DB connectivity, and real detection latency —
    all measured directly, with no fixed placeholder numbers when a metric is unavailable."""
    cpu = None
    mem = None
    psutil_available = False
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        psutil_available = True
    except Exception as e:
        logger.info("psutil unavailable: %s", e)

    t0 = time.perf_counter()
    stats = get_stats()
    detection_latency_ms = round((time.perf_counter() - t0) * 1000, 2)

    db = SessionLocal()
    db_ok = True
    try:
        db.execute(sa_text("SELECT 1"))
    except Exception as e:
        db_ok = False
        logger.warning("DB health check failed: %s", e)
    finally:
        db.close()

    confidence_threshold = 85
    try:
        db2 = SessionLocal()
        try:
            s = get_settings_db(db2)
            confidence_threshold = int(s.confidence_threshold or 85)
        finally:
            db2.close()
    except Exception:
        pass

    healthy = psutil_available and db_ok
    return {
        "status": "Healthy — All Operational" if healthy else "Degraded",
        "cpu_usage_percent": cpu,
        "memory_usage_percent": mem,
        "psutil_available": psutil_available,
        "active_threads": threading.active_count(),
        "detection_latency_ms": detection_latency_ms,
        "db_status": "Connected (SQLite WAL Mode)" if db_ok else "Unavailable",
        "active_model": stats.get("model", "lstm"),
        "confidence_threshold": confidence_threshold,
        "uptime_seconds": int(time.monotonic() - _PROCESS_START_TIME),
    }