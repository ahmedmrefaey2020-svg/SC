import asyncio
import time
from backend.db.database import SessionLocal
from backend.db.models import BlockedIP
from backend.core.config import get_settings

_cfg = get_settings()

_blocked_ips_cache: set[str] = set()
_cache_ts: float = 0.0
_cache_lock = asyncio.Lock()
CACHE_TTL = float(_cfg.BLOCKED_IP_CACHE_TTL)


def invalidate_blocked_ip_cache():
    global _cache_ts
    _blocked_ips_cache.clear()
    _cache_ts = 0.0


async def _refresh_cache_if_stale():
    global _cache_ts
    now = time.monotonic()
    if (now - _cache_ts) < CACHE_TTL:
        return
    loop = asyncio.get_running_loop()
    ips = await loop.run_in_executor(None, _load_blocked_ips_from_db)
    async with _cache_lock:
        _blocked_ips_cache.clear()
        _blocked_ips_cache.update(ips)
        _cache_ts = now


def _load_blocked_ips_from_db() -> set[str]:
    db = SessionLocal()
    try:
        rows = db.query(BlockedIP.ip_address).all()
        return {r[0] for r in rows}
    finally:
        db.close()


_PROTECTED_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


def _sync_add_to_db(
    ip: str,
    protocol: str = "TCP",
    port: int = 0,
    src_bytes: float = 0.0,
    reason: str = "AUTO",
    attack_type: str = "Suspicious Traffic",
) -> bool:
    if not ip or ip in _PROTECTED_IPS:
        return False
    db = SessionLocal()
    try:
        existing = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
        if existing:
            return False
        db.add(BlockedIP(
            ip_address=ip,
            protocol=protocol or "TCP",
            port=port or 0,
            src_bytes=src_bytes or 0.0,
            reason=reason or "AUTO",
            attack_type=attack_type or "Suspicious Traffic",
        ))
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()


async def is_ip_blocked(ip: str) -> bool:
    await _refresh_cache_if_stale()
    return ip in _blocked_ips_cache


async def block_ip(
    ip: str,
    protocol: str = "TCP",
    port: int = 0,
    src_bytes: float = 0.0,
    reason: str = "AUTO",
    attack_type: str = "Suspicious Traffic",
) -> bool:
    if ip in _blocked_ips_cache:
        return False
    loop = asyncio.get_running_loop()
    added = await loop.run_in_executor(None, _sync_add_to_db, ip, protocol, port, src_bytes, reason, attack_type)
    if added:
        async with _cache_lock:
            _blocked_ips_cache.add(ip)
    return added


def sync_block_ip(
    ip: str,
    protocol: str = "TCP",
    port: int = 0,
    src_bytes: float = 0.0,
    reason: str = "AUTO",
    attack_type: str = "Suspicious Traffic",
) -> bool:
    if ip in _blocked_ips_cache:
        return False
    added = _sync_add_to_db(ip, protocol, port, src_bytes, reason, attack_type)
    if added:
        _blocked_ips_cache.add(ip)
    return added


def is_ip_blocked_sync(ip: str) -> bool:
    global _cache_ts
    now = time.monotonic()
    if (now - _cache_ts) >= CACHE_TTL or not _blocked_ips_cache:
        ips = _load_blocked_ips_from_db()
        _blocked_ips_cache.clear()
        _blocked_ips_cache.update(ips)
        _cache_ts = now
    return ip in _blocked_ips_cache


async def unblock_ip(ip: str) -> bool:
    loop = asyncio.get_running_loop()
    removed = await loop.run_in_executor(None, _sync_remove_from_db, ip)
    if removed:
        async with _cache_lock:
            _blocked_ips_cache.discard(ip)
    return removed


def _sync_remove_from_db(ip: str) -> bool:
    db = SessionLocal()
    try:
        row = db.query(BlockedIP).filter(BlockedIP.ip_address == ip).first()
        if not row:
            return False
        db.delete(row)
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False
    finally:
        db.close()
