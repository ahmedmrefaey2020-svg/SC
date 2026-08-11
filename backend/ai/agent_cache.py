"""
LLM Result Cache — prevents calling HuggingFace on every request.
Agents cache their analysis for a configurable TTL (default 60 sec for normal,
15 sec for active attack).  Only triggers a new LLM call when:
  - Cache expired
  - A NEW attack is detected (score change > threshold)
"""
import time
import threading
from typing import Any, Optional

_cache_lock = threading.Lock()


class _CacheEntry:
    __slots__ = ("value", "expires_at", "score_snapshot")

    def __init__(self, value: Any, ttl: float, score: float = 0.0):
        self.value = value
        self.expires_at = time.monotonic() + ttl
        self.score_snapshot = score

    def is_valid(self, current_score: float = 0.0, score_delta_threshold: float = 20.0) -> bool:
        if time.monotonic() > self.expires_at:
            return False
        # Invalidate early if score has jumped significantly (new attack wave)
        if abs(current_score - self.score_snapshot) > score_delta_threshold:
            return False
        return True


class AgentResultCache:
    """
    Thread-safe per-agent result cache with TTL and score-change invalidation.
    """

    def __init__(self):
        self._entries: dict[str, _CacheEntry] = {}

    def get(self, key: str, current_score: float = 0.0) -> Optional[Any]:
        with _cache_lock:
            entry = self._entries.get(key)
            if entry and entry.is_valid(current_score):
                return entry.value
        return None

    def set(self, key: str, value: Any, ttl: float, score: float = 0.0) -> None:
        with _cache_lock:
            self._entries[key] = _CacheEntry(value, ttl, score)

    def invalidate(self, key: str) -> None:
        with _cache_lock:
            self._entries.pop(key, None)

    def invalidate_all(self) -> None:
        with _cache_lock:
            self._entries.clear()


# Global singleton shared across all agents
agent_cache = AgentResultCache()

# TTL constants (seconds)
NORMAL_TRAFFIC_TTL = 90.0   # 90 sec when no attack — barely any tokens used
ATTACK_ACTIVE_TTL  = 20.0   # 20 sec refresh during active attack
