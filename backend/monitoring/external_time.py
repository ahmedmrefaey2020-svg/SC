import threading
import time

_last_external_data_time: float = 0.0
_external_time_lock = threading.Lock()


def update_last_external_time():
    global _last_external_data_time
    with _external_time_lock:
        _last_external_data_time = time.time()


def get_last_external_time() -> float:
    with _external_time_lock:
        return _last_external_data_time


def is_agent_offline(offline_threshold_seconds: float = 15.0) -> bool:
    last = get_last_external_time()
    if last <= 0:
        return True
    return (time.time() - last) > offline_threshold_seconds
