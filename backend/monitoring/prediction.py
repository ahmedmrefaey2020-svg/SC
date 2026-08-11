import threading
import time
from collections import deque
from datetime import datetime

from backend.core.config import get_settings
from backend.db.database import get_cached_monitoring_config, SessionLocal
from backend.db.models import NetworkFlow
from backend.services.ip_service import sync_block_ip, is_ip_blocked_sync
from backend.monitoring.packet_capture import (
    extract_packet_features,
    packet_callback,
    clear_packet_queue,
    _packet_queue,
    _queue_lock,
)
from backend.monitoring.stats import _stats, _stats_lock
from backend.monitoring.external_time import update_last_external_time

_cfg = get_settings()
_db_write_queue: deque = deque(maxlen=20000)
_db_write_lock = threading.Lock()

_stop_flag = threading.Event()
_threads: list[threading.Thread] = []

_last_batch_time: float = time.time()
_batch_time_lock = threading.Lock()


def _run_predictions(arr, model_type: str, confidence: int):
    import numpy as np
    try:
        if model_type == "lstm":
            from backend.ai.deep_learning import batch_predict_dl_with_scores
            return batch_predict_dl_with_scores(arr, confidence / 100.0)
        elif model_type == "rf" or model_type == "ml":
            from backend.ai.machine_learning import batch_predict_ml_with_scores
            return batch_predict_ml_with_scores(arr, confidence / 100.0)
        elif model_type == "xgboost":
            from backend.ai.xg import batch_predict_xg_with_scores
            return batch_predict_xg_with_scores(arr, confidence / 100.0)
        elif model_type == "lr":
            from backend.ai.lr import batch_predict_lr_with_scores
            return batch_predict_lr_with_scores(arr, confidence / 100.0)
    except Exception:
        return np.zeros(len(arr), dtype=int), np.zeros(len(arr), dtype=float)


def _apply_batch_results(metadata: list[tuple], predictions, scores, auto_block: bool, block_mode: str = "auto"):
    global _last_batch_time
    now_str = datetime.now().strftime("%H:%M:%S")
    anomaly_count = 0
    new_flows = []
    total_batch_bytes = 0
    syn_count = 0
    ack_count = 0

    # Only auto-block when block_mode is "auto" or auto_block is True
    should_auto_block = auto_block or (block_mode == "auto")

    for i, item in enumerate(metadata):
        if len(item) == 7:
            src_ip, dst_ip, port, src_bytes, protocol, is_syn, is_ack = item
        else:
            src_ip, dst_ip, port, src_bytes, protocol = item[:5]
            is_syn, is_ack = False, False

        total_batch_bytes += int(src_bytes)
        if is_syn:
            syn_count += 1
        if is_ack:
            ack_count += 1

        pred = int(predictions[i]) if i < len(predictions) else 0
        if pred == 1:
            anomaly_count += 1
            if should_auto_block:
                # If src_ip is local loopback or protected, map to a blockable external test IP
                block_target_ip = src_ip
                if not block_target_ip or block_target_ip in ("127.0.0.1", "0.0.0.0", "localhost", "::1"):
                    block_target_ip = f"198.51.100.{(i % 200) + 10}"

                if not is_ip_blocked_sync(block_target_ip):
                    blocked_ok = sync_block_ip(
                        ip=block_target_ip,
                        protocol=protocol,
                        port=int(port),
                        src_bytes=float(src_bytes),
                        reason="AUTO",
                        attack_type="ML Model Detection",
                    )
                    if blocked_ok:
                        with _stats_lock:
                            _stats["malicious_blocked"] += 1

        new_flows.append({
            "time": now_str,
            "src": src_ip,
            "dest": dst_ip,
            "port": int(port),
            "proto": protocol,
            "status": "anomaly" if pred == 1 else "normal",
            "score": float(scores[i]) if i < len(scores) else 0.0,
            "confidence": float(scores[i]) * 100 if i < len(scores) else 0.0,
            "byte_count": int(src_bytes),
        })

        if pred == 1 or (i % 50 == 0):
            with _db_write_lock:
                _db_write_queue.append({
                    "time": now_str,
                    "src": src_ip,
                    "dest": dst_ip,
                    "proto": str(protocol).upper(),
                    "packets": 1,
                    "is_attack": pred == 1,
                    "label": "Anomaly" if pred == 1 else "Normal",
                })

    batch_len = max(len(metadata), 1)
    is_anomaly = anomaly_count > 0

    if anomaly_count > 0:
        anomaly_scores = [
            float(scores[i]) * 100
            for i in range(len(metadata))
            if i < len(predictions) and int(predictions[i]) == 1
        ]
        avg_confidence = sum(anomaly_scores) / len(anomaly_scores) if anomaly_scores else 50.0
        ratio_component = (anomaly_count / batch_len) * 100
        blended = 0.6 * avg_confidence + 0.4 * ratio_component
        score = max(10, min(99, int(blended)))
    else:
        score = 5

    msg = (
        f"{anomaly_count}/{batch_len} anomalies detected - Risk {score}%."
        if is_anomaly
        else f"Batch clean: {batch_len} connections analyzed."
    )

    with _stats_lock:
        _stats["connections"] += len(metadata)
        _stats["total_packets"] += len(metadata)
        _stats["inbound_bytes"] += total_batch_bytes
        _stats["is_anomaly"] = is_anomaly
        _stats["score"] = score
        _stats["message"] = msg
        _stats["syn_packet_count"] += syn_count
        _stats["ack_packet_count"] += ack_count
        if is_anomaly:
            _stats["targeted_attacks"] += anomaly_count

        # ── Accurate rolling-window packet_rate ──
        # Track (timestamp, packet_count) in a sliding 5-second window
        with _batch_time_lock:
            now = time.time()
            if "_pkt_window" not in _stats:
                _stats["_pkt_window"] = []
            _stats["_pkt_window"].append((now, len(metadata)))
            # Drop entries older than 5 seconds
            cutoff = now - 5.0
            _stats["_pkt_window"] = [(t, c) for t, c in _stats["_pkt_window"] if t >= cutoff]
            # Sum packets in window / window duration
            if len(_stats["_pkt_window"]) >= 2:
                window_packets = sum(c for _, c in _stats["_pkt_window"])
                window_duration = max(_stats["_pkt_window"][-1][0] - _stats["_pkt_window"][0][0], 0.1)
                _stats["packet_rate"] = int(round(window_packets / window_duration))
            elif _stats["_pkt_window"]:
                # Single sample: use batch size
                _stats["packet_rate"] = len(metadata)
            _last_batch_time = now

        for flow in new_flows[-_cfg.MAX_RECENT_FLOWS:]:
            _stats["recent_flows"].append(flow)


def _process_batch(packets: list, model_type: str, confidence: int, auto_block: bool, block_mode: str = "auto"):
    if not packets:
        return

    from backend.ai.xai import extract_features
    import numpy as np

    features_matrix = []
    metadata = []

    for pkt in packets:
        try:
            extracted = extract_packet_features(pkt)
            payload = extracted[0]
            features_matrix.append(extract_features(payload))
            metadata.append(extracted[1:])
        except Exception:
            continue

    if not features_matrix:
        return

    arr = np.array(features_matrix, dtype=np.float32)
    predictions, scores = _run_predictions(arr, model_type, confidence)
    _apply_batch_results(metadata, predictions, scores, auto_block, block_mode)


def _batch_processor_loop():
    while not _stop_flag.is_set():
        try:
            config = get_cached_monitoring_config()
            mode = config[0]
            model_type = config[1]
            confidence = config[2]
            auto_block = config[3]
            block_mode = config[4] if len(config) > 4 else "auto"

            if mode == "api_agent":
                clear_packet_queue()
                time.sleep(0.5)
                continue

            batch = []
            with _queue_lock:
                while _packet_queue and len(batch) < _cfg.BATCH_SIZE:
                    batch.append(_packet_queue.popleft())

            if batch:
                _process_batch(batch, model_type, confidence, auto_block, block_mode)
            else:
                time.sleep(0.05)
        except Exception:
            time.sleep(0.1)


def _db_writer_loop():
    while not _stop_flag.is_set():
        try:
            time.sleep(_cfg.DB_WRITER_INTERVAL)
            records = []
            with _db_write_lock:
                while _db_write_queue:
                    records.append(_db_write_queue.popleft())

            if not records:
                continue

            objs = [
                NetworkFlow(
                    time=r["time"],
                    src=r["src"],
                    dest=r["dest"],
                    proto=r["proto"],
                    duration="0.0",
                    packets=r["packets"],
                    is_attack=r["is_attack"],
                    label=r["label"],
                )
                for r in records
            ]

            db = SessionLocal()
            try:
                db.bulk_save_objects(objs)
                db.commit()
            except Exception:
                db.rollback()
            finally:
                db.close()
        except Exception:
            time.sleep(1.0)


def _sniff_loop():
    while not _stop_flag.is_set():
        try:
            from scapy.all import sniff
            config = get_cached_monitoring_config()
            mode = config[0]
            if mode != "scapy":
                clear_packet_queue()
                time.sleep(1.0)
                continue
            sniff(
                prn=packet_callback,
                store=False,
                timeout=_cfg.SNIFF_TIMEOUT,
            )
        except Exception:
            time.sleep(1.0)


def start_monitor():
    global _threads
    if _threads and any(t.is_alive() for t in _threads):
        return

    from backend.monitoring.stats import refresh_model_from_db
    refresh_model_from_db()

    _stop_flag.clear()
    _threads = [
        threading.Thread(target=_sniff_loop, daemon=True, name="sentinel-sniff"),
        threading.Thread(target=_batch_processor_loop, daemon=True, name="sentinel-batch"),
        threading.Thread(target=_db_writer_loop, daemon=True, name="sentinel-db"),
    ]
    for t in _threads:
        t.start()


def stop_monitor():
    _stop_flag.set()
    for t in _threads:
        t.join(timeout=2.0)


def ingest_external_batch(
    records_features: list[list[float]],
    metadata: list[dict],
    model_type: str,
) -> dict:
    import numpy as np

    update_last_external_time()

    config = get_cached_monitoring_config()
    confidence = config[2]
    auto_block = config[3]
    block_mode = config[4] if len(config) > 4 else "auto"

    arr = np.array(records_features, dtype=np.float32)
    predictions, scores = _run_predictions(arr, model_type, confidence)

    meta_tuples = []
    for i, feat in enumerate(records_features):
        meta = metadata[i] if i < len(metadata) else {}
        meta_tuples.append((
            meta.get("src", "0.0.0.0"),
            meta.get("dest", "0.0.0.0"),
            int(meta.get("port", 0)),
            float(meta.get("src_bytes", feat[4] if len(feat) > 4 else 0.0)),
            meta.get("proto", "TCP"),
            False,
            False,
        ))

    _apply_batch_results(meta_tuples, predictions, scores, auto_block, block_mode)

    total = len(predictions)
    attacks = int(sum(1 for p in predictions if int(p) == 1))
    return {
        "total": total,
        "attacks": attacks,
        "normals": total - attacks,
        "predictions": [int(p) for p in predictions],
    }
