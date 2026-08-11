import threading
from collections import deque
from backend.core.config import get_settings

_cfg = get_settings()

_packet_queue: deque = deque(maxlen=_cfg.BATCH_SIZE * 2)
_queue_lock = threading.Lock()


def clear_packet_queue():
    with _queue_lock:
        _packet_queue.clear()


def packet_callback(packet):
    try:
        from scapy.all import IP
        if packet.haslayer(IP):
            with _queue_lock:
                _packet_queue.append(packet)
    except Exception:
        pass


def extract_packet_features(packet) -> tuple[dict, str, str, int, float, str, bool, bool]:
    from scapy.all import IP, TCP, UDP

    src_bytes = float(len(packet))
    has_tcp = packet.haslayer(TCP)
    has_udp = packet.haslayer(UDP)
    protocol = "TCP" if has_tcp else ("UDP" if has_udp else "OTHER")
    port = int(packet[TCP].dport) if has_tcp else (int(packet[UDP].dport) if has_udp else 0)

    tcp_flags = str(packet[TCP].flags) if has_tcp else ""
    tcp_window = float(packet[TCP].window) if has_tcp else 0.0
    tcp_len = float(len(packet[TCP])) if has_tcp else 0.0

    is_syn = "S" in tcp_flags
    is_ack = "A" in tcp_flags

    payload = {
        "Flow Duration": 0.0,
        "Flow IAT Mean": 0.0,
        "Flow IAT Max": 0.0,
        "Flow IAT Min": 0.0,
        "TotLen Fwd Pkts": src_bytes,
        "TotLen Bwd Pkts": 0.0,
        "Fwd Pkt Len Max": src_bytes,
        "Fwd Pkt Len Mean": src_bytes,
        "Bwd Pkt Len Max": 0.0,
        "Bwd Pkt Len Mean": 0.0,
        "Pkt Size Avg": src_bytes,
        "FIN Flag Cnt": 1.0 if "F" in tcp_flags else 0.0,
        "SYN Flag Cnt": 1.0 if is_syn else 0.0,
        "RST Flag Cnt": 1.0 if "R" in tcp_flags else 0.0,
        "PSH Flag Cnt": 1.0 if "P" in tcp_flags else 0.0,
        "ACK Flag Cnt": 1.0 if is_ack else 0.0,
        "URG Flag Cnt": 1.0 if "U" in tcp_flags else 0.0,
        "Init Fwd Win Byts": tcp_window,
        "Init Bwd Win Byts": 0.0,
        "Flow Byts/s": src_bytes,
        "Flow Pkts/s": 1.0,
        "Fwd Pkt Len Std": 0.0,
        "Pkt Len Var": 0.0,
        "Fwd Header Len": tcp_len,
    }
    return payload, packet[IP].src, packet[IP].dst, port, src_bytes, protocol, is_syn, is_ack
