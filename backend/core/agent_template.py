import time
import requests
import json

SERVER_URL = "REPLACE_WITH_YOUR_SITE_URL"
AGENT_TOKEN = "REPLACE_WITH_USER_TOKEN"

def collect_system_telemetry():
    return {
        "records": [
            {
                "src": "192.168.1.100",
                "dest": "10.0.0.1",
                "port": 80,
                "proto": "TCP",
                "Flow Duration": 0.5,
                "TotLen Fwd Pkts": 1024,
                "Flow Pkts/s": 10.0
            }
        ]
    }

def main():
    print(f"[Sentinel Agent] Starting telemetry agent connecting to {SERVER_URL}")
    endpoint = f"{SERVER_URL}/api/external-data-ingest"
    headers = {
        "Content-Type": "application/json",
        "token": AGENT_TOKEN
    }
    
    while True:
        try:
            payload = collect_system_telemetry()
            resp = requests.post(endpoint, json=payload, headers=headers, timeout=10)
            if resp.status_code == 200:
                print(f"[Sentinel Agent] Ingestion success: {resp.json()}")
            else:
                print(f"[Sentinel Agent] Ingestion error ({resp.status_code}): {resp.text}")
        except Exception as e:
            print(f"[Sentinel Agent] Connection error: {e}")
        time.sleep(5)

if __name__ == "__main__":
    main()
