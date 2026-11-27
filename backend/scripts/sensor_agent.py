"""Lightweight remote VLAN sensor agent for pushing Suricata eve.json to central NetSentinel.

Usage:
  export NETSENTINEL_SERVER_URL="https://soc.hospital.local"
  export NETSENTINEL_SENSOR_KEY="ns_sensor_..."
  python sensor_agent.py /var/log/suricata/eve.json
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import httpx


def main() -> None:
    server_url = os.environ.get("NETSENTINEL_SERVER_URL", "").rstrip("/")
    sensor_key = os.environ.get("NETSENTINEL_SENSOR_KEY", "")
    if not server_url or not sensor_key:
        raise RuntimeError(
            "NETSENTINEL_SERVER_URL and NETSENTINEL_SENSOR_KEY environment variables are required"
        )

    eve_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/var/log/suricata/eve.json")
    if not eve_path.exists():
        raise FileNotFoundError(f"Suricata eve.json not found at {eve_path}")

    endpoint = f"{server_url}/api/enterprise/sensors/ingest"
    offset = eve_path.stat().st_size

    with httpx.Client(timeout=5.0) as client:
        while True:
            size = eve_path.stat().st_size
            if size > offset:
                with eve_path.open("r", encoding="utf-8", errors="ignore") as f:
                    f.seek(offset)
                    chunk = f.read(500_000)
                    offset = f.tell()
                if chunk.strip():
                    resp = client.post(
                        endpoint,
                        headers={"X-Sensor-Key": sensor_key},
                        json={"suricata_eve_ndjson": chunk},
                    )
                    resp.raise_for_status()
            time.sleep(2.0)


if __name__ == "__main__":
    main()
