#!/usr/bin/env python3
"""
NetSentry Bridge - يقرا Snort alert_fast log ويبعث الـ alerts للداشبورد
"""
import os
import time
import re
import uuid
import requests
from datetime import datetime, timezone

# ============ الإعدادات - بدل حسب الحاجة ============
LOG_FILE = "/var/log/snort/snort.alert.fast"
DASHBOARD_URL = "http://172.20.10.2:5173/api/alerts"
POLL_INTERVAL = 1  # ثانية بين كل قراءة

# ============ خريطة الـ Priority -> Severity ============
PRIORITY_TO_SEVERITY = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}

# فورمة سطر alert_fast:
# 09/15-10:48:46.379131  [**] [1:1000001:1] ICMP Ping Detected [**] [Priority: 0] {ICMP} 192.168.76.1 -> 192.168.76.129
ALERT_PATTERN = re.compile(
    r"^(?P<timestamp>\d{2}/\d{2}-\d{2}:\d{2}:\d{2}\.\d+)\s+"
    r"\[\*\*\]\s+"
    r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<signature>.+?)\s+"
    r"\[\*\*\]\s+"
    r"(?:\[Classification:\s*(?P<classification>[^\]]*)\]\s*)?"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<protocol>\w+)\}\s+"
    r"(?P<src_ip>[\d.]+)(?::(?P<src_port>\d+))?\s*->\s*"
    r"(?P<dst_ip>[\d.]+)(?::(?P<dst_port>\d+))?"
)


def parse_snort_timestamp(ts: str) -> str:
    """يحول 09/15-10:48:46.379131 لصيغة ISO 8601 (بالسنة الحالية)"""
    current_year = datetime.now().year
    date_part, time_part = ts.split("-")
    month, day = date_part.split("/")
    dt = datetime.strptime(
        f"{current_year}-{month}-{day} {time_part}", "%Y-%m-%d %H:%M:%S.%f"
    )
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def parse_line(line: str):
    """يحول سطر خام من Snort لـ dict متوافق مع API الداشبورد"""
    match = ALERT_PATTERN.match(line.strip())
    if not match:
        return None

    data = match.groupdict()
    # Snort priorities can be 0 (or higher), lekin l'API katsna 1..4 f "priority" (minimum 1, maximum 4)
    raw_priority = int(data["priority"])
    priority = min(max(raw_priority, 1), 4)
    # muhim: severity kanhsboha b raw_priority (0 = low bhal ping), machi b priority l msah-h-ha
    severity = PRIORITY_TO_SEVERITY.get(raw_priority, "low" if raw_priority == 0 else "medium")
    classification = data.get("classification") or "Unclassified"

    return {
        "id": str(uuid.uuid4()),
        "signature": data["signature"].strip(),
        "signatureId": f"{data['gid']}:{data['sid']}:{data['rev']}",
        "classification": classification,
        "priority": priority,
        "severity": severity,
        "sourceIp": data["src_ip"],
        "sourcePort": int(data["src_port"]) if data["src_port"] else 0,
        "destIp": data["dst_ip"],
        "destPort": int(data["dst_port"]) if data["dst_port"] else 0,
        "protocol": data["protocol"],
        "rawLog": line.strip(),
        "status": "new",
        "detectedAt": parse_snort_timestamp(data["timestamp"]),
    }


def send_alert(alert: dict):
    try:
        resp = requests.post(DASHBOARD_URL, json=alert, timeout=5)
        if resp.status_code in (200, 201):
            print(f"[OK] Sent: {alert['signature']} ({alert['sourceIp']} -> {alert['destIp']})")
        else:
            print(f"[WARN] Server returned {resp.status_code}: {resp.text}")
            print(f"[DEBUG] Payload sent: {alert}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Could not reach dashboard: {e}")


def follow(filepath):
    """tail -f مع تجاهل القديم فالأول والتعامل مع file rotation"""
    position = 0
    inode = None
    first_open = True

    while True:
        try:
            stat = os.stat(filepath)
            current_inode = stat.st_ino

            if inode != current_inode:
                inode = current_inode

                if first_open:
                    position = stat.st_size
                    first_open = False
                else:
                    position = 0

            with open(filepath, "r") as f:
                f.seek(position)

                while True:
                    line = f.readline()

                    if line:
                        position = f.tell()
                        yield line
                        continue

                    try:
                        new_stat = os.stat(filepath)

                        if new_stat.st_ino != inode:
                            break

                    except FileNotFoundError:
                        break

                    time.sleep(POLL_INTERVAL)

        except FileNotFoundError:
            time.sleep(POLL_INTERVAL)

def main():
    print(f"[*] NetSentry Bridge بدا الخدمة...")
    print(f"[*] كيراقب: {LOG_FILE}")
    print(f"[*] كيبعث لـ: {DASHBOARD_URL}")
    print("-" * 60)

    for line in follow(LOG_FILE):
        if not line.strip():
            continue
        alert = parse_line(line)
        if alert:
            send_alert(alert)
        else:
            print(f"[SKIP] Could not parse line: {line.strip()[:80]}")


if __name__ == "__main__":
    main()
