#!/usr/bin/env python3
"""
NetSentry Network Scanner (continuous) - كيمسح الشبكة المحلية بـ nmap بشكل متكرر
وكيحدث حالة كل جهاز فالداشبورد: Active إلا كان خدام دابا، Inactive إلا اختفى من المسح.

الاستعمال:
    sudo python3 network_scanner.py 172.20.10.0/28          # loop دائم (كل SCAN_INTERVAL ثانية)
    sudo python3 network_scanner.py 172.20.10.0/28 --once    # مسحة وحدة وخروج
"""

import sys
import re
import time
import subprocess
import requests
import xml.etree.ElementTree as ET

DASHBOARD_URL = "http://172.20.10.2:5173/api/machines"
SCAN_INTERVAL = 60  # ثانية بين كل مسح


def get_local_subnet() -> str:
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if "/" in line and "src" in line:
                cidr = line.split()[0]
                if "/" in cidr:
                    return cidr
    except Exception:
        pass
    return "172.20.10.0/28"


def run_nmap_scan(subnet: str) -> str:
    print(f"[*] كيمسح الشبكة: {subnet}")
    result = subprocess.run(
        ["nmap", "-sS", "-O", "--osscan-guess", "-T4", "-oX", "-", subnet],
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        print(f"[ERROR] nmap فشل: {result.stderr}")
        return ""
    return result.stdout


def parse_nmap_xml(xml_data: str):
    if not xml_data:
        return []
    root = ET.fromstring(xml_data)
    machines = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            continue
        ip = addr_elem.get("addr")

        hostname = ip
        hostnames_elem = host.find("hostnames")
        if hostnames_elem is not None:
            hn = hostnames_elem.find("hostname")
            if hn is not None and hn.get("name"):
                hostname = hn.get("name")

        open_ports = []
        ports_elem = host.find("ports")
        if ports_elem is not None:
            for port in ports_elem.findall("port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    portid = port.get("portid")
                    proto = port.get("protocol")
                    service_elem = port.find("service")
                    service_name = service_elem.get("name") if service_elem is not None else "unknown"
                    open_ports.append(f"{portid}/{proto} ({service_name})")

        os_name = "Unknown"
        os_elem = host.find("os")
        if os_elem is not None:
            osmatch = os_elem.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "Unknown")

        notes = f"Open ports: {', '.join(open_ports) if open_ports else 'none detected'}"

        machines.append({
            "ipAddress": ip,
            "hostname": hostname,
            "os": os_name,
            "status": "active",
            "notes": notes,
        })

    return machines


def get_existing_machines():
    """يرجع dict: ipAddress -> {id, status}"""
    try:
        resp = requests.get(DASHBOARD_URL, timeout=10)
        if resp.status_code == 200:
            return {m["ipAddress"]: m for m in resp.json()}
    except requests.exceptions.RequestException as e:
        print(f"[WARN] ما قدرتش نجيب الأجهزة الموجودين: {e}")
    return {}


def upsert_machine(machine: dict, existing: dict):
    ip = machine["ipAddress"]
    try:
        if ip in existing:
            machine_id = existing[ip]["id"]

            # ما نبدلوش hostname الموجود فالداتاباز بالـIP
            # إلا Nmap ما لقا حتى hostname حقيقي.
            update_data = {
               "hostname": existing[ip].get("hostname") or machine["hostname"],
               "os": machine["os"],
               "status": machine["status"],
               "notes": machine["notes"],
            }

            if machine["hostname"] != ip:
                update_data["hostname"] = machine["hostname"]

            resp = requests.patch(
                f"{DASHBOARD_URL}/{machine_id}",
                json=update_data,
                timeout=10,
            )
            action = "UPDATED (active)"
        else:
            resp = requests.post(
                DASHBOARD_URL,
                json=machine,
                timeout=10,
            )
            action = "ADDED (active)"

        if resp.status_code in (200, 201):
            print(f"[OK] {action}: {machine['hostname']} ({ip})")
        else:
            print(f"[WARN] {ip} -> {resp.status_code}: {resp.text}")

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] ما قدرتش نبعث {ip}: {e}")

def mark_inactive(ip: str, existing: dict):
    """يبدل حالة جهاز كان معروف قبل، لكن ما بانش فهاد المسحة"""
    info = existing[ip]
    if info.get("status") == "inactive":
        return  # ديجا inactive، ماخاصوش نعاود
    try:
        resp = requests.patch(
            f"{DASHBOARD_URL}/{info['id']}", json={"status": "inactive"}, timeout=10
        )
        if resp.status_code == 200:
            print(f"[OK] MARKED INACTIVE: {info.get('hostname', ip)} ({ip})")
        else:
            print(f"[WARN] ما قدرتش نبدل حالة {ip}: {resp.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {ip}: {e}")


def run_one_cycle(subnet: str):
    xml_data = run_nmap_scan(subnet)
    found_machines = parse_nmap_xml(xml_data)
    found_ips = {m["ipAddress"] for m in found_machines}

    print(f"[*] لقا {len(found_machines)} جهاز(أجهزة) خدامين دابا")

    existing = get_existing_machines()

    # 1) الأجهزة اللي بانو دابا -> Active
    for machine in found_machines:
        upsert_machine(machine, existing)

    # 2) الأجهزة اللي كانو معروفين قبل، وما بانوش هاد المرة -> Inactive
    for ip in existing:
        if ip not in found_ips:
            mark_inactive(ip, existing)

    print("[*] كملت الدورة.")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    once = "--once" in sys.argv
    subnet = args[0] if args else get_local_subnet()

    print(f"[*] NetSentry Network Scanner بدا...")
    print(f"[*] كيبعث لـ: {DASHBOARD_URL}")
    print(f"[*] الشبكة: {subnet}")
    print("-" * 60)

    if once:
        run_one_cycle(subnet)
        return

    while True:
        run_one_cycle(subnet)
        print(f"[*] كنستنى {SCAN_INTERVAL} ثانية قبل الدورة الجاية...")
        print("-" * 60)
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
