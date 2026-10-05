#!/usr/bin/env python3
"""
NetSentry PCAP Receiver - كيستقبل ملفات pcap من الأجهزة (agents) وكيشغل Snort عليهم
خدام مع snort_bridge.py: الـ alerts الجداد كيتزادو فـ snort.alert.fast وبعدها
snort_bridge.py كيشدهم أوتوماتيكيا ويبعثهم للداشبورد.

الاستعمال:
    pip3 install flask --break-system-packages
    python3 pcap_receiver.py
"""

import os
import subprocess
import threading
import time
from datetime import datetime
from flask import Flask, request, jsonify

UPLOAD_DIR = "/home/youssef/pcap_uploads"
SNORT_CONF = "/etc/snort/snort.conf"
LISTEN_PORT = 8000

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)


def process_pcap(filepath: str, hostname: str):
    """يدير snort فموضة offline على الملف، والـ alerts كيتزادو تلقائيا فـ snort.alert.fast"""
    print(f"[*] كيحلل: {filepath} (من {hostname})")
    try:
        result = subprocess.run(
            [
                "sudo", "snort",
                "-r", filepath,
                "-c", SNORT_CONF,
                "-q",  # quiet mode
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            print(f"[WARN] snort رجع كود {result.returncode}: {result.stderr[:300]}")
        else:
            print(f"[OK] تحليل {os.path.basename(filepath)} كمل")
    except subprocess.TimeoutExpired:
        print(f"[ERROR] Timeout فتحليل {filepath}")
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        try:
            pass
            print(f"[OK] تحيد: {os.path.basename(filepath)}")
        except OSError as e:
            print(f"[WARN] ما قدرناش نحيدو {filepath}: {e}")


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "no file part"}), 400

    file = request.files["file"]
    hostname = request.form.get("hostname", "unknown")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    filename = f"{hostname}_{timestamp}.pcap"
    filepath = os.path.join(UPLOAD_DIR, filename)
    file.save(filepath)

    print(f"[RECEIVED] {filename} ({os.path.getsize(filepath)} bytes)")

    # نديرو التحليل فـ thread منفصل باش ما نوقفوش الـ response
    threading.Thread(target=process_pcap, args=(filepath, hostname), daemon=True).start()

    return jsonify({"status": "received", "filename": filename}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


if __name__ == "__main__":
    print(f"[*] NetSentry PCAP Receiver بدا على البورت {LISTEN_PORT}")
    print(f"[*] كيسجل الملفات فـ: {UPLOAD_DIR}")
    app.run(host="0.0.0.0", port=LISTEN_PORT)
