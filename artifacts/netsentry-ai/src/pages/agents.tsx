import { useMemo, useState } from 'react';
import {
  Check,
  Copy,
  Download,
  Radio,
  Terminal,
  Info,
} from 'lucide-react';
import { PageTitle, Surface } from '@/components/ui-kit';

const DEFAULT_SERVER = window.location.hostname || '172.20.10.2';
const RECEIVER_PORT = 8000;

function CopyBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard may be unavailable on non-secure HTTP pages.
    }
  };

  return (
    <div className="relative">
      <button
        onClick={copy}
        className="absolute right-3 top-3 flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-[11px] font-medium text-slate-300 hover:bg-slate-700"
      >
        {copied ? (
          <Check size={12} className="text-emerald-400" />
        ) : (
          <Copy size={12} />
        )}
        {copied ? 'Copied' : 'Copy'}
      </button>

      <pre className="max-h-[500px] overflow-auto rounded-xl border border-slate-800 bg-[#0b0f1a] p-4 font-mono text-[11px] leading-5 text-slate-300">
        {code}
      </pre>
    </div>
  );
}

export default function Agents() {
  const [serverIp, setServerIp] = useState(DEFAULT_SERVER);
  const [networkInterface, setNetworkInterface] = useState('5');

  const agentScript = useMemo(() => {
    const server = serverIp.trim() || DEFAULT_SERVER;
    const iface = networkInterface.trim() || '5';

    return `#!/usr/bin/env python3
"""
NetSentry Client Agent

Captures Windows network traffic with dumpcap.exe
and uploads rotated PCAP files to the NetSentry server.

Requirements:
    - Wireshark + Npcap
    - Python 3
    - requests

Install:
    pip install requests

Run:
    python client_agent.py
"""

import os
import time
import socket
import subprocess
import glob
import requests


SERVER_URL = "http://${server}:${RECEIVER_PORT}/upload"
DUMPCAP_PATH = r"C:\\Program Files\\Wireshark\\dumpcap.exe"

CAPTURE_DIR = os.path.join(
    os.environ.get("TEMP", "."),
    "netsentry_capture"
)

ROTATE_SECONDS = 30
INTERFACE = "${iface}"
HOSTNAME = socket.gethostname()

os.makedirs(CAPTURE_DIR, exist_ok=True)


def check_dumpcap():
    if not os.path.exists(DUMPCAP_PATH):
        print("[ERROR] dumpcap.exe not found:")
        print(DUMPCAP_PATH)
        print()
        print("Install Wireshark + Npcap first.")
        return False

    return True


def start_capture():
    output_pattern = os.path.join(
        CAPTURE_DIR,
        "capture.pcap"
    )

    cmd = [
        DUMPCAP_PATH,
        "-b",
        f"duration:{ROTATE_SECONDS}",
        "-w",
        output_pattern,
        "-i",
        INTERFACE,
    ]

    print("[*] Starting dumpcap...")
    print("[*] Interface:", INTERFACE)
    print("[*] Rotation:", ROTATE_SECONDS, "seconds")

    return subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def upload_file(filepath):
    filename = os.path.basename(filepath)

    try:
        print("[*] Uploading:", filename)

        with open(filepath, "rb") as f:
            files = {
                "file": (
                    filename,
                    f,
                    "application/vnd.tcpdump.pcap",
                )
            }

            response = requests.post(
                SERVER_URL,
                files=files,
                data={
                    "hostname": HOSTNAME,
                },
                timeout=120,
            )

        if response.status_code == 200:
            print("[OK] Uploaded:", filename)

            try:
                os.remove(filepath)
                print("[OK] Deleted:", filename)
            except PermissionError:
                print("[WARN] File is still locked:", filename)

            return True

        print(
            "[WARN] Server returned:",
            response.status_code,
        )

        return False

    except requests.exceptions.RequestException as error:
        print("[ERROR] Upload failed:", error)
        return False

    except Exception as error:
        print("[ERROR]:", error)
        return False


def main():
    print()
    print("===================================")
    print("       NetSentry Client Agent")
    print("===================================")
    print("[*] Hostname :", HOSTNAME)
    print("[*] Server   :", SERVER_URL)
    print("[*] Interface:", INTERFACE)
    print("[*] Rotation :", ROTATE_SECONDS, "seconds")
    print()

    if not check_dumpcap():
        return

    process = start_capture()

    try:
        while True:
            files = sorted(
                glob.glob(
                    os.path.join(
                        CAPTURE_DIR,
                        "capture_*.pcap",
                    )
                )
            )

            # The newest file is normally still being written.
            # Upload only older/closed files.
            for filepath in files[:-1]:
                upload_file(filepath)

            time.sleep(5)

    except KeyboardInterrupt:
        print()
        print("[*] Stopping Agent...")

        process.terminate()

        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()

        print("[OK] Agent stopped.")


if __name__ == "__main__":
    main()
`;
  }, [serverIp, networkInterface]);

  const downloadAgent = () => {
    const blob = new Blob(
      [agentScript],
      { type: 'text/x-python;charset=utf-8' }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = 'client_agent.py';

    document.body.appendChild(link);
    link.click();
    link.remove();

    URL.revokeObjectURL(url);
  };

  return (
    <div className="animate-rise">
      <PageTitle
        eyebrow="Assets / Endpoint telemetry"
        title="Agents"
        description="Turn any Windows PC into a sensor that streams its own traffic to this dashboard."
        action={
          <div className="flex items-center gap-2 rounded-lg border border-violet-400/20 bg-violet-400/5 px-3 py-2 text-xs font-semibold text-violet-300">
            <Radio size={14} />
            Self-serve setup
          </div>
        }
      />

      <Surface className="mb-5 p-5">
        <div className="flex items-center gap-2 text-sm font-bold">
          <Terminal size={16} className="text-violet-300" />
          Add a new agent
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-2">
          <div>
            <label className="mb-2 block text-xs font-semibold text-slate-400">
              Server IP
            </label>

            <input
              type="text"
              value={serverIp}
              onChange={(event) => setServerIp(event.target.value)}
              placeholder="172.20.10.2"
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-slate-200 outline-none transition focus:border-violet-400"
            />

            <p className="mt-1.5 text-[11px] text-slate-500">
              IP address of the NetSentry Ubuntu server.
            </p>
          </div>

          <div>
            <label className="mb-2 block text-xs font-semibold text-slate-400">
              Network Interface
            </label>

            <input
              type="text"
              value={networkInterface}
              onChange={(event) =>
                setNetworkInterface(event.target.value)
              }
              placeholder="5"
              className="w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2.5 text-sm text-slate-200 outline-none transition focus:border-violet-400"
            />

            <p className="mt-1.5 text-[11px] text-slate-500">
              Example: Wi-Fi may be interface 5.
            </p>
          </div>
        </div>

        <div className="mt-4 rounded-lg border border-slate-800 bg-slate-900/50 p-3">
          <div className="flex items-start gap-2">
            <Info
              size={15}
              className="mt-0.5 shrink-0 text-violet-300"
            />

            <div className="text-xs leading-5 text-slate-400">
              <span className="font-semibold text-slate-200">
                Find the interface on Windows:
              </span>

              <div className="mt-2 rounded-md bg-black/30 px-3 py-2 font-mono text-[11px] text-slate-300">
                &quot;C:\Program Files\Wireshark\dumpcap.exe&quot; -D
              </div>

              <p className="mt-2">
                Find the Wi-Fi or Ethernet interface you want to
                monitor, then enter its number above.
              </p>
            </div>
          </div>
        </div>

        <div className="mt-5 flex flex-wrap items-center gap-3">
          <button
            onClick={downloadAgent}
            className="flex items-center gap-2 rounded-lg bg-violet-500 px-4 py-2.5 text-xs font-bold text-white transition hover:bg-violet-400"
          >
            <Download size={14} />
            Download client_agent.py
          </button>

          <span className="text-[11px] text-slate-500">
            Generates the agent using your settings.
          </span>
        </div>
      </Surface>

      <Surface className="mb-5 p-5">
        <div className="flex items-center gap-2 text-sm font-bold">
          <Terminal size={16} className="text-violet-300" />
          Setup — 3 steps
        </div>

        <ol className="mt-4 space-y-4 text-sm text-slate-300">
          <li>
            <div className="font-semibold text-slate-100">
              1. Install Wireshark + Npcap
            </div>

            <p className="mt-1 text-xs leading-5 text-slate-500">
              The agent uses Wireshark&apos;s dumpcap.exe to capture
              network traffic.
            </p>
          </li>

          <li>
            <div className="font-semibold text-slate-100">
              2. Install Python + requests
            </div>

            <div className="mt-2 inline-block rounded-md bg-slate-800 px-3 py-2 font-mono text-xs text-slate-300">
              pip install requests
            </div>
          </li>

          <li>
            <div className="font-semibold text-slate-100">
              3. Run the downloaded agent
            </div>

            <div className="mt-2 inline-block rounded-md bg-slate-800 px-3 py-2 font-mono text-xs text-slate-300">
              python client_agent.py
            </div>
          </li>
        </ol>
      </Surface>

      <Surface className="p-5">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <div>
            <div className="text-sm font-bold">
              Generated client_agent.py
            </div>

            <div className="mt-1 text-[11px] text-slate-500">
              Server: {serverIp || DEFAULT_SERVER}
              {' · '}
              Interface: {networkInterface || '5'}
              {' · '}
              Rotation: 30s
            </div>
          </div>

          <button
            onClick={downloadAgent}
            className="flex items-center gap-1.5 rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold text-slate-300 hover:bg-slate-800"
          >
            <Download size={13} />
            Download .py
          </button>
        </div>

        <CopyBlock code={agentScript} />
      </Surface>
    </div>
  );
}
