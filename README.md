# 🛡️ NetSentry AI

**NetSentry AI** is a local cybersecurity monitoring and response platform designed to detect, analyze, and respond to suspicious network activity.

It combines **Snort IDS**, a web dashboard, a Windows security agent, PostgreSQL, PCAP analysis, network discovery, and automated IP blocking into a single local security workspace.

---

## 🚀 Features

### 🔎 Intrusion Detection

NetSentry uses **Snort** to detect suspicious network activity, including:

* ICMP activity
* SSH brute-force attempts
* Nmap SYN scans
* Nmap NULL scans
* Nmap XMAS scans
* Custom Snort rules

Detected events are sent to the NetSentry backend and displayed in the dashboard.

### 🚫 Automatic Threat Response

NetSentry can automatically respond to selected high-risk detections.

Example workflow:

```text
Network Activity
      ↓
     Snort
      ↓
  Security Alert
      ↓
 NetSentry Backend
      ↓
Threat Detection
      ↓
Create BLOCK_IP command
      ↓
 Windows Agent
      ↓
Windows Firewall
      ↓
     IP Blocked
```

The Windows Agent receives commands from the NetSentry server and can create Windows Firewall rules to block malicious source IP addresses.

### 🤖 Windows Agent

The Windows Agent:

* Registers/polls with the NetSentry API
* Receives security commands
* Executes firewall actions
* Sends execution results back to the server
* Uploads PCAP files to the server

Example response:

```text
[COMMAND RECEIVED]

Action : BLOCK_IP
Target : 172.20.10.X

Result:
Firewall rule created
```

### 📡 PCAP Analysis

The agent can upload packet captures to the NetSentry PCAP receiver.

The server processes uploaded PCAP files through Snort for additional analysis.

```text
Windows Agent
      ↓
PCAP Receiver
      ↓
Snort
      ↓
Security Alerts
      ↓
NetSentry Dashboard
```

### 🌐 Network Scanner

NetSentry includes a network discovery script based on Nmap.

It periodically discovers machines on the monitored network and updates their information in the database.

Collected information can include:

* IP address
* Hostname
* Operating system
* Machine status

### 📊 Security Dashboard

The web interface provides a centralized view of the security environment.

It can display:

* Security alerts
* Monitored machines
* Alert severity
* Detection signatures
* Source and destination information
* Agent commands
* Command execution status

### 📧 Email Alerts

NetSentry supports SMTP-based security notifications.

Gmail SMTP can be configured using a Gmail App Password.

> Never commit `.env` files or SMTP credentials to GitHub.

---

# 🏗️ Architecture

```text
                    ┌──────────────────┐
                    │     Network      │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │      Snort       │
                    │       IDS        │
                    └────────┬─────────┘
                             │
                             ▼
                    ┌──────────────────┐
                    │    NetSentry     │
                    │   Backend API    │
                    └───────┬──────────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
        ┌──────────┐  ┌──────────┐  ┌────────────┐
        │PostgreSQL│  │ Dashboard│  │ Email SMTP │
        └──────────┘  └──────────┘  └────────────┘
                            │
                            ▼
                     ┌────────────┐
                     │Windows Agent│
                     └──────┬─────┘
                            │
                            ▼
                    ┌────────────────┐
                    │ Windows Firewall│
                    └────────────────┘
```

---

# 🧰 Technology Stack

| Component          | Technology        |
| ------------------ | ----------------- |
| IDS                | Snort             |
| Backend            | Node.js / Express |
| Frontend           | React / Vite      |
| Database           | PostgreSQL        |
| ORM                | Drizzle ORM       |
| Agent              | Python            |
| Network Scanner    | Nmap              |
| PCAP Processing    | Snort             |
| Email              | Nodemailer / SMTP |
| Remote Access      | Tailscale         |
| Service Management | systemd           |
| Package Manager    | pnpm              |

---

# 📁 Project Structure

```text
netsentry-ai/
│
├── artifacts/
│   ├── api-server/
│   │   └── src/
│   │
│   └── netsentry-ai/
│       └── src/
│
├── lib/
│   ├── api-client-react/
│   ├── api-zod/
│   └── db/
│
├── scripts/
│   ├── network_scanner.py
│   ├── pcap_receiver.py
│   └── snort_bridge.py
│
├── .gitignore
├── package.json
└── README.md
```

---

# ⚙️ Requirements

Recommended environment:

* Ubuntu Server
* Node.js
* pnpm
* PostgreSQL
* Python 3
* Snort
* Nmap
* Git

For Windows Agent:

* Windows
* Python 3
* Administrator privileges for firewall operations

---

# 🚀 Installation

Clone the repository:

```bash
git clone git@github.com:jesus000001/netsentry-ai.git
cd netsentry-ai
```

Install dependencies:

```bash
pnpm install
```

Configure PostgreSQL and create the NetSentry database.

Then configure the API environment:

```bash
cd artifacts/api-server
nano .env
```

Example configuration:

```env
PORT=8080
NODE_ENV=production

DATABASE_URL=postgresql://USER:PASSWORD@localhost:5432/netsentry

SMTP_HOST=smtp.gmail.com
SMTP_PORT=465
SMTP_SECURE=true
SMTP_USER=your-email@gmail.com
SMTP_PASS=YOUR_APP_PASSWORD
ALERT_EMAIL=your-email@gmail.com

AGENT_SHARED_SECRET=CHANGE_ME
NETSENTRY_SERVER_IP=YOUR_SERVER_IP
```

**Do not commit this file to GitHub.**

---

# 🧪 Development

Install dependencies:

```bash
pnpm install
```

Push the database schema:

```bash
pnpm --filter @workspace/db run push
```

Start the backend:

```bash
pnpm --filter @workspace/api-server run dev
```

Start the frontend in another terminal:

```bash
PORT=5173 BASE_PATH=/ pnpm --filter @workspace/netsentry-ai run dev
```

Then open:

```text
http://localhost:5173
```

---

# 🛠️ Production Services

NetSentry can run as systemd services.

Example services:

```text
netsentry-backend.service
netsentry-frontend.service
netsentry-bridge.service
netsentry-pcap-receiver.service
```

Check services:

```bash
systemctl list-units --type=service | grep -i netsentry
```

Check the backend:

```bash
sudo systemctl status netsentry-backend
```

View backend logs:

```bash
sudo journalctl -u netsentry-backend -f
```

---

# 🔐 Security

NetSentry is designed to operate inside a controlled network or cybersecurity lab.

Important security practices:

* Never commit `.env` files.
* Never expose API secrets publicly.
* Use strong agent authentication.
* Restrict access to the NetSentry API.
* Run firewall operations with appropriate privileges.
* Use TLS when traffic crosses an untrusted network.
* Use Tailscale or another secure private network for remote administration.

---

# 🧪 Detection & Response

Current automated response signatures include selected Snort detections such as:

```text
1:1000002:5  → SSH brute-force detection
1:1000004:1  → Nmap SYN scan
1:1000005:1  → Nmap NULL scan
1:1000006:1  → Nmap XMAS scan
```

For selected detections, NetSentry creates a `BLOCK_IP` command.

The command is delivered to the Windows Agent, which creates a Windows Firewall block rule.

---

# 📈 Roadmap

Planned improvements include:

* [ ] Incident correlation
* [ ] Risk scoring
* [ ] Threat Intelligence integration
* [ ] Shodan enrichment
* [ ] AbuseIPDB integration
* [ ] MITRE ATT&CK mapping
* [ ] Advanced PCAP analysis
* [ ] Network topology visualization
* [ ] Historical security analytics
* [ ] Real-time notifications
* [ ] Improved alert deduplication
* [ ] HTTPS/TLS for API communication
* [ ] Multi-agent management

---

# 🎯 Project Goal

The goal of NetSentry AI is to build a practical local security platform capable of:

```text
Detect
  ↓
Analyze
  ↓
Correlate
  ↓
Score
  ↓
Respond
  ↓
Monitor
```

Instead of only displaying security alerts, NetSentry aims to provide an automated **Detection → Analysis → Response** workflow.

---

# 📌 Project Status

NetSentry currently includes:

* ✅ Snort IDS integration
* ✅ PostgreSQL database
* ✅ Web security dashboard
* ✅ Network discovery
* ✅ PCAP receiver
* ✅ Windows security agent
* ✅ Automated IP blocking
* ✅ Agent command acknowledgment
* ✅ SMTP email notification support
* ✅ systemd services
* ✅ Tailscale support

---

# 👨‍💻 Author

**Youssef**

Cybersecurity / Network Security project.

---

## ⚠️ Disclaimer

NetSentry is intended for authorized networks, systems, and cybersecurity laboratories.

Only monitor or block systems that you own or have explicit permission to administer.

