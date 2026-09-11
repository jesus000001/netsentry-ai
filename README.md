# NetSentry AI

NetSentry AI is a local cybersecurity workspace for triaging Snort alerts, reviewing raw detection logs, generating local threat insights, and managing monitored machines.

## Quick start on Ubuntu

The app uses PostgreSQL, Node.js, pnpm, a local API server, and a local Vite frontend. Follow the complete setup in [`docs/ubuntu-local.md`](docs/ubuntu-local.md).

## Development commands

```bash
pnpm install
pnpm --filter @workspace/db run push
pnpm --filter @workspace/api-server run dev
# in a second terminal:
PORT=5173 BASE_PATH=/ pnpm --filter @workspace/netsentry-ai run dev
```

Open `http://localhost:5173`.

The API seeds a small set of representative alerts and machines on the first request. The built-in analyzer is deterministic and runs locally, so the workspace does not need an API key or cloud provider to function.