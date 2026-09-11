# Run NetSentry AI on a local Ubuntu server

This is the local deployment path for a fresh Ubuntu 22.04/24.04 server.

## 1. Install prerequisites

```bash
sudo apt update
sudo apt install -y git curl postgresql postgresql-contrib
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt install -y nodejs
sudo corepack enable
corepack prepare pnpm@10.14.0 --activate
```

Check the tools:

```bash
node --version
pnpm --version
psql --version
```

## 2. Create a local PostgreSQL database

```bash
sudo -u postgres psql
```

In the PostgreSQL prompt:

```sql
CREATE USER netsentry WITH PASSWORD 'change-this-local-password';
CREATE DATABASE netsentry OWNER netsentry;
\q
```

From the project root, configure the connection for the current shell:

```bash
export DATABASE_URL='postgresql://netsentry:change-this-local-password@127.0.0.1:5432/netsentry'
```

For a permanent server setup, put the same variable in the service manager environment instead of committing it to the repository.

## 3. Install and create the tables

```bash
pnpm install
pnpm --filter @workspace/db run push
```

## 4. Start the two local services

Terminal 1, API:

```bash
export DATABASE_URL='postgresql://netsentry:change-this-local-password@127.0.0.1:5432/netsentry'
PORT=8080 pnpm --filter @workspace/api-server run dev
```

Terminal 2, web:

```bash
PORT=5173 BASE_PATH=/ pnpm --filter @workspace/netsentry-ai run dev
```

Open `http://SERVER_IP:5173` from your browser. The Vite server proxies `/api` requests to the API on port `8080`, so no browser-side API URL configuration is needed.

## 5. Verify the local services

```bash
curl http://127.0.0.1:8080/api/healthz
curl http://127.0.0.1:8080/api/dashboard/summary
```

The first dashboard request seeds five sample Snort alerts, one local insight, and three monitored machines if the database is empty.

## Production process manager

For a persistent server, run the API and web commands above under `systemd`, `supervisord`, or another process manager. Keep the database password in that manager's environment file. If the server is exposed outside the LAN, place the web service behind HTTPS and restrict PostgreSQL to localhost or the private network.