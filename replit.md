# NetSentry AI

NetSentry AI is a local-first cybersecurity workspace for Snort alert triage, threat insights, raw logs, traffic telemetry, and monitored machines.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `PORT=5173 BASE_PATH=/ pnpm --filter @workspace/netsentry-ai run dev` — run the frontend directly on Ubuntu
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string for the API server

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/netsentry-ai` — React/Vite security workspace
- `artifacts/api-server/src/routes/security.ts` — alerts, insights, machines, dashboard summary, and local analyzer
- `lib/db/src/schema/security.ts` — PostgreSQL schema
- `lib/api-spec/openapi.yaml` — API contract source of truth
- `docs/ubuntu-local.md` — local Ubuntu setup and process guidance

## Architecture decisions

- The analyzer is deterministic and local-first so the app works on an Ubuntu server without an external API key.
- The frontend uses the generated OpenAPI client and Vite `/api` proxy so direct local browser access works with separate API and web processes.
- Seed data is inserted only when the database is empty, keeping the first install useful without overwriting user data.

## Product

The workspace provides an overview dashboard, live traffic telemetry, Snort alert triage with inline analysis, raw log search, model status, insight review, and monitored machine CRUD.

## User preferences

The app should remain runnable locally on Ubuntu without requiring hosted auth, cloud storage, or user-provided AI credentials.

## Gotchas

- Run the database push before starting the API on a new machine.
- Keep the API on port 8080 when running the Vite proxy directly.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
