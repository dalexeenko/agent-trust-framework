# Agent Trust Framework

A simple purpose-based authorization gateway for AI agents, designed around Google Cloud's
agentic security controls.

An agent declares a purpose and bounded blast radius. A human approves that purpose once.
The agent can then exchange its identity for one opaque, short-lived handle. The handle is
re-authorized for every action; Google credentials are injected only inside the gateway.

## What the MVP includes

- Per-agent identities (local API key now, SPIFFE ID field for Google Agent Identity)
- Structured task declarations: purpose, capabilities, resources, TTL, action budget, data rules
- Deterministic blast-radius risk scoring with explainable factors
- Human approval inbox and minimal React dashboard
- Opaque, one-time-issued, short-lived credential handles stored only as SHA-256 hashes
- Per-action authorization and local guardrail checks
- Optional Google Model Armor pre-execution adapter
- Live Vertex AI `generateContent` execution through server-side Application Default Credentials
- A2A Agent Card and a Google governance-control inventory endpoint
- Hash-chained, append-only SQLite audit events

This is a prototype, not a production security boundary. In particular, local API keys and static
review tokens are development authentication, the SQLite audit chain is not externally anchored,
and the local guardrail fallback is not a replacement for Model Armor.

## Architecture

```text
AI agent
  │  1. Authenticate and declare a purpose
  ▼
Gateway API ──► Risk engine ──► Human approval dashboard
  │                                  │
  │  2. Issue an opaque,             │ approve / deny
  │     short-lived handle           │
  ▼                                  │
Policy engine ◄───────────────────────┘
  │  3. Check capability, resource, TTL, budget, and guardrails
  ▼
Google executor ──► Model Armor / Vertex AI / Agent services
  │
  └──► Hash-chained audit ledger
```

The model and agent runtime are treated as untrusted. They can request actions but cannot select
credentials, OAuth scopes, or arbitrary upstream URLs. The gateway stores only hashes of agent
keys and handles, re-authorizes every action against the approved task envelope, and acquires
Google credentials through server-side Application Default Credentials.

The repository is a TypeScript workspace:

- `packages/core` — task schemas, deterministic risk scoring, and authorization policy
- `apps/server` — Fastify API, SQLite state, Google adapters, guardrails, and audit chain
- `apps/web` — React approval and audit dashboard
- `docs` — Google Cloud security model and production roadmap

## Run it

Requires Node.js 22 or newer.

```bash
npm install
npm run build
npm run dev
```

In another terminal:

```bash
npm run dev:web
```

Open `http://localhost:5173`. Development defaults are `dev-bootstrap` and `dev-approve`.
Set every value in `.env.example` before exposing the service beyond localhost.

## Try the complete flow

Register a development agent:

```bash
curl -s http://127.0.0.1:8787/v1/agents \
  -H 'content-type: application/json' \
  -H 'x-bootstrap-token: dev-bootstrap' \
  -d '{"name":"support-agent"}'
```

Keep the returned `apiKey`, then declare a task:

```bash
curl -s http://127.0.0.1:8787/v1/tasks \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer AGENT_API_KEY' \
  -d '{
    "purpose":"Summarize approved support records for the weekly operations review",
    "capabilities":["google.agentspace.search"],
    "resources":["projects/demo/locations/global/collections/support"],
    "expiresInSeconds":600,
    "constraints":{
      "maxCalls":5,
      "allowExternalCommunication":false,
      "allowSensitiveData":false,
      "requireModelArmor":true
    }
  }'
```

Approve the task in the dashboard, then exchange the approved task for its handle:

```bash
curl -s -X POST http://127.0.0.1:8787/v1/tasks/TASK_ID/handle \
  -H 'authorization: Bearer AGENT_API_KEY'
```

Exercise authorization without calling Google:

```bash
curl -s http://127.0.0.1:8787/v1/gateway/execute \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer ATF_HANDLE' \
  -d '{
    "capability":"google.agentspace.search",
    "resource":"projects/demo/locations/global/collections/support",
    "operation":"search",
    "input":{"query":"open cases"},
    "dryRun":true
  }'
```

## API surface

- `POST /v1/agents` — register an agent with the bootstrap control token
- `POST /v1/tasks` — declare a purpose as an authenticated agent
- `GET /v1/tasks/:id` — poll task status
- `POST /v1/tasks/:id/handle` — issue the approved handle once
- `GET /v1/review/tasks` — list purposes for a human reviewer
- `POST /v1/review/tasks/:id/decision` — approve or deny a purpose
- `POST /v1/gateway/execute` — authorize, screen, inject credentials, execute, audit
- `GET /v1/review/audit` — replay the decision ledger
- `GET /.well-known/agent-card.json` — A2A discovery metadata
- `GET /v1/governance/google-controls` — implementation-to-Google-control map

See [docs/GOOGLE-SECURITY-MODEL.md](docs/GOOGLE-SECURITY-MODEL.md) for the trust model and
production roadmap.
