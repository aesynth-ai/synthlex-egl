# Synthlex-EGL

> WARNING: **Safety Notice**
> This project governs **execution authority**. Do **not** run it with real credentials, production accounts, or exposed network bindings.
> Default posture is **local, loopback-only, sandbox identity**.

**Synthlex-EGL** is the execution governance layer for the Synthlex ecosystem.

It exists to keep **tool calling** separate from **tool execution**, and to make execution:
- **explicit**
- **permit-bound**
- **policy-version bound**
- **replayable**
- **auditable**
- **safe by default**

This repo is designed for **controlled environments** (e.g., ClawLab) where we observe and map autonomous/agentic behavior under constrained execution.

## What this is

- A governance and enforcement layer between:
  - **reasoning / planning** (LLM + router)
  - and **side effects** (filesystem, network, external APIs)
- A home for:
  - execution surface maps
  - policy bundles (the "law")
  - permits / allowlists
  - receipts / traces
  - harness tests + goldens (replay proofs)

## What this isn't

- Not an agent framework.
- Not a hosted service.
- Not a general-purpose automation toolkit.
- Not safe to run with real credentials "just to see what happens."

## Safety posture (non-negotiable)

**Never attach production credentials.**  
Operate with:
- **loopback-only** networking
- **sandbox identity**
- dedicated **workspace root**
- explicit allowlists
- strict permit boundaries

If an invariant is violated: stop, preserve raw artifacts, classify.

## Quickstart (minimal)

1) Create local secrets (never commit):
- Copy `.env.example` -> `.env` and fill only sandbox keys.
- `.env` is ignored by git.

2) Confirm containment:
- bind to `127.0.0.1` / `localhost`
- use a dedicated workspace directory (single known root)

3) Run in observation-first mode:
- map tool surfaces and payload grammar
- enable permits only for controlled execution

Runtime is Node-first (`.mjs` / ESM). No Python harness in this repo.

## License

Apache-2.0 -- see `LICENSE`.

## Security

See `SECURITY.md` for reporting and safe operating rules.
