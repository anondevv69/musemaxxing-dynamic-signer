# musemaxxing-dynamic-signer

Minimal signing sidecar for musemaxxing agent wallets (Dynamic embedded EVM wallets, MPC-TSS).

- `POST /sign` — signs a Robinhood Chain (4663) transaction with the agent's Dynamic wallet via the official `@dynamic-labs-wallet/node-evm` SDK. Never broadcasts; returns the signed raw tx + hash.
- `GET /health` — liveness.

Env: `SIDECAR_TOKEN` (required, bearer auth), `PORT`, `SIDECAR_HOST`,
`DYNAMIC_ENVIRONMENT_ID`, `ALLOW_TEST_SIGNING` (test only, default false).

The FastAPI backend (which holds the Dynamic credential) fetches a short-lived
WaaS JWT + full wallet metadata and calls this service. Raw private keys never
exist anywhere in this pipeline.
