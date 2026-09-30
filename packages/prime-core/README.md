# prime-core

Python distribution `praxis-prime`, import package `praxis_prime`.

The Hatchling build maps `packages/prime-core/` onto the wheel root, so imports stay `praxis_prime`. Console scripts declared on this distribution:

- `praxis-prime`
- `pprime` (alias)
- `praxis-primed` (loopback daemon)

The running kernel lives here: `loop/`, `router/`, `policy/`, `approvals/`, `tools/`, `sandbox/`, `memory/`, `audit/`, `gateway/`, and `channels/`. The gateway is stdlib HTTP and WebSocket. FastAPI and Pydantic stay out (ARCHITECTURE §23 and §24).
