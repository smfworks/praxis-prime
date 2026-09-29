# prime-core

Python distribution `praxis-prime`, import package `praxis_prime`.

The Hatchling build maps `packages/prime-core/` onto the wheel root, so imports stay `praxis_prime`. Console scripts declared on this distribution:

- `praxis-prime`
- `pprime` (alias)
- `praxis-primed` (daemon stub)

The running kernel lives here: `loop/`, `router/`, `policy/`, `approvals/`, `tools/`, `sandbox/`, `memory/`, and `audit/`. FastAPI and Pydantic stay out until the gateway needs them (ARCHITECTURE §23 and §24).
