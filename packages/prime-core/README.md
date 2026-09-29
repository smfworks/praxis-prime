# prime-core

Python distribution `praxis-prime`, import package `praxis_prime`.

The Hatchling build maps `packages/prime-core/` onto the wheel root, so imports stay `praxis_prime`. Console scripts declared on this distribution:

- `praxis-prime`
- `pprime` (alias)
- `praxis-primed` (daemon stub)

TODO: ARCHITECTURE §23 and §24. Runtime dependencies (FastAPI, Pydantic, and the rest) are intentionally absent until the kernel needs them.
