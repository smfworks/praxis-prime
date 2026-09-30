# Compliance packs

TOML starter policy loaded by the kernel. Not legal advice.

These files ship in the wheel as package data (`praxis_prime/_data/packs/compliance`) and load through `importlib.resources`. A source checkout still reads this directory.

User files in `~/.config/praxis-prime/packs` and project files in `.prime/packs` replace a bundled pack with the same `id`.

Vertical packs in the old `pack.json` format are a separate loader. See `docs/PACKS-LEGACY.md`. Do not copy those repositories into this tree.
