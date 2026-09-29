# Regulated packs

This directory is reserved for the Praxis regulated verticals:

- legal and law firm
- medical and medical office
- behavioral health
- school system
- homeschool
- forensic

**They are not imported.** SMF Praxis 0.29.0 moved them into private repositories. Those trees are not in this checkout, and this skeleton does not copy them.

Before any import:

1. Confirm the current LICENSE of each private repo and that SMF Works holds the contributor rights (ARCHITECTURE §32).
2. Remember that copies released under MIT before 0.29.0 stay MIT for the people who received them.
3. Keep third-party text (statutes, forms, datasets) under its own terms.
4. Load packs through the future `praxis_prime.packs` entry point. The core must not import pack code directly.
5. Update `THIRD_PARTY.md` and this directory's README in the same change.

The `LICENSE` file here covers the placeholder files only. It is MIT, copyright (c) 2026 SMF Works, matching the recommended default (option A in §32). If the imported packs use a different license, replace that file at import time. The Debian/AUR package name reserved for them is `praxis-prime-packs`.

Nothing in this directory enables a compliance dial. Dials default to off.
