# Regulated packs

This directory stays empty of pack code. The six public MIT verticals
(legal, medical, behavioral health, education, homeschool, forensic) live in
`smfworks/smf-praxis-*` and are installed with `praxis-prime packs install`.
The loader reads `pack.json` and `knowledge.md` only. It does not vendor the
repositories, import their Python, or serve their dashboard JavaScript.
See `docs/PACKS-LEGACY.md`.

Compliance dial TOML still loads from `packs/compliance`,
`~/.config/praxis-prime/packs`, and `.prime/packs`.

This directory is reserved for a future in-tree copy of the Praxis regulated verticals:

- legal and law firm
- medical and medical office
- behavioral health
- school system
- homeschool
- forensic

**Their code is not copied into this directory.** The public MIT repositories are installed by `praxis_prime.packs` as data. Any additional private tree still needs a license check before it is copied here (ARCHITECTURE §32).

Before copying a pack into this directory:

1. Confirm the current LICENSE and that SMF Works holds the contributor rights (ARCHITECTURE §32).
2. Remember that copies released under MIT before 0.29.0 stay MIT for the people who received them.
3. Keep third-party text (statutes, forms, datasets) under its own terms.
4. Keep the core on the data loader. Do not import pack Python from this tree.
5. Update `THIRD_PARTY.md` and this directory's README in the same change.

The `LICENSE` file here covers the placeholder files only. It is MIT, copyright (c) 2026 SMF Works, matching the recommended default (option A in §32). If the imported packs use a different license, replace that file at import time. The Debian/AUR package name reserved for them is `praxis-prime-packs`.

Nothing in this directory enables a compliance dial. Dials default to off.
