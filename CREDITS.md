# Credits

This project builds on other people's generous work. Everything we've reused or
adapted is listed here so the people behind it get the credit they deserve.
Thank you!

<!--
How to add an entry (people and agents alike):
- Add one row per source. Keep the rows that are already here; don't reword them.
- Source: the author's or project's name, plus their handle (e.g. @someone).
- License: an SPDX ID if you know it (MIT, Apache-2.0, BSD-3-Clause, ...).
  Copyleft or unknown license? Don't import it. Ask Michael first.
- Where it lives: the file or folder in this repo, in backticks.
- Commit / version: a tag, release or full commit SHA if you know it. Otherwise
  write "unknown". Never guess a SHA.
-->

| Source (name, handle) | Link | License | What we used | Where it lives here | Commit / version |
|---|---|---|---|---|---|
| Contributor Covenant | https://www.contributor-covenant.org/version/2/1/code_of_conduct.html | CC-BY-4.0 | Code of Conduct text, version 2.1 | `CODE_OF_CONDUCT.md` | 2.1 |
| Mozilla | https://github.com/mozilla/diversity | unknown | Community Impact Guidelines, which the adapted code of conduct says were inspired by Mozilla's enforcement ladder | `CODE_OF_CONDUCT.md` | unknown |
| Cinzel Project Authors (Cinzel), via google/fonts | https://github.com/google/fonts/tree/main/ofl/cinzel | OFL-1.1 | Cinzel display font, subset WOFF2 | `packages/prime-core/praxis_prime/ui_themes/smf.praxis/assets/fonts/Cinzel.woff2`, OFL text in `packages/prime-core/praxis_prime/ui_themes/smf.praxis/assets/fonts/OFL.txt` | unknown (retrieved 2026-10) |
| Inter Project Authors (Inter, @rsms), via google/fonts | https://github.com/google/fonts/tree/main/ofl/inter | OFL-1.1 | Inter UI font, subset WOFF2 | `packages/prime-core/praxis_prime/ui_themes/smf.praxis/assets/fonts/Inter.woff2` | unknown (retrieved 2026-10) |
| JetBrains Mono Project Authors (JetBrains), via google/fonts | https://github.com/google/fonts/tree/main/ofl/jetbrainsmono | OFL-1.1 | JetBrains Mono monospace font, subset WOFF2 | `packages/prime-core/praxis_prime/ui_themes/smf.praxis/assets/fonts/JetBrainsMono.woff2`, `packages/prime-core/praxis_prime/ui_themes/smf.high-contrast/assets/fonts/JetBrainsMono.woff2` | unknown (retrieved 2026-10) |
| Braille Institute of America (Atkinson Hyperlegible), via google/fonts | https://github.com/google/fonts/tree/main/ofl/atkinsonhyperlegible | OFL-1.1 | Atkinson Hyperlegible regular and bold, subset WOFF2 | `packages/prime-core/praxis_prime/ui_themes/smf.high-contrast/assets/fonts/AtkinsonHyperlegible-Regular.woff2`, `packages/prime-core/praxis_prime/ui_themes/smf.high-contrast/assets/fonts/AtkinsonHyperlegible-Bold.woff2`, OFL text in `packages/prime-core/praxis_prime/ui_themes/smf.high-contrast/assets/fonts/OFL.txt` | unknown (retrieved 2026-10) |

Python packages and runtime programs are installed or invoked, not copied into
this tree. Their notices are in [THIRD_PARTY.md](THIRD_PARTY.md).
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) is the blueprint's name for
that inventory. The web app's build dependencies are declared in
`ui/package.json`; `ui/dist` is the build output, not vendored source.
Design credits for Hermes Agent, OpenClaw, Omarchy and SMF Swarm are in
[NOTICE](NOTICE).
No upstream source code is copied in. The only copied files are the bundled
OFL-1.1 fonts listed above, logged in THIRD_PARTY.md's copied-file log with the
OFL text kept beside them in each theme's `assets/fonts/OFL.txt`.
