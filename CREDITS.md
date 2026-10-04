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
- Delete the EXAMPLE row once you add your first real entry.
-->

| Source (name, handle) | Link | License | What we used | Where it lives here | Commit / version |
|---|---|---|---|---|---|
| Contributor Covenant | https://www.contributor-covenant.org/version/2/1/code_of_conduct.html | CC-BY-4.0 | Code of Conduct text, version 2.1 | `CODE_OF_CONDUCT.md` | 2.1 |
| Mozilla | https://github.com/mozilla/diversity | unknown | Community Impact Guidelines, which the adapted code of conduct says were inspired by Mozilla's enforcement ladder | `CODE_OF_CONDUCT.md` | unknown |

Python packages and runtime programs are installed or invoked, not copied into
this tree. Their notices are in [THIRD_PARTY.md](THIRD_PARTY.md).
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) is the blueprint's name for
that inventory. The web app's build dependencies are declared in
`ui/package.json`; `ui/dist` is the build output, not vendored source.
No upstream source file is copied in (the copied-file log in THIRD_PARTY.md is
empty), and no OFL font is bundled.
