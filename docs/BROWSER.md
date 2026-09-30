# Browser tool

The `browser` tool drives a headless Chromium through Playwright. Playwright is an optional extra and is not imported unless you install it:

```bash
python -m pip install "praxis-prime[browser]"
python -m playwright install chromium
```

`praxis-prime doctor` reports Playwright as a warning when the package is missing. That check does not fail the doctor. Chromium itself is a separate download and is not required in CI.

Without Playwright, `navigate`, `snapshot`, and `extract` fall back to the existing `web_fetch` tool (HTML stripped for snapshot and extract). `click`, `type`, `screenshot`, `submit`, `login`, `download`, and `purchase` return a clear error instead of pretending to drive a page.

## Actions

One tool, `browser`, with an `action` argument:

| Action | Effect |
|---|---|
| `navigate` | Open a URL |
| `snapshot` | Accessibility tree as text, or the visible text when the tree is empty |
| `click` | Click a selector |
| `type` | Type into a selector |
| `screenshot` | Save a PNG under the working directory |
| `extract` | Return visible text |
| `close` | Close the browser and drop a disposable profile |
| `submit` | Submit a form. Always asks |
| `login` | A login step. Always asks |
| `download` | Allow one download. Always asks |
| `purchase` | A payment step. Always asks |

Page content is untrusted data. The loop fences it the same way it fences other tool output.

## Profile

The default profile is a disposable directory created for the session and removed on close. It is not your signed-in browser profile.

```toml
[browser]
enabled = true
profile = "disposable"   # or "persistent"
allow_domains = []
deny_domains = []
```

`profile = "persistent"` stores state under `$XDG_DATA_HOME/praxis-prime/browser-profile` (or `~/.local/share/praxis-prime/browser-profile`). That directory is still separate from the user's Chrome or Chromium profile.

## Domains and approvals

`allow_domains` and `deny_domains` match the host exactly or as a suffix (`.example.com` matches `shop.example.com`). Deny wins. An empty allow list does not restrict hosts. Metadata addresses and non-http(s) URLs are rejected by the same check `web_fetch` uses.

These always ask, even when the domain is allowed:

- form submit, including a click whose selector looks like a submit control
- login, password, or OAuth pages and actions
- downloads (a navigation cannot save a file on its own)
- purchase, checkout, cart, or billing pages, and a purchase action
- typing a card-like number (13–19 digits). The approval summary redacts that text

A plain click is `DRAFT` and does not ask. Payment-like pages are `SPEND`. Login, submit, and download are `SEND`.
