# Web UI

React 19, Vite, TypeScript, Tailwind, and TanStack Query (ARCHITECTURE §21 and §23).

`npm run build` writes `ui/dist`. `praxis-primed` serves that directory on loopback. The install does not need Node: the built files are in the wheel. There is no CDN, font host, or analytics call.

Hash routes (`#/chat`, `#/approvals`, `#/settings`, `#/security`) keep the daemon's route allowlist to `/` and `/assets/*`. Settings → Appearance swaps a theme stylesheet (`<link id="pp-theme">`). Colours and type come from `--pp-*` tokens.

OIDC sign-in, link, and unlink call the loopback `/v1/auth/oidc/*` routes from this SPA.

The Tauri shell in `apps/desktop` is still a stub.
