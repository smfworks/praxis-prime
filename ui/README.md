# Web UI

React 19, Vite, TypeScript, Tailwind, and TanStack Query (ARCHITECTURE §21 and §23).

`npm run build` writes `ui/dist`. `praxis-primed` serves that directory on loopback. The install does not need Node: the built files are in the wheel. There is no CDN, font host, or analytics call.

Hash routes (`#/chat`, `#/approvals`, `#/security`) keep the daemon's route allowlist to `/` and `/assets/*`. Themes are M3. The CSS variables in `src/styles.css` are the hook for that later.

The Tauri shell in `apps/desktop` is still a stub.
