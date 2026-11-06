# APIShield dashboard

The React + Vite + TypeScript frontend for APIShield. It runs entirely against an in-browser mock Admin API (MSW) until the backend is ready.

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173
```

**Demo logins** all use the password `demo`: `admin@demo.local`, `analyst@demo.local`, `viewer@demo.local`.

## Scripts
| | |
|---|---|
| `npm run dev` | Dev server with mocks |
| `npm run build` | Typecheck and production build to `dist/` (static files to serve behind the Admin API) |
| `npm run typecheck` | `tsc` only |
| `npm test` | Vitest unit tests |

## Switching to the real backend
Edit `.env`:
```
VITE_USE_MOCKS=false
VITE_API_BASE=/api        # or http://localhost:8000
```
All HTTP calls go through `src/api/client.ts`, and every response is validated against the Zod schemas in `src/api/schemas.ts`. If the backend drifts from the contract, the browser console shows a `ContractError` naming the field. Open questions for the backend owners are listed in `CONTRACT_QUESTIONS.md`.

## Layout
```
src/
  api/          client.ts (only fetch wrapper) · schemas.ts (contracts) · endpoints.ts · queries.ts (TanStack Query hooks)
  mocks/        seed.ts (demo story data) · db.ts (in-memory store + generators) · handlers.ts (MSW)
  auth/         AuthContext, RequireAuth, roles.ts (admin / analyst / viewer → can())
  theme/        tokens.css (design tokens, light + dark) · ThemeProvider
  components/   ui/ (primitives) · domain/ (SeverityBadge, KpiCard, RiskGauge, MaskedValue…) · layout/ (AppShell)
  features/     landing/ (vault scroll story) · auth/ · overview/ · placeholders for weeks 2–4
```

## Landing page
`features/landing/` tells the product story as a scroll-scrubbed GSAP timeline over a layered SVG vault:
**scan** (a lockpick and a scanner beam find weak spots) → **protect** (rules applied, the bolts lock) → **rate limit** (a flood of keys gets throttled) → **learn** (an unfamiliar payload *shape* raises a ranked alert) → **open** (the right key opens the door).

- `story.ts` holds the copy.
- `VaultStage.tsx` holds the artwork.
- `useVaultTimeline.ts` holds the choreography. Positions are 0–100, so they read as percent of the story.

Visitors with `prefers-reduced-motion` get a static version. The "Play story" / "Reduce motion" button in the nav overrides the OS setting.

## Conventions
- Severity is always shown as color + icon + text (`SeverityBadge`).
- Every score or metric gets a "why" affordance (`WhyTooltip`).
- Never render raw payload values or secrets. Use `MaskedValue` / `CallerId`.
- No runtime CDNs: fonts are bundled via `@fontsource`, and GSAP and everything else come from npm.
