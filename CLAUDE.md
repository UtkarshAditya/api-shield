# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

APIShield is a self-hosted security gateway with three parts: Scan, Protect and Learn. Its users are small dev teams, and hackathon judges watching a demo. The backend has four owners:
- **M1:** Gateway / Protection
- **M2:** Scanner / Risk
- **M3:** Learning / Alerts
- **M4:** Platform / UI / QA

Each team member builds their part in parallel. Only the dashboard exists in this repo so far, in `frontend/`. It runs entirely against an in-browser mock of the Admin API until the real backend lands.

**User preference:** do not run git commands in this repo.

## Commands

Run everything from `frontend/`. Use npm; pnpm is not installed.

```bash
npm run dev                           # Vite dev server on :5173, with MSW mocks
npm run build                         # tsc -b && vite build -> dist/ (static files, served behind the Admin API)
npm run typecheck                     # tsc only
npm test                              # vitest run (all)
npx vitest run src/test/core.test.tsx # single file
npx vitest run -t "roles"             # single test by name
```

- **Demo logins:** `admin@demo.local`, `analyst@demo.local` and `viewer@demo.local`, all with the password `demo`. These only work in mock mode.
- **Vitest config:** lives in `vitest.config.ts`, separate from `vite.config.ts`. Vitest 2 types clash with Vite 6, so keep them apart.

## Architecture (frontend)

**Data flow.** A call goes through four layers:
1. `api/client.ts` is the *only* HTTP code. It attaches the JWT and parses every response with a Zod schema. A response that doesn't match throws `ContractError`, which names the offending field.
2. `api/schemas.ts` holds the Zod schemas and is the frontend's source of truth for the data contracts. Every TS type is `z.infer` of a schema.
3. `api/endpoints.ts` holds the typed calls.
4. `api/queries.ts` wraps them as TanStack Query hooks. Query keys include `upstreamId` and `range`, so switching upstream refetches everything.

**Contract assumptions.** Shapes the brief didn't specify are marked `// CONTRACT-TBD` in `schemas.ts` and listed in `frontend/CONTRACT_QUESTIONS.md`. When the backend confirms a shape, change `schemas.ts` and `endpoints.ts`, plus the matching mock.

**Mocks.**
- `main.tsx` starts the MSW worker only when `VITE_USE_MOCKS=true` (set in `.env`). For the real backend, set it to false and point `VITE_API_BASE` at the Admin API.
- `mocks/seed.ts` holds the deterministic demo-story data: the vulnerable "Demo Shop API", findings for `/search` SQL injection and `/login` with no rate limit, and a ranked alert burst.
- `mocks/db.ts` is a mutable in-memory store plus generators for the time series and summary. Writes persist for the session.
- `mocks/handlers.ts` holds the MSW routes.
- A unit test asserts that the mock output parses against the schemas. Keep the mocks contract-valid.

**Contexts and provider order.**
- `app/providers.tsx` nests the providers: QueryClient > Theme > Radix Tooltip > Auth.
- `WorkspaceProvider` holds the selected upstream. It lives inside `components/layout/AppShell.tsx`, not at the root, because it fetches `/upstreams`, which needs auth.
- `auth/roles.ts` maps each role (admin, analyst, viewer) to permissions via `can()`. Gate UI actions with `useAuth().can(...)`.

**Routing.**
- `app/router.tsx` lazy-loads every route.
- Public routes are `/` (landing) and `/login`.
- `/app/*` sits behind `RequireAuth` and then `AppShell`.
- Screens that aren't built yet are stubs in `features/placeholders.tsx`.

**Landing page** (`features/landing/`). It is a scroll-scrubbed GSAP ScrollTrigger story over a layered SVG vault door.
- `story.ts` holds the copy and each chapter's start position.
- `VaultStage.tsx` holds the artwork, in four layers: back SVG, door SVG in its own div so CSS 3D can swing it open, overlay SVG, and HTML labels. Its elements carry `v-*` class names, which the timeline targets.
- `useVaultTimeline.ts` holds one master timeline, 100 units long, so positions read as percent of the story. It is pinned with `end: "+=650%"`.
- The default SVG markup is the calm, locked state. The timeline `gsap.set`s the starting state, and the reduced-motion `StaticStory` renders the markup as-is.
- A nav toggle overrides `prefers-reduced-motion`, using the localStorage key `apishield.landingMotion`.
- The landing page always renders dark: it applies a `dark` class on its wrapper.

**Theming.**
- `theme/tokens.css` defines semantic CSS variables on `:root` and on `.dark`, and maps them into Tailwind v4 through `@theme inline`. Examples: `bg-surface`, `text-muted`, `text-sev-critical`, `bg-act-block`.
- Use the tokens, not raw colors.
- The chart colors `--chart-allowed` and `--chart-blocked` were validated separately for light and dark.

## UI rules from the brief

- **Severity:** always show color + icon + text via `SeverityBadge`, never color alone.
- **Explanations:** every score, block or alert gets a "why" affordance (`WhyTooltip`) written in plain English.
- **Privacy:** never render raw payload values, tokens or PII. Values arrive pre-masked; show them with `MaskedValue` and `CallerId`. Copy should reinforce "shapes, not contents".
- **Confirmations:** switching to ENFORCE, purging data and starting a scan all need confirmation. Scans also need an explicit consent checkbox.
- **Self-hosting:** no runtime CDNs or external fonts. Fonts come from `@fontsource`, and everything else is bundled from npm.
- **Accessibility:** target WCAG 2.1 AA and full keyboard navigation. Desktop-first, responsive down to tablet.

## Roadmap

1. **Week 1 (done):** shell, mocks, landing page, login, Overview.
2. **Week 2:** Live Traffic (virtualized table, SSE with a polling fallback), Rules (editor, YAML view, rule tester), API map.
3. **Week 3:** Alerts (feedback shows "threshold adjusted"), Scans (wizard, findings, apply suggested rule, export), Learning.
4. **Week 4:** Settings & Privacy, audit log, a Demo-mode replay of the storyline, Playwright tests of the demo flow.
