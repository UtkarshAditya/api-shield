# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

APIShield is a self-hosted security gateway with three parts: Scan, Protect and Learn. Its users are small dev teams, and hackathon judges watching a demo. The backend has four owners:
- **M1:** Gateway / Protection
- **M2:** Scanner / Risk
- **M3:** Learning / Alerts
- **M4:** Platform / UI / QA

Each team member builds their part in parallel. In the repo so far:
- `gateway/` (M1) and `scanner/` (M2).
- `admin_api/` (M4): FastAPI, the only service the dashboard talks to. See `admin_api/README.md`.
- `frontend/`: the dashboard. It runs against an in-browser mock of the Admin API (`VITE_USE_MOCKS=true`) or the real one.
- `demo_api/`: the vulnerable demo target.

- `learning/` (M3): the learner. `python -m apishield_learning` (live mode, `live.py`) writes alerts and learning progress into the Admin database (`alerts`, `learning_state`, `alert_feedback`, its own `learner_baselines`). `ADMIN_DEMO_ALERTS=true` is the replay fallback (see `docs/DEMO.md`).

**User preference:** do not run git commands in this repo.

## Commands

**Python (repo root).** The venv is `.venv` (Python 3.13; 3.15 is also installed but too new for some wheels).

```bash
.venv/Scripts/python -m pytest admin_api/tests     # Admin API (also gateway/tests, scanner/tests)
.venv/Scripts/python -m admin_api                  # :8000, API under /api
python scripts/simulate_traffic.py                 # demo traffic + attack burst through the gateway
python scripts/demo_check.py                       # whole demo flow against a running stack, PASS/FAIL per step
python scripts/demo_reset.py                       # back to the demo's starting state (needs DEMO_SEED=true)
python scripts/demo_warmup.py                      # normal traffic until the learner reports active
docker compose up --build                          # whole stack (cp .env.example .env first)
```

Running `pytest admin_api/tests` also regenerates `frontend/src/test/contract/samples/`. The frontend contract test parses those samples with the Zod schemas.
A plain `pytest` from the repo root runs every package's tests (the root `conftest.py` puts `learning/` on the path). The learning tests need `pip install -r learning/requirements.txt`.

The demo runbook is `docs/DEMO.md`.

**Frontend.** Run these from `frontend/`. Use npm; pnpm is not installed.

```bash
npm run dev                           # Vite dev server on :5173, with MSW mocks
npm run build                         # tsc -b && vite build -> dist/ (static files, served behind the Admin API)
npm run typecheck                     # tsc only
npm test                              # vitest run (all)
npx vitest run src/test/core.test.tsx # single file
npx vitest run -t "roles"             # single test by name
VITE_API_BASE=http://localhost:8000/api npx vitest run src/test/live.test.tsx   # every screen against a running Admin API
```

Screen tests use `src/test/renderScreen.tsx`, which runs the MSW handlers in Node and resets the mock store before each test.

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
- Every sidebar route is a real screen under `features/<name>/`. Shared dialogs (`Modal`, `ConfirmDialog`, `Sheet`) are in `components/ui/Dialog.tsx`; use `describeError()` (`lib/errors.ts`) for error text.

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
