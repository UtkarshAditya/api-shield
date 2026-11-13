/**
 * Opt-in: renders every dashboard screen against a RUNNING Admin API (no mocks). Every response
 * goes through the real Zod schemas, so contract drift fails here. Skipped unless VITE_API_BASE
 * is an absolute URL:
 *
 *   VITE_API_BASE=http://localhost:8000/api npx vitest run src/test/live.test.tsx
 *
 * It only reads: nothing is changed on the server.
 */
import { screen, waitFor } from "@testing-library/react";
import type { ReactElement } from "react";
import AlertsPage from "@/features/alerts/AlertsPage";
import InventoryPage from "@/features/inventory/InventoryPage";
import LearningPage from "@/features/learning/LearningPage";
import OverviewPage from "@/features/overview/OverviewPage";
import RulesPage from "@/features/rules/RulesPage";
import ScansPage from "@/features/scans/ScansPage";
import SettingsPage from "@/features/settings/SettingsPage";
import TrafficPage from "@/features/traffic/TrafficPage";
import { ModeControl } from "@/components/domain/ModeControl";
import { renderScreen } from "./renderScreen";

const base = import.meta.env.VITE_API_BASE ?? "";
const live = /^https?:\/\//.test(base);

async function token(email = "admin@demo.local") {
  const res = await fetch(`${base}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password: "demo" }),
  });
  if (!res.ok) throw new Error(`login failed: ${res.status}`);
  return ((await res.json()) as { token: string }).token;
}

const screens: [string, ReactElement, RegExp][] = [
  ["Overview", <OverviewPage />, /Top endpoints/],
  ["Live traffic", <TrafficPage />, /Live traffic/],
  ["Alerts", <AlertsPage />, /Alerts/],
  ["Scans", <ScansPage />, /Scans & reports/],
  ["API map", <InventoryPage />, /Requests 24 h/],
  ["Rules", <RulesPage />, /Gateway rules|0 rules/],
  ["Learning", <LearningPage />, /Payload shapes/],
  ["Settings", <SettingsPage />, /Never stored/],
];

describe.runIf(live)("screens against the live Admin API", () => {
  let errors: unknown[] = [];
  const original = console.error;
  beforeEach(() => {
    errors = [];
    console.error = (...args: unknown[]) => {
      errors.push(args);
      original(...args);
    };
  });
  afterEach(() => {
    console.error = original;
  });

  it.each(screens)("%s renders without contract errors", async (_name, ui, marker) => {
    renderScreen(ui, { token: await token() });
    expect((await screen.findAllByText(marker, undefined, { timeout: 8000 })).length).toBeGreaterThan(0);
    // Let the first round of queries settle, then make sure none failed or broke the contract.
    await new Promise((r) => setTimeout(r, 1500));
    await waitFor(() => expect(screen.queryByText(/did not load|couldn't load/i)).not.toBeInTheDocument());
    expect(errors.filter((e) => String(e).includes("does not match the contract"))).toEqual([]);
  });

  it("mode control renders for an admin", async () => {
    renderScreen(<ModeControl />, { token: await token() });
    expect(await screen.findByRole("button", { name: /gateway mode/i }, { timeout: 8000 })).toBeInTheDocument();
  });
});

describe.skipIf(live)("live Admin API tests", () => {
  it("are skipped (set VITE_API_BASE=http://host:8000/api to run them)", () => expect(live).toBe(false));
});
