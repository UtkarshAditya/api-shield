/** Screen tests: each screen renders from mock data, its main action works, and roles gate it. */
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { ModeControl } from "@/components/domain/ModeControl";
import AlertsPage from "@/features/alerts/AlertsPage";
import RulesPage from "@/features/rules/RulesPage";
import ScansPage from "@/features/scans/ScansPage";
import TrafficPage, { MAX_ROWS, mergeEvents } from "@/features/traffic/TrafficPage";
import { buildRecentTraffic, db } from "@/mocks/db";
import { renderScreen, useMockApi } from "./renderScreen";

useMockApi();

describe("Mode control", () => {
  it("lets an admin switch to ENFORCE after confirming", async () => {
    renderScreen(<ModeControl />);
    fireEvent.click(await screen.findByRole("button", { name: /gateway mode: monitor/i }));
    const dialog = await screen.findByRole("dialog", { name: /switch to enforce/i });
    expect(db.settings.mode).toBe("monitor"); // nothing happens before confirming
    fireEvent.click(within(dialog).getByRole("button", { name: "Switch to ENFORCE" }));
    expect(await screen.findByRole("button", { name: /gateway mode: enforce/i })).toBeInTheDocument();
    expect(db.settings.mode).toBe("enforce");
  });

  it("is a read-only badge for analysts", async () => {
    renderScreen(<ModeControl />, { role: "analyst" });
    expect(await screen.findByText("MONITOR")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /gateway mode/i })).not.toBeInTheDocument();
  });

  it("shows a clear message when the gateway is unreachable", async () => {
    const { http, HttpResponse } = await import("msw");
    const { server } = await import("./renderScreen");
    server.use(
      http.patch("/api/settings", () =>
        HttpResponse.json({ error: { code: "gateway_unreachable", message: "The gateway is not reachable." } }, { status: 502 }),
      ),
    );
    renderScreen(<ModeControl />);
    fireEvent.click(await screen.findByRole("button", { name: /gateway mode: monitor/i }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Switch to ENFORCE" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/gateway is not reachable, so nothing was changed/i);
  });
});

describe("Scans", () => {
  it("shows findings grouped by endpoint and applies a suggested rule", async () => {
    renderScreen(<ScansPage />);
    const group = await screen.findByRole("region", { name: "Findings for GET /search" });
    fireEvent.click(within(group).getByRole("button", { name: /sql injection/i }));
    expect(within(group).getByText(/how to fix it/i)).toBeInTheDocument();
    fireEvent.click(within(group).getByRole("button", { name: "Apply suggested rule" }));
    expect(await within(group).findByText(/mitigated by rule/i)).toBeInTheDocument();
    expect(within(group).getByRole("link", { name: "rule-block-sqli-q" })).toHaveAttribute("href", "/app/rules?highlight=rule-block-sqli-q");
    expect(db.rules.up_shop.some((r) => r.id === "rule-block-sqli-q")).toBe(true);
  });

  it("requires the consent checkbox before starting a scan", async () => {
    renderScreen(<ScansPage />, { role: "analyst" });
    fireEvent.click(await screen.findByRole("button", { name: /new scan/i }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByRole("switch", { name: /safe mode/i })).toBeChecked();
    fireEvent.click(within(dialog).getByRole("button", { name: "Next" }));
    const start = within(dialog).getByRole("button", { name: /start scan/i });
    expect(start).toBeDisabled();
    fireEvent.click(within(dialog).getByRole("checkbox"));
    expect(start).toBeEnabled();
    fireEvent.click(start);
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(db.scans.up_shop).toHaveLength(2);
    expect(await screen.findByRole("progressbar", { name: /scan progress/i })).toBeInTheDocument();
  });

  it("hides scanning and rule actions from viewers", async () => {
    renderScreen(<ScansPage />, { role: "viewer" });
    expect(await screen.findByRole("button", { name: /new scan/i })).toBeDisabled();
    const group = await screen.findByRole("region", { name: "Findings for GET /search" });
    fireEvent.click(within(group).getByRole("button", { name: /sql injection/i }));
    expect(within(group).queryByRole("button", { name: "Apply suggested rule" })).not.toBeInTheDocument();
  });
});

describe("Rules", () => {
  it("renders list-valued matches and keeps built-in rules read-only", async () => {
    renderScreen(<RulesPage />);
    expect(await screen.findByText("method POST | PUT | DELETE")).toBeInTheDocument();
    expect(screen.getByText(/IP range 203\.0\.113\.0\/24, 198\.51\.100\.0\/24/)).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: /SQL injection signatures enabled \(read-only\)/ })).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Delete rule builtin-sqli" })).not.toBeInTheDocument();
  });

  it("lets an analyst create a rule, then delete it after confirming", async () => {
    renderScreen(<RulesPage />, { role: "analyst" });
    fireEvent.click(await screen.findByRole("button", { name: /new rule/i }));
    const dialog = await screen.findByRole("dialog");
    fireEvent.change(within(dialog).getByLabelText(/^Rule id/), { target: { value: "block-export" } });
    fireEvent.change(within(dialog).getByLabelText("Path"), { target: { value: "/internal/export" } });
    fireEvent.change(within(dialog).getByLabelText("Action"), { target: { value: "block" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Create rule" }));
    expect(await screen.findByText("block-export", { selector: "p" })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Delete rule block-export" }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Delete rule" }));
    await waitFor(() => expect(db.rules.up_shop.some((r) => r.id === "block-export")).toBe(false));
  });

  it("gives viewers no edit controls", async () => {
    renderScreen(<RulesPage />, { role: "viewer" });
    await screen.findByText("Block writes to /admin");
    expect(screen.queryByRole("button", { name: /new rule/i })).not.toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Block writes to /admin enabled" })).toBeDisabled();
  });
});

describe("Alerts", () => {
  it("groups the ranked queue by caller", async () => {
    renderScreen(<AlertsPage />);
    const heading = await screen.findAllByText("key_929bf132");
    expect(heading.length).toBeGreaterThan(0);
    expect(screen.getAllByText(/^#\d$/)[0]).toHaveTextContent("#1");
  });

  it("shows reasons and reports the threshold adjustment for a false positive", async () => {
    renderScreen(<AlertsPage />, { route: "/app/alerts/al_1001", path: "/app/alerts/:id" });
    expect(await screen.findByText("What happened")).toBeInTheDocument();
    expect(screen.getByText("412 req/min")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /false positive/i }));
    expect(await screen.findByText(/threshold adjusted/i)).toHaveTextContent("Request rate +0.1");
  });

  it("explains that pseudonymous callers cannot be targeted individually", async () => {
    renderScreen(<AlertsPage />, { route: "/app/alerts/al_1002", path: "/app/alerts/:id" });
    fireEvent.click(await screen.findByRole("button", { name: /promote to rule/i }));
    expect(await screen.findByRole("dialog")).toHaveTextContent(/only api-key callers can be targeted individually/i);
  });

  it("is read-only for viewers", async () => {
    renderScreen(<AlertsPage />, { role: "viewer", route: "/app/alerts/al_1001", path: "/app/alerts/:id" });
    expect(await screen.findByText("What happened")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /false positive/i })).not.toBeInTheDocument();
  });
});

describe("Live traffic", () => {
  it("renders recent requests, filters them and opens the rule-hit drawer", async () => {
    renderScreen(<TrafficPage />, { role: "viewer" });
    await screen.findAllByRole("button", { name: /rule hits/i });
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "block" } });
    for (const row of screen.queryAllByRole("row").slice(1)) expect(row).toHaveTextContent("Block");
    fireEvent.change(screen.getByLabelText("Action"), { target: { value: "all" } });
    fireEvent.click(screen.getAllByRole("button", { name: /rule hits/i })[0]);
    expect(await screen.findByRole("dialog", { name: "Request details" })).toHaveTextContent(/payload values never/i);
  }, 20_000); // ~200 rows in jsdom is slow on a loaded machine

  it("pauses and resumes", async () => {
    renderScreen(<TrafficPage />);
    fireEvent.click(await screen.findByRole("button", { name: "Pause" }));
    expect(screen.getByRole("button", { name: "Resume" })).toHaveAttribute("aria-pressed", "true");
  });

  it("dedupes by request id and caps the buffer", () => {
    const batch = buildRecentTraffic("up_shop", 50);
    const once = mergeEvents([], batch);
    expect(mergeEvents(once, batch)).toBe(once);
    expect(mergeEvents([], buildRecentTraffic("up_shop", 400))).toHaveLength(MAX_ROWS);
  });
});

describe("Learning", () => {
  it("shows status, saves sensitivity and confirms a reset", async () => {
    const LearningPage = (await import("@/features/learning/LearningPage")).default;
    renderScreen(<LearningPage />);
    expect(await screen.findByText(/never the values/i)).toBeInTheDocument();
    expect(await screen.findByText("23")).toBeInTheDocument(); // shapes learned
    fireEvent.change(screen.getByLabelText("Sensitivity"), { target: { value: "0.8" } });
    fireEvent.click(screen.getByRole("button", { name: "Save sensitivity" }));
    await waitFor(() => expect(db.learning.up_shop.sensitivity).toBe(0.8));
    fireEvent.click(screen.getByRole("button", { name: /reset baseline/i }));
    const dialog = await screen.findByRole("dialog", { name: /reset the learned baseline/i });
    fireEvent.click(within(dialog).getByRole("button", { name: "Reset baseline" }));
    await waitFor(() => expect(db.learning.up_shop.mode).toBe("warmup"));
  });

  it("is read-only for analysts", async () => {
    const LearningPage = (await import("@/features/learning/LearningPage")).default;
    renderScreen(<LearningPage />, { role: "analyst" });
    expect(await screen.findByLabelText("Sensitivity")).toBeDisabled();
    expect(screen.queryByRole("button", { name: /reset baseline/i })).not.toBeInTheDocument();
  });
});

describe("API map", () => {
  it("flags shadow endpoints and shows risk with a severity badge", async () => {
    const InventoryPage = (await import("@/features/inventory/InventoryPage")).default;
    renderScreen(<InventoryPage />, { role: "viewer" });
    const debugRow = (await screen.findByText("/debug")).closest("tr")!;
    expect(within(debugRow).getByText("Shadow")).toBeInTheDocument();
    const searchRow = screen.getByText("/search").closest("tr")!;
    expect(within(searchRow).getByText("Critical")).toBeInTheDocument();
  });
});

describe("Settings & privacy", () => {
  it("shows the privacy panel and audit log to admins, and confirms a purge", async () => {
    const SettingsPage = (await import("@/features/settings/SettingsPage")).default;
    renderScreen(<SettingsPage />);
    expect(await screen.findByText("Never stored")).toBeInTheDocument();
    expect(await screen.findByText("scan.start")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /purge traffic data/i }));
    fireEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Purge data" }));
    expect(await screen.findByText(/purged 0 buffered events/i)).toBeInTheDocument();
    expect(db.audit[0].action).toBe("data.purge");
  });

  it("hides the audit log, purge and mode switch from analysts", async () => {
    const SettingsPage = (await import("@/features/settings/SettingsPage")).default;
    renderScreen(<SettingsPage />, { role: "analyst" });
    expect(await screen.findByText(/only admins can view the audit log/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /purge/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /switch to enforce/i })).not.toBeInTheDocument();
    expect(await screen.findByRole("switch", { name: "Fail open" })).toBeDisabled();
  });
});
