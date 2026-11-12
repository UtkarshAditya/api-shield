import { render, screen } from "@testing-library/react";
import { z } from "zod";
import { can } from "@/auth/roles";
import { SeverityBadge, severityForScore } from "@/components/domain/SeverityBadge";
import { ContractError, openEventStream, request } from "@/api/client";
import { buildRecentTraffic, buildSummary, buildTimeseries, db } from "@/mocks/db";
import {
  Alert,
  AuditEntry,
  EndpointInventoryItem,
  Finding,
  LearningStatus,
  MetricsSummary,
  Rule,
  Scan,
  Settings,
  Timeseries,
  TrafficEvent,
} from "@/api/schemas";

describe("roles", () => {
  it("gates enforce-mode switching to admins", () => {
    expect(can("admin", "mode.switch")).toBe(true);
    expect(can("analyst", "mode.switch")).toBe(false);
    expect(can("viewer", "alerts.triage")).toBe(false);
    expect(can(undefined, "rules.edit")).toBe(false);
  });
});

describe("SeverityBadge", () => {
  it("renders text, not just color", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });
  it("maps risk scores to severities", () => {
    expect(severityForScore(9.1)).toBe("critical");
    expect(severityForScore(7.4)).toBe("high");
    expect(severityForScore(0.5)).toBe("info");
  });
});

describe("api client", () => {
  it("throws a ContractError naming the bad field", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ count: "nope" }), { status: 200 })));
    await expect(request("/x", { schema: z.object({ count: z.number() }) })).rejects.toThrow(ContractError);
    await expect(request("/x", { schema: z.object({ count: z.number() }) })).rejects.toThrow(/count/);
    vi.unstubAllGlobals();
  });
});

describe("event stream", () => {
  it("falls back to polling without EventSource and drops duplicates", async () => {
    vi.useFakeTimers();
    const batches = [[{ id: "a" }, { id: "b" }], [{ id: "b" }, { id: "c" }]];
    const seen: string[] = [];
    const modes: string[] = [];
    const stop = openEventStream({
      path: "/traffic/stream",
      event: "traffic",
      schema: z.object({ id: z.string() }),
      onEvent: (e) => seen.push(e.id),
      onModeChange: (m) => modes.push(m),
      poll: async () => batches.shift() ?? [],
      keyOf: (e) => e.id,
      pollMs: 100,
    });
    await vi.advanceTimersByTimeAsync(250);
    stop();
    vi.useRealTimers();
    expect(modes).toEqual(["polling"]);
    expect(seen).toEqual(["a", "b", "c"]);
  });
});

describe("mock data matches the contracts", () => {
  it.each(["1h", "24h", "7d"] as const)("summary + timeseries for %s", (range) => {
    expect(() => MetricsSummary.parse(buildSummary("up_shop", range))).not.toThrow();
    expect(() => Timeseries.parse(buildTimeseries("up_shop", range))).not.toThrow();
  });
});

describe("mock seed data matches the contracts", () => {
  const all = <T,>(rec: Record<string, T[]>) => Object.values(rec).flat();

  it("parses every seeded record", () => {
    for (const r of all(db.rules)) Rule.parse(r);
    for (const f of all(db.findings)) Finding.parse(f);
    for (const a of all(db.alerts)) Alert.parse(a);
    for (const s of all(db.scans)) Scan.parse(s);
    for (const e of all(db.inventory)) EndpointInventoryItem.parse(e);
    for (const l of Object.values(db.learning)) LearningStatus.parse(l);
    for (const a of db.audit) AuditEntry.parse(a);
    for (const t of buildRecentTraffic("up_shop", 50)) TrafficEvent.parse(t);
    Settings.parse({ ...db.settings, upstreams: db.upstreams });
  });

  it("covers the gateway's list-valued method and throttle rules", () => {
    expect(all(db.rules).some((r) => Array.isArray(r.match.method))).toBe(true);
    const login = all(db.findings).find((f) => f.endpoint === "/login");
    expect(login?.suggested_rule).toMatchObject({ action: "throttle", throttle: { limit: 5, per: 60 } });
  });

  it("only uses pseudonymized caller ids", () => {
    const ids = [...all(db.alerts).map((a) => a.caller), ...buildRecentTraffic("up_shop", 50).flatMap((t) => [t.caller, t.ip])];
    for (const id of ids) expect(id).toMatch(/^(key|ip|user)_[0-9a-f]{8}$/);
  });
});
