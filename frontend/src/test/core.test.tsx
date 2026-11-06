import { render, screen } from "@testing-library/react";
import { z } from "zod";
import { can } from "@/auth/roles";
import { SeverityBadge, severityForScore } from "@/components/domain/SeverityBadge";
import { ContractError, request } from "@/api/client";
import { buildSummary, buildTimeseries } from "@/mocks/db";
import { MetricsSummary, Timeseries } from "@/api/schemas";

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

describe("mock data matches the contracts", () => {
  it.each(["1h", "24h", "7d"] as const)("summary + timeseries for %s", (range) => {
    expect(() => MetricsSummary.parse(buildSummary("up_shop", range))).not.toThrow();
    expect(() => Timeseries.parse(buildTimeseries("up_shop", range))).not.toThrow();
  });
});
