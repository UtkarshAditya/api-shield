/** Rules detail panel: opens from a row, deep link, fallback without docs, switch sync. */
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import RulesPage from "@/features/rules/RulesPage";
import { db } from "@/mocks/db";
import { renderScreen, useMockApi } from "./renderScreen";

useMockApi();

describe("Rules detail panel", () => {
  it("groups rules by source with counts and evaluation numbers", async () => {
    renderScreen(<RulesPage />);
    const table = await screen.findByRole("table", { name: "Gateway rules" });
    for (const g of ["Built-in", "Scanner", "Analyst", "Learner"]) {
      expect(within(table).getByRole("columnheader", { name: new RegExp(`^${g}`) })).toBeInTheDocument();
    }
    const first = within(table).getByText("IP deny list").closest("tr")!;
    expect(first).toHaveTextContent(/^01/);
  });

  it("opens from a row click and explains the built-in", async () => {
    renderScreen(<RulesPage />);
    fireEvent.click(await screen.findByText("SQL injection signatures"));
    const panel = await screen.findByRole("dialog", { name: "Rule details" });
    expect(within(panel).getByText("What it catches")).toBeInTheDocument();
    expect(within(panel).getByText(/UNION \[ALL\] SELECT/)).toBeInTheDocument();
    expect(within(panel).getByText(/403 Forbidden, error code blocked_by_rule/)).toBeInTheDocument();
    expect(within(panel).getByText("Known limits")).toBeInTheDocument();
    expect(within(panel).getByText(/CWE-89/)).toBeInTheDocument();
  });

  it("opens from the ?rule= deep link", async () => {
    renderScreen(<RulesPage />, { route: "/app/rules?rule=builtin-bad-user-agent", path: "/app/rules" });
    const panel = await screen.findByRole("dialog", { name: "Rule details" });
    expect(within(panel).getByText("User-Agent request header only")).toBeInTheDocument();
    fireEvent.keyDown(panel, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("renders the fallback for a rule without docs, and a not-found panel for an unknown id", async () => {
    const view = renderScreen(<RulesPage />, { route: "/app/rules?rule=block-admin-writes", path: "/app/rules" });
    const panel = await screen.findByRole("dialog", { name: "Rule details" });
    expect(within(panel).getByText(/no written explanation for this rule/i)).toBeInTheDocument();
    expect(within(panel).getByText("Behavior by mode")).toBeInTheDocument();
    expect(within(panel).queryByText("What it catches")).not.toBeInTheDocument();
    view.unmount();

    renderScreen(<RulesPage />, { route: "/app/rules?rule=does-not-exist", path: "/app/rules" });
    expect(await screen.findByRole("dialog", { name: "Rule not found" })).toHaveTextContent("does-not-exist");
  });

  it("keeps the panel switch and the table switch in sync", async () => {
    renderScreen(<RulesPage />, { role: "analyst", route: "/app/rules?rule=block-admin-writes", path: "/app/rules" });
    const panel = await screen.findByRole("dialog", { name: "Rule details" });
    fireEvent.click(within(panel).getByRole("switch", { name: /block writes to \/admin enabled, details panel/i }));
    await waitFor(() => expect(db.rules.up_shop.find((r) => r.id === "block-admin-writes")?.enabled).toBe(false));
    await waitFor(() => expect(within(panel).getByRole("switch", { name: /details panel/i })).not.toBeChecked());
  });
});
