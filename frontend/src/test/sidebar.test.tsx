/** Collapsible sidebar: aria state, persistence across remount, keyboard shortcut. */
import { fireEvent, screen } from "@testing-library/react";
import { Sidebar } from "@/components/layout/Sidebar";
import { SIDEBAR_KEY, SidebarProvider } from "@/components/layout/useSidebar";
import { renderScreen, useMockApi } from "./renderScreen";

useMockApi();

const ui = (
  <SidebarProvider>
    <Sidebar />
    <input aria-label="search box" />
  </SidebarProvider>
);

beforeEach(() => {
  localStorage.clear();
  Object.defineProperty(window, "innerWidth", { configurable: true, value: 1280 });
});

describe("Sidebar", () => {
  it("toggles, flips its aria state and persists across remount", async () => {
    const first = renderScreen(ui);
    const toggle = await screen.findByRole("button", { name: "Collapse sidebar" });
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("navigation", { name: "Main" })).toHaveTextContent("Live traffic");

    fireEvent.click(toggle);
    const expand = screen.getByRole("button", { name: "Expand sidebar" });
    expect(expand).toHaveAttribute("aria-expanded", "false");
    expect(localStorage.getItem(SIDEBAR_KEY)).toBe("collapsed");
    // collapsed: labels move into tooltips / accessible names; links stay focusable
    expect(screen.getByRole("link", { name: "Live traffic" })).toBeInTheDocument();

    first.unmount();
    renderScreen(ui);
    expect(await screen.findByRole("button", { name: "Expand sidebar" })).toHaveAttribute("aria-expanded", "false");
  });

  it("toggles with [ but not while typing", async () => {
    renderScreen(ui);
    await screen.findByRole("button", { name: "Collapse sidebar" });
    fireEvent.keyDown(screen.getByLabelText("search box"), { key: "[" });
    expect(screen.getByRole("button", { name: "Collapse sidebar" })).toBeInTheDocument();
    fireEvent.keyDown(window, { key: "[" });
    expect(screen.getByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();
  });

  it("starts collapsed below 1024 px when the user has not chosen", async () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 900 });
    renderScreen(ui);
    expect(await screen.findByRole("button", { name: "Expand sidebar" })).toBeInTheDocument();
  });
});
