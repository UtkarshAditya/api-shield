import * as D from "@radix-ui/react-dialog";
import { NavLink } from "react-router-dom";
import {
  Activity,
  Bell,
  Brain,
  LayoutDashboard,
  Lock,
  Map,
  PanelLeftClose,
  PanelLeftOpen,
  ScanSearch,
  Settings,
  Shield,
  SlidersHorizontal,
  X,
  type LucideIcon,
} from "lucide-react";
import { useAlerts } from "@/api/queries";
import { useWorkspace } from "@/app/WorkspaceContext";
import { Tooltip } from "@/components/ui/Tooltip";
import { cn } from "@/lib/cn";
import { useSidebar } from "./useSidebar";

type Item = { to: string; label: string; icon: LucideIcon; badge?: "alerts" };

const sections: { title: string; items: Item[] }[] = [
  {
    title: "Monitor",
    items: [
      { to: "overview", label: "Overview", icon: LayoutDashboard },
      { to: "traffic", label: "Live traffic", icon: Activity },
      { to: "alerts", label: "Alerts", icon: Bell, badge: "alerts" },
    ],
  },
  {
    title: "Harden",
    items: [
      { to: "scans", label: "Scans & reports", icon: ScanSearch },
      { to: "inventory", label: "API map", icon: Map },
      { to: "rules", label: "Rules", icon: SlidersHorizontal },
    ],
  },
  {
    title: "Configure",
    items: [
      { to: "learning", label: "Learning", icon: Brain },
      { to: "settings", label: "Settings & privacy", icon: Settings },
    ],
  },
];

const FOOTER = "Self-hosted. Learns shapes, never contents.";

function NavItem({ item, collapsed, newAlerts }: { item: Item; collapsed: boolean; newAlerts: number }) {
  const count = item.badge === "alerts" ? newAlerts : 0;
  const link = (
    <NavLink
      to={item.to}
      aria-label={collapsed ? (count ? `${item.label}, ${count} new` : item.label) : undefined}
      className={({ isActive }) =>
        cn(
          "relative flex h-8 items-center gap-2.5 text-sm transition-[color,box-shadow,background-color] ease-ui",
          collapsed ? "justify-center px-0" : "px-3",
          isActive
            ? "bg-surface-2 font-medium text-fg shadow-[inset_2px_0_0_var(--text)]"
            : "text-muted hover:bg-surface-2 hover:text-fg",
        )
      }
    >
      {({ isActive }) => (
        <>
          <item.icon className={cn("size-4 shrink-0", isActive && "text-fg")} strokeWidth={isActive ? 2.25 : 1.75} aria-hidden />
          {!collapsed && <span className="flex-1 truncate">{item.label}</span>}
          {count > 0 &&
            (collapsed ? (
              <span aria-hidden className="absolute top-1 right-3 size-1.5 rounded-full bg-signal-mark" />
            ) : (
              <span className="font-mono text-xs font-medium text-signal tabular-nums">
                {count}
                <span className="sr-only"> new alerts</span>
              </span>
            ))}
        </>
      )}
    </NavLink>
  );
  // The tooltip wraps a span: as a Slot on NavLink it would drop NavLink's function className.
  return (
    <li>
      {collapsed ? (
        <Tooltip content={item.label} side="right">
          <span className="block">{link}</span>
        </Tooltip>
      ) : (
        link
      )}
    </li>
  );
}

/** The navigation itself; rendered in the desktop rail and in the mobile drawer. */
function SidebarBody({ collapsed, onToggle, inDrawer }: { collapsed: boolean; onToggle?: () => void; inDrawer?: boolean }) {
  const { upstreamId } = useWorkspace();
  const { data: newAlerts } = useAlerts(upstreamId, { status: "new", limit: 1 });
  const count = newAlerts?.total ?? 0;

  return (
    <div className="flex h-full flex-col">
      <div className={cn("flex h-[var(--topbar-h)] shrink-0 items-center gap-2 border-b border-border", collapsed ? "justify-center" : "px-4")}>
        <Shield className="size-[18px] shrink-0 text-fg" strokeWidth={2} aria-hidden />
        {!collapsed && <span className="text-[15px] font-semibold tracking-tight">APIShield</span>}
        {collapsed && <span className="sr-only">APIShield</span>}
        {inDrawer && (
          <D.Close className="ml-auto rounded-sm p-1 text-muted hover:text-fg" aria-label="Close navigation">
            <X className="size-4" aria-hidden />
          </D.Close>
        )}
      </div>
      <nav aria-label="Main" className="flex-1 overflow-y-auto py-3">
        {sections.map((s, i) => (
          <div key={s.title} className={cn(i > 0 && (collapsed ? "mt-3 border-t border-border pt-3" : "mt-5"))}>
            {!collapsed && <p className="eyebrow px-4 pb-1.5">{s.title}</p>}
            <ul className="space-y-px">
              {s.items.map((item) => (
                <NavItem key={item.to} item={item} collapsed={collapsed} newAlerts={count} />
              ))}
            </ul>
          </div>
        ))}
      </nav>
      <div className="shrink-0 border-t border-border">
        {collapsed ? (
          <Tooltip content={FOOTER} side="right">
            <span tabIndex={0} role="note" className="flex h-9 items-center justify-center text-muted" aria-label={FOOTER}>
              <Lock className="size-3.5" aria-hidden />
            </span>
          </Tooltip>
        ) : (
          <p className="px-4 py-2.5 font-mono text-[11px] leading-snug text-muted">{FOOTER}</p>
        )}
        {onToggle && (
          <button
            type="button"
            onClick={onToggle}
            aria-expanded={!collapsed}
            aria-controls="app-sidebar"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={cn(
              "flex h-9 w-full items-center gap-2 border-t border-border text-xs text-muted transition-colors ease-ui hover:bg-surface-2 hover:text-fg",
              collapsed ? "justify-center" : "px-4",
            )}
          >
            {collapsed ? <PanelLeftOpen className="size-4" aria-hidden /> : <PanelLeftClose className="size-4" aria-hidden />}
            {!collapsed && (
              <>
                <span className="flex-1 text-left">Collapse</span>
                <kbd className="border border-border px-1 font-mono text-[10px]">[</kbd>
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}

export function Sidebar() {
  const { collapsed, toggle, mobileOpen, setMobileOpen } = useSidebar();
  return (
    <>
      <aside
        id="app-sidebar"
        className="sticky top-0 hidden h-screen shrink-0 overflow-hidden border-r border-border bg-surface transition-[width] ease-ui md:block"
        style={{ width: collapsed ? "var(--sidebar-w-collapsed)" : "var(--sidebar-w)" }}
      >
        <SidebarBody collapsed={collapsed} onToggle={toggle} />
      </aside>
      <D.Root open={mobileOpen} onOpenChange={setMobileOpen}>
        <D.Portal>
          <D.Overlay className="fixed inset-0 z-40 bg-fg/25 md:hidden dark:bg-black/55" />
          <D.Content className="fixed inset-y-0 left-0 z-50 w-[var(--sidebar-w)] border-r border-border-strong bg-surface md:hidden">
            <D.Title className="sr-only">Navigation</D.Title>
            <D.Description className="sr-only">Main navigation</D.Description>
            <SidebarBody collapsed={false} inDrawer />
          </D.Content>
        </D.Portal>
      </D.Root>
    </>
  );
}
