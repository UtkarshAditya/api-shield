import { NavLink } from "react-router-dom";
import {
  Activity,
  Bell,
  Brain,
  LayoutDashboard,
  Map,
  ScanSearch,
  Settings,
  ShieldCheck,
  SlidersHorizontal,
  type LucideIcon,
} from "lucide-react";
import { useAlerts } from "@/api/queries";
import { useWorkspace } from "@/app/WorkspaceContext";
import { cn } from "@/lib/cn";

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

export function Sidebar() {
  const { upstreamId } = useWorkspace();
  const { data: newAlerts } = useAlerts(upstreamId, { status: "new", limit: 1 });

  return (
    <aside className="hidden w-60 shrink-0 flex-col border-r border-border bg-surface md:flex">
      <div className="flex h-14 items-center gap-2 px-5">
        <ShieldCheck className="size-6 text-accent" aria-hidden />
        <span className="text-base font-semibold tracking-tight">APIShield</span>
      </div>
      <nav aria-label="Main" className="flex-1 space-y-6 overflow-y-auto px-3 py-4">
        {sections.map((s) => (
          <div key={s.title}>
            <p className="px-2 pb-1.5 text-[11px] font-semibold tracking-wider text-muted uppercase">{s.title}</p>
            <ul className="space-y-0.5">
              {s.items.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    className={({ isActive }) =>
                      cn(
                        "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-sm transition-colors",
                        isActive ? "bg-accent-soft font-medium text-fg" : "text-muted hover:bg-surface-2 hover:text-fg",
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <item.icon className={cn("size-4", isActive && "text-accent")} aria-hidden />
                        <span className="flex-1">{item.label}</span>
                        {item.badge === "alerts" && !!newAlerts?.total && (
                          <span className="rounded-full bg-sev-critical px-1.5 text-[10px] font-bold text-white tabular-nums">
                            {newAlerts.total}
                            <span className="sr-only"> new alerts</span>
                          </span>
                        )}
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      <p className="border-t border-border px-5 py-3 text-[11px] leading-snug text-muted">
        Self-hosted · learns shapes, <br />
        never contents.
      </p>
    </aside>
  );
}
