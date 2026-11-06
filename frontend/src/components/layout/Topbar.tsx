import * as DM from "@radix-ui/react-dropdown-menu";
import { Check, ChevronDown, LogOut, Moon, Server, Sun, User } from "lucide-react";
import { useLearningStatus, useSettings } from "@/api/queries";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { roleLabel } from "@/auth/roles";
import { LearningChip } from "@/components/domain/LearningChip";
import { ModeBadge } from "@/components/domain/ModeBadge";
import { Button } from "@/components/ui/Button";
import { useTheme } from "@/theme/ThemeProvider";

const menuCls = "z-50 min-w-56 rounded-lg border border-border bg-surface p-1 shadow-xl";
const itemCls = "flex cursor-pointer items-center gap-2 rounded-md px-2.5 py-1.5 text-sm outline-none data-[highlighted]:bg-surface-2";

function UpstreamSelector() {
  const { upstreams, upstream, setUpstreamId } = useWorkspace();
  return (
    <DM.Root>
      <DM.Trigger asChild>
        <Button variant="secondary" size="sm" aria-label="Select upstream API">
          <Server className="size-3.5 text-accent" aria-hidden />
          <span className="max-w-40 truncate">{upstream?.name ?? "No upstream"}</span>
          <ChevronDown className="size-3.5 text-muted" aria-hidden />
        </Button>
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="start" sideOffset={6} className={menuCls}>
          <DM.Label className="px-2.5 py-1.5 text-[11px] font-semibold tracking-wider text-muted uppercase">Protected APIs</DM.Label>
          {upstreams.map((u) => (
            <DM.Item key={u.id} className={itemCls} onSelect={() => setUpstreamId(u.id)}>
              <Check className={u.id === upstream?.id ? "size-3.5 text-accent" : "size-3.5 opacity-0"} aria-hidden />
              <span className="flex-1">
                <span className="block">{u.name}</span>
                <span className="block font-mono text-[11px] text-muted">{u.url}</span>
              </span>
            </DM.Item>
          ))}
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  if (!user) return null;
  return (
    <DM.Root>
      <DM.Trigger asChild>
        <Button variant="ghost" size="sm" aria-label="Account menu">
          <span className="grid size-6 place-items-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent">
            {user.name.slice(0, 1)}
          </span>
          <span className="hidden text-fg lg:inline">{user.name}</span>
          <ChevronDown className="size-3.5" aria-hidden />
        </Button>
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={6} className={menuCls}>
          <div className="px-2.5 py-2">
            <p className="text-sm font-medium">{user.name}</p>
            <p className="text-xs text-muted">{user.email}</p>
            <p className="mt-1.5 inline-flex items-center gap-1 rounded bg-surface-2 px-1.5 py-0.5 text-[11px] text-muted">
              <User className="size-3" aria-hidden /> {roleLabel[user.role]}
            </p>
          </div>
          <DM.Separator className="my-1 h-px bg-border" />
          <DM.Item className={itemCls} onSelect={logout}>
            <LogOut className="size-3.5" aria-hidden /> Sign out
          </DM.Item>
        </DM.Content>
      </DM.Portal>
    </DM.Root>
  );
}

export function Topbar() {
  const { upstreamId } = useWorkspace();
  const { data: settings } = useSettings();
  const { data: learning } = useLearningStatus(upstreamId);
  const { theme, toggle } = useTheme();

  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-3 border-b border-border bg-bg/85 px-4 backdrop-blur md:px-6">
      <UpstreamSelector />
      <div className="flex-1" />
      <ModeBadge mode={settings?.mode} />
      <LearningChip status={learning} />
      <Button variant="ghost" size="sm" onClick={toggle} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
        {theme === "dark" ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
      </Button>
      <UserMenu />
    </header>
  );
}
