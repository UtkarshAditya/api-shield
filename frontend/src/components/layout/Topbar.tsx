import * as DM from "@radix-ui/react-dropdown-menu";
import { Check, ChevronDown, LogOut, Menu, Moon, Sun } from "lucide-react";
import { useLearningStatus } from "@/api/queries";
import { useWorkspace } from "@/app/WorkspaceContext";
import { useAuth } from "@/auth/AuthContext";
import { roleLabel } from "@/auth/roles";
import { LearningChip } from "@/components/domain/LearningChip";
import { ModeControl } from "@/components/domain/ModeControl";
import { useTheme } from "@/theme/ThemeProvider";
import { useSidebar } from "./useSidebar";

const menuCls = "z-50 min-w-56 rounded-sm border border-border-strong bg-surface p-1";
const itemCls = "flex cursor-pointer items-center gap-2 rounded-sm px-2.5 py-1.5 text-sm outline-none data-[highlighted]:bg-surface-2";
const barBtn = "inline-flex h-7 items-center gap-1.5 rounded-sm px-1.5 text-sm text-fg transition-colors ease-ui hover:bg-surface-2";

function UpstreamSelector() {
  const { upstreams, upstream, setUpstreamId } = useWorkspace();
  return (
    <DM.Root>
      <DM.Trigger className={barBtn} aria-label="Select upstream API">
        <span className="max-w-48 truncate font-medium">{upstream?.name ?? "No upstream"}</span>
        <ChevronDown className="size-3.5 text-muted" aria-hidden />
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="start" sideOffset={6} className={menuCls}>
          <DM.Label className="eyebrow px-2.5 py-1.5">Protected APIs</DM.Label>
          {upstreams.map((u) => (
            <DM.Item key={u.id} className={itemCls} onSelect={() => setUpstreamId(u.id)}>
              <Check className={u.id === upstream?.id ? "size-3.5" : "size-3.5 opacity-0"} aria-hidden />
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
      <DM.Trigger className={barBtn} aria-label="Account menu">
        <span className="grid size-5 place-items-center bg-accent font-mono text-[10px] font-semibold text-accent-fg">{user.name.slice(0, 1)}</span>
        <span className="hidden lg:inline">{user.name}</span>
        <ChevronDown className="size-3.5 text-muted" aria-hidden />
      </DM.Trigger>
      <DM.Portal>
        <DM.Content align="end" sideOffset={6} className={menuCls}>
          <div className="px-2.5 py-2">
            <p className="text-sm font-medium">{user.name}</p>
            <p className="font-mono text-xs text-muted">{user.email}</p>
            <p className="eyebrow mt-1.5">{roleLabel[user.role]}</p>
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
  const { data: learning } = useLearningStatus(upstreamId);
  const { theme, toggle } = useTheme();
  const { setMobileOpen } = useSidebar();

  return (
    <header className="sticky top-0 z-30 flex h-[var(--topbar-h)] items-center gap-3 border-b border-border bg-bg px-3 md:px-5">
      <button type="button" className={`${barBtn} md:hidden`} onClick={() => setMobileOpen(true)} aria-label="Open navigation">
        <Menu className="size-4" aria-hidden />
      </button>
      <UpstreamSelector />
      <div className="flex-1" />
      <ModeControl />
      <span className="hidden sm:inline-flex">
        <LearningChip status={learning} />
      </span>
      <button type="button" className={barBtn} onClick={toggle} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
        {theme === "dark" ? <Sun className="size-4" aria-hidden /> : <Moon className="size-4" aria-hidden />}
      </button>
      <UserMenu />
    </header>
  );
}
