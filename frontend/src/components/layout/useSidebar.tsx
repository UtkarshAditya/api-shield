import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useLocation } from "react-router-dom";

export const SIDEBAR_KEY = "apishield.sidebar";

function readStored(): "collapsed" | "expanded" | null {
  try {
    const v = window.localStorage.getItem(SIDEBAR_KEY);
    return v === "collapsed" || v === "expanded" ? v : null;
  } catch {
    return null; // private mode / blocked storage
  }
}

function store(v: "collapsed" | "expanded") {
  try {
    window.localStorage.setItem(SIDEBAR_KEY, v);
  } catch {
    /* not persisted; the state still works for this session */
  }
}

/** Default: expanded, except below 1024 px where it starts collapsed, unless the user chose. */
function initialCollapsed(): boolean {
  const stored = readStored();
  if (stored) return stored === "collapsed";
  return typeof window !== "undefined" && window.innerWidth < 1024;
}

function isTyping(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable;
}

type SidebarState = {
  collapsed: boolean;
  toggle: () => void;
  /** Under 768 px the sidebar is an overlay drawer. */
  mobileOpen: boolean;
  setMobileOpen: (v: boolean) => void;
};

const Ctx = createContext<SidebarState | null>(null);

export function SidebarProvider({ children }: { children: ReactNode }) {
  const [collapsed, setCollapsed] = useState(initialCollapsed);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  const toggle = useCallback(() => {
    setCollapsed((c) => {
      store(c ? "expanded" : "collapsed");
      return !c;
    });
  }, []);

  // "[" toggles the sidebar, but never while the user is typing or holding a modifier.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "[" || e.ctrlKey || e.metaKey || e.altKey || isTyping(e.target)) return;
      e.preventDefault();
      toggle();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggle]);

  // The mobile drawer closes on navigation.
  useEffect(() => setMobileOpen(false), [location.pathname]);

  const value = useMemo(() => ({ collapsed, toggle, mobileOpen, setMobileOpen }), [collapsed, toggle, mobileOpen]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSidebar(): SidebarState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useSidebar must be used inside SidebarProvider");
  return v;
}
