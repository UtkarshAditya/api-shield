import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useUpstreams } from "@/api/queries";
import type { Upstream } from "@/api/schemas";

const KEY = "apishield.upstream";

type Workspace = {
  upstreams: Upstream[];
  upstream: Upstream | undefined;
  upstreamId: string | undefined;
  setUpstreamId: (id: string) => void;
  isLoading: boolean;
};

const WorkspaceContext = createContext<Workspace | null>(null);

export function WorkspaceProvider({ children }: { children: ReactNode }) {
  const { data: upstreams = [], isLoading } = useUpstreams();
  const [selected, setSelected] = useState<string | undefined>(() => {
    try {
      return localStorage.getItem(KEY) ?? undefined;
    } catch {
      return undefined;
    }
  });

  const upstream = upstreams.find((u) => u.id === selected) ?? upstreams[0];

  useEffect(() => {
    if (!upstream) return;
    try {
      localStorage.setItem(KEY, upstream.id);
    } catch {
      /* ignore */
    }
  }, [upstream]);

  return (
    <WorkspaceContext.Provider value={{ upstreams, upstream, upstreamId: upstream?.id, setUpstreamId: setSelected, isLoading }}>
      {children}
    </WorkspaceContext.Provider>
  );
}

export function useWorkspace() {
  const ctx = useContext(WorkspaceContext);
  if (!ctx) throw new Error("useWorkspace must be used inside WorkspaceProvider");
  return ctx;
}
