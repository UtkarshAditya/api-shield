import { Suspense } from "react";
import { Outlet } from "react-router-dom";
import { WorkspaceProvider } from "@/app/WorkspaceContext";
import { Skeleton } from "@/components/ui/Skeleton";
import { Sidebar } from "./Sidebar";
import { Topbar } from "./Topbar";

export default function AppShell() {
  return (
    <WorkspaceProvider>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded focus:bg-accent focus:px-3 focus:py-1.5 focus:text-accent-fg">
        Skip to content
      </a>
      <div className="flex min-h-screen">
        <Sidebar />
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar />
          <main id="main" className="flex-1 px-4 py-6 md:px-6">
            <Suspense fallback={<Skeleton className="h-96 w-full" />}>
              <Outlet />
            </Suspense>
          </main>
        </div>
      </div>
    </WorkspaceProvider>
  );
}
