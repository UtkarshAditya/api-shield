import { createBrowserRouter, Navigate } from "react-router-dom";
import { RequireAuth } from "@/auth/RequireAuth";

const lazyPage = (load: () => Promise<{ default: React.ComponentType }>) => async () => ({ Component: (await load()).default });

export const router = createBrowserRouter([
  { path: "/", lazy: lazyPage(() => import("@/features/landing/LandingPage")) },
  { path: "/login", lazy: lazyPage(() => import("@/features/auth/LoginPage")) },
  {
    path: "/app",
    element: <RequireAuth />,
    children: [
      {
        lazy: lazyPage(() => import("@/components/layout/AppShell")),
        children: [
          { index: true, element: <Navigate to="overview" replace /> },
          { path: "overview", lazy: lazyPage(() => import("@/features/overview/OverviewPage")) },
          { path: "traffic", lazy: lazyPage(() => import("@/features/traffic/TrafficPage")) },
          { path: "alerts", lazy: lazyPage(() => import("@/features/alerts/AlertsPage")) },
          { path: "alerts/:id", lazy: lazyPage(() => import("@/features/alerts/AlertsPage")) },
          { path: "scans", lazy: lazyPage(() => import("@/features/scans/ScansPage")) },
          { path: "inventory", lazy: lazyPage(() => import("@/features/inventory/InventoryPage")) },
          { path: "rules", lazy: lazyPage(() => import("@/features/rules/RulesPage")) },
          { path: "learning", lazy: lazyPage(() => import("@/features/learning/LearningPage")) },
          { path: "settings", lazy: lazyPage(() => import("@/features/settings/SettingsPage")) },
        ],
      },
    ],
  },
  { path: "*", element: <Navigate to="/" replace /> },
]);
