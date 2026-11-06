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
          { path: "traffic", lazy: lazyPage(() => import("@/features/placeholders").then((m) => ({ default: m.TrafficPage }))) },
          { path: "alerts", lazy: lazyPage(() => import("@/features/placeholders").then((m) => ({ default: m.AlertsPage }))) },
          { path: "alerts/:id", lazy: lazyPage(() => import("@/features/placeholders").then((m) => ({ default: m.AlertsPage }))) },
          { path: "scans", lazy: lazyPage(() => import("@/features/placeholders").then((m) => ({ default: m.ScansPage }))) },
          { path: "inventory", lazy: lazyPage(() => import("@/features/placeholders").then((m) => ({ default: m.InventoryPage }))) },
          { path: "rules", lazy: lazyPage(() => import("@/features/placeholders").then((m) => ({ default: m.RulesPage }))) },
          { path: "learning", lazy: lazyPage(() => import("@/features/placeholders").then((m) => ({ default: m.LearningPage }))) },
          { path: "settings", lazy: lazyPage(() => import("@/features/placeholders").then((m) => ({ default: m.SettingsPage }))) },
        ],
      },
    ],
  },
  { path: "*", element: <Navigate to="/" replace /> },
]);
