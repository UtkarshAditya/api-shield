import { Navigate, Outlet, useLocation } from "react-router-dom";
import { ShieldCheck } from "lucide-react";
import { useAuth } from "./AuthContext";

export function RequireAuth() {
  const { status } = useAuth();
  const location = useLocation();

  if (status === "loading") {
    return (
      <div className="grid min-h-screen place-items-center text-muted" role="status">
        <ShieldCheck className="size-8 animate-pulse text-accent" aria-hidden />
        <span className="sr-only">Restoring your session…</span>
      </div>
    );
  }
  if (status === "anonymous") return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Outlet />;
}
