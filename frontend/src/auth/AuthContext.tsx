import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { setAuthToken, setUnauthorizedHandler } from "@/api/client";
import { authApi } from "@/api/endpoints";
import type { Me } from "@/api/schemas";
import { can as canFn, type Permission } from "./roles";

const STORAGE_KEY = "apishield.token";

type AuthState = {
  user: Me | null;
  status: "loading" | "authenticated" | "anonymous";
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  can: (p: Permission) => boolean;
};

const AuthContext = createContext<AuthState | null>(null);

function readToken() {
  try {
    return sessionStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
}

function writeToken(token: string | null) {
  try {
    if (token) sessionStorage.setItem(STORAGE_KEY, token);
    else sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable: session lives in memory only */
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [user, setUser] = useState<Me | null>(null);
  const [status, setStatus] = useState<AuthState["status"]>(() => (readToken() ? "loading" : "anonymous"));

  const logout = useCallback(() => {
    setAuthToken(null);
    writeToken(null);
    setUser(null);
    setStatus("anonymous");
    queryClient.clear();
  }, [queryClient]);

  useEffect(() => {
    setUnauthorizedHandler(logout);
    const token = readToken();
    if (!token) return;
    setAuthToken(token);
    authApi
      .me()
      .then((me) => {
        setUser(me);
        setStatus("authenticated");
      })
      .catch(() => logout());
    return () => setUnauthorizedHandler(null);
  }, [logout]);

  const login = useCallback(async (email: string, password: string) => {
    const res = await authApi.login(email, password);
    setAuthToken(res.token);
    writeToken(res.token);
    setUser(res.user);
    setStatus("authenticated");
  }, []);

  const value = useMemo<AuthState>(
    () => ({ user, status, login, logout, can: (p) => canFn(user?.role, p) }),
    [user, status, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider");
  return ctx;
}
