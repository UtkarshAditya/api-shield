/**
 * Renders a dashboard screen against the MSW mock Admin API (the same handlers as mock mode),
 * signed in as a demo role, inside the real providers.
 */
import type { ReactElement, ReactNode } from "react";
import { render } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { setupServer } from "msw/node";
import { WorkspaceProvider } from "@/app/WorkspaceContext";
import { AuthProvider, useAuth } from "@/auth/AuthContext";
import type { Role } from "@/api/schemas";
import { handlers } from "@/mocks/handlers";
import { resetDb } from "@/mocks/db";

export const server = setupServer(...handlers);

/** Call once per test file: starts MSW and resets the mock store before every test. */
export function useMockApi() {
  beforeAll(() => server.listen({ onUnhandledRequest: "error" }));
  beforeEach(() => {
    resetDb();
    sessionStorage.clear();
  });
  afterEach(() => server.resetHandlers());
  afterAll(() => server.close());
}

function SignedIn({ children }: { children: ReactNode }) {
  const { status } = useAuth();
  return status === "authenticated" ? <WorkspaceProvider>{children}</WorkspaceProvider> : null;
}

type Options = { role?: Role; route?: string; path?: string; /** a real session token (live tests) */ token?: string };

export function renderScreen(ui: ReactElement, { role = "admin", route = "/", path = "*", token }: Options = {}) {
  sessionStorage.setItem("apishield.token", token ?? `mock.u_${role}`);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 0, refetchOnWindowFocus: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Tooltip.Provider delayDuration={0}>
        <AuthProvider>
          <SignedIn>
            <MemoryRouter initialEntries={[route]}>
              <Routes>
                <Route path={path} element={ui} />
                {path !== "*" && <Route path="*" element={<p>other route</p>} />}
              </Routes>
            </MemoryRouter>
          </SignedIn>
        </AuthProvider>
      </Tooltip.Provider>
    </QueryClientProvider>,
  );
}
