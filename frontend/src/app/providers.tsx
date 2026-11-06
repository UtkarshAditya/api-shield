import { useState, type ReactNode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { HttpError } from "@/api/client";
import { AuthProvider } from "@/auth/AuthContext";
import { ThemeProvider } from "@/theme/ThemeProvider";

export function Providers({ children }: { children: ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 10_000,
            refetchOnWindowFocus: false,
            retry: (count, err) => !(err instanceof HttpError && err.status < 500) && count < 2,
          },
        },
      }),
  );

  return (
    <QueryClientProvider client={client}>
      <ThemeProvider>
        <Tooltip.Provider delayDuration={200}>
          <AuthProvider>{children}</AuthProvider>
        </Tooltip.Provider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}
