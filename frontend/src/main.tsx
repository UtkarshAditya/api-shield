import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { RouterProvider } from "react-router-dom";
import "@/theme/tokens.css";
import { Providers } from "@/app/providers";
import { router } from "@/app/router";

async function enableMocks() {
  if (import.meta.env.VITE_USE_MOCKS !== "true") return;
  const { worker } = await import("@/mocks/browser");
  await worker.start({ onUnhandledRequest: "bypass", quiet: true });
}

enableMocks().then(() => {
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <Providers>
        <RouterProvider router={router} />
      </Providers>
    </StrictMode>,
  );
});
