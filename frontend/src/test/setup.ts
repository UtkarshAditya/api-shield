import "@testing-library/jest-dom/vitest"; // matcher types for vitest
import { expect } from "vitest";
import * as matchers from "@testing-library/jest-dom/matchers";

// "@testing-library/jest-dom/vitest" does not register its matchers with Vitest 5, and with
// globals: true the global `expect` is a different instance from the imported one. Extend both.
expect.extend(matchers);
(globalThis as unknown as { expect?: typeof expect }).expect?.extend(matchers);

// jsdom gaps that Radix (tooltips, dialogs, switches) touches.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= ResizeObserverStub as unknown as typeof ResizeObserver;
if (typeof window !== "undefined") {
  window.HTMLElement.prototype.scrollIntoView ??= function scrollIntoView() {};
  window.HTMLElement.prototype.hasPointerCapture ??= () => false;
  window.HTMLElement.prototype.releasePointerCapture ??= () => {};
  window.matchMedia ??= ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as typeof window.matchMedia;
}
