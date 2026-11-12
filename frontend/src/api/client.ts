/**
 * The only module that talks HTTP to the Admin API. Everything else calls the typed
 * functions in ./endpoints, so contract changes stay localized here and in schemas.ts.
 */
import type { z } from "zod";
import { ApiError } from "./schemas";

export const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

let authToken: string | null = null;
let onUnauthorized: (() => void) | null = null;

export function setAuthToken(token: string | null) {
  authToken = token;
}

export function setUnauthorizedHandler(fn: (() => void) | null) {
  onUnauthorized = fn;
}

export class HttpError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export class ContractError extends Error {
  constructor(path: string, issues: z.ZodIssue[]) {
    const detail = issues
      .slice(0, 5)
      .map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`)
      .join("; ");
    super(`Response from ${path} does not match the contract: ${detail}`);
    this.name = "ContractError";
  }
}

type Query = Record<string, string | number | boolean | undefined>;

type RequestOptions<S extends z.ZodTypeAny> = {
  schema: S;
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  query?: Query;
  signal?: AbortSignal;
};

function buildUrl(path: string, query?: Query) {
  const url = new URL(API_BASE + path, window.location.origin);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined) url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

type StreamOptions<S extends z.ZodTypeAny> = {
  path: string;
  query?: Query;
  event: string;
  schema: S;
  onEvent: (item: z.infer<S>) => void;
  onModeChange?: (mode: "live" | "polling") => void;
  /** Fallback when SSE is unavailable: fetch recent items, oldest first. */
  poll: () => Promise<z.infer<S>[]>;
  keyOf: (item: z.infer<S>) => string;
  pollMs?: number;
};

/**
 * Server-sent events with a polling fallback. EventSource cannot send headers, so the token
 * goes in `access_token` (the Admin API accepts it on the stream route only). If the stream
 * never opens or is closed for good, this switches to polling. Returns a stop function.
 */
export function openEventStream<S extends z.ZodTypeAny>(opts: StreamOptions<S>): () => void {
  let stopped = false;
  let source: EventSource | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const seen: string[] = [];

  const deliver = (item: z.infer<S>) => {
    const key = opts.keyOf(item);
    if (seen.includes(key)) return;
    seen.push(key);
    if (seen.length > 500) seen.shift();
    opts.onEvent(item);
  };

  const startPolling = () => {
    opts.onModeChange?.("polling");
    const tick = async () => {
      if (stopped) return;
      try {
        (await opts.poll()).forEach(deliver);
      } catch {
        // keep polling; the next tick may succeed
      }
      timer = setTimeout(tick, opts.pollMs ?? 3000);
    };
    void tick();
  };

  if (typeof EventSource === "undefined" || !authToken) {
    startPolling();
  } else {
    let opened = false;
    source = new EventSource(buildUrl(opts.path, { ...opts.query, access_token: authToken }));
    source.addEventListener("open", () => {
      opened = true;
      opts.onModeChange?.("live");
    });
    source.addEventListener(opts.event, (msg) => {
      const parsed = opts.schema.safeParse(JSON.parse((msg as MessageEvent<string>).data));
      if (parsed.success) deliver(parsed.data);
      else if (import.meta.env.DEV) console.error(new ContractError(opts.path, parsed.error.issues).message);
    });
    source.addEventListener("error", () => {
      if (!source || stopped) return;
      if (!opened || source.readyState === EventSource.CLOSED) {
        source.close();
        source = null;
        startPolling();
      }
    });
  }

  return () => {
    stopped = true;
    source?.close();
    clearTimeout(timer);
  };
}

export async function request<S extends z.ZodTypeAny>(path: string, opts: RequestOptions<S>): Promise<z.infer<S>> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (opts.body !== undefined) headers["Content-Type"] = "application/json";
  if (authToken) headers.Authorization = `Bearer ${authToken}`;

  const res = await fetch(buildUrl(path, opts.query), {
    method: opts.method ?? "GET",
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    signal: opts.signal,
  });

  const data: unknown = res.status === 204 ? null : await res.json().catch(() => null);

  if (!res.ok) {
    if (res.status === 401) onUnauthorized?.();
    const parsed = ApiError.safeParse(data);
    throw new HttpError(
      res.status,
      parsed.success ? parsed.data.error.code : "http_error",
      parsed.success ? parsed.data.error.message : `Request failed (${res.status})`,
    );
  }

  const parsed = opts.schema.safeParse(data);
  if (!parsed.success) {
    const err = new ContractError(path, parsed.error.issues);
    if (import.meta.env.DEV) console.error(err.message, data);
    throw err;
  }
  return parsed.data;
}
