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
