import { useEffect, useMemo, useRef, useState } from "react";
import { Activity, Pause, Play, Radio, RefreshCw } from "lucide-react";
import { trafficApi } from "@/api/endpoints";
import type { Action, TrafficEvent } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { ActionBadge, actionMeaning } from "@/components/domain/ActionBadge";
import { EmptyState } from "@/components/domain/EmptyState";
import { CallerId } from "@/components/domain/MaskedValue";
import { WhyTooltip } from "@/components/domain/WhyTooltip";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { InlineError, Sheet } from "@/components/ui/Dialog";
import { describeError } from "@/lib/errors";
import { formatMs } from "@/lib/format";

/** The table keeps the newest MAX_ROWS events. That stays small enough to render without
 * virtualization; older events are on the Overview charts. */
export const MAX_ROWS = 300;
const ACTIONS: ("all" | Action)[] = ["all", "allow", "log", "block", "throttle", "challenge"];
const pastTense: Record<Action, string> = { allow: "allowed", log: "logged", block: "blocked", throttle: "throttled", challenge: "challenged" };
const selectCls ="h-8 rounded-md border border-border bg-surface-2 px-2 text-sm";

export function mergeEvents(current: TrafficEvent[], incoming: TrafficEvent[]): TrafficEvent[] {
  if (!incoming.length) return current;
  const seen = new Set(current.map((e) => e.req_id));
  const fresh = incoming.filter((e) => !seen.has(e.req_id));
  if (!fresh.length) return current;
  return [...fresh, ...current].sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, MAX_ROWS);
}

function useTrafficFeed(upstreamId: string | undefined, paused: boolean) {
  const [events, setEvents] = useState<TrafficEvent[]>([]);
  const [mode, setMode] = useState<"connecting" | "live" | "polling">("connecting");
  const [error, setError] = useState<string | null>(null);
  const pending = useRef<TrafficEvent[]>([]);

  useEffect(() => {
    setEvents([]);
  }, [upstreamId]);

  useEffect(() => {
    if (!upstreamId || paused) return;
    let cancelled = false;
    setMode("connecting");
    trafficApi
      .recent(upstreamId, 200)
      .then((r) => {
        if (!cancelled) {
          setError(null);
          setEvents((cur) => mergeEvents(cur, r.items));
        }
      })
      .catch((err) => !cancelled && setError(describeError(err)));
    // Batch stream deliveries so a burst of events is one render, not hundreds.
    const flush = setInterval(() => {
      if (pending.current.length) {
        const batch = pending.current;
        pending.current = [];
        setEvents((cur) => mergeEvents(cur, batch));
      }
    }, 500);
    const stop = trafficApi.subscribe(upstreamId, (e) => pending.current.push(e), setMode);
    return () => {
      cancelled = true;
      stop();
      clearInterval(flush);
      pending.current = [];
    };
  }, [upstreamId, paused]);

  return { events, mode, error };
}

function EventDrawer({ event, onClose }: { event: TrafficEvent | null; onClose: () => void }) {
  return (
    <Sheet open={!!event} onOpenChange={(v) => !v && onClose()} title="Request details" description="Metadata and rule hits only. Payload values never reach APIShield's storage.">
      {event && (
        <div className="space-y-5 text-sm">
          <dl className="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1.5">
            <dt className="text-muted">Endpoint</dt>
            <dd className="font-mono text-xs">
              {event.method} {event.path_template}
            </dd>
            <dt className="text-muted">Caller</dt>
            <dd>
              <CallerId value={event.caller} />
            </dd>
            <dt className="text-muted">Outcome</dt>
            <dd className="flex items-center gap-2">
              <ActionBadge action={event.action} /> <span className="tabular-nums">{event.status}</span>
            </dd>
            <dt className="text-muted">Latency</dt>
            <dd className="tabular-nums">{formatMs(event.latency_ms)}</dd>
            <dt className="text-muted">Shape</dt>
            <dd className="font-mono text-xs">
              {event.shape_hash}
              <span className="ml-1 font-sans text-muted">(field names and types, not values)</span>
            </dd>
          </dl>
          <section>
            <h3 className="mb-2 flex items-center gap-1 text-xs font-semibold text-muted">
              Rule hits
              <WhyTooltip label="What are rule hits?">
                The gateway rules and checks this request matched. In ENFORCE mode a block, throttle or challenge hit decides the outcome; in MONITOR mode they are only
                recorded.
              </WhyTooltip>
            </h3>
            {event.rule_hits.length ? (
              <ul className="space-y-1">
                {event.rule_hits.map((h) => (
                  <li key={h} className="rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs">
                    {h}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-muted">No rule matched this request.</p>
            )}
          </section>
        </div>
      )}
    </Sheet>
  );
}

export default function TrafficPage() {
  const { upstreamId } = useWorkspace();
  const [paused, setPaused] = useState(false);
  const [action, setAction] = useState<"all" | Action>("all");
  const [endpoint, setEndpoint] = useState("all");
  const [caller, setCaller] = useState("");
  const [selected, setSelected] = useState<TrafficEvent | null>(null);
  const { events, mode, error } = useTrafficFeed(upstreamId, paused);

  const endpoints = useMemo(() => [...new Set(events.map((e) => `${e.method} ${e.path_template}`))].sort(), [events]);
  const rows = useMemo(
    () =>
      events.filter(
        (e) =>
          (action === "all" || e.action === action) &&
          (endpoint === "all" || `${e.method} ${e.path_template}` === endpoint) &&
          (!caller.trim() || e.caller.includes(caller.trim())),
      ),
    [events, action, endpoint, caller],
  );

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Live traffic</h1>
          <p className="text-sm text-muted">Every request through the gateway, newest first. Callers are pseudonymized; payloads are never shown.</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="inline-flex items-center gap-1.5 text-xs text-muted" role="status">
            {paused ? (
              <>Paused</>
            ) : mode === "live" ? (
              <>
                <Radio className="size-3.5 text-act-allow" aria-hidden /> Live stream
              </>
            ) : (
              <>
                <RefreshCw className="size-3.5" aria-hidden /> {mode === "polling" ? "Refreshing every 2 s" : "Connecting…"}
              </>
            )}
          </span>
          <Button variant="secondary" size="sm" onClick={() => setPaused((p) => !p)} aria-pressed={paused}>
            {paused ? <Play className="size-3.5" aria-hidden /> : <Pause className="size-3.5" aria-hidden />}
            {paused ? "Resume" : "Pause"}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <label className="text-xs text-muted">
          <span className="mb-1 block">Action</span>
          <select value={action} onChange={(e) => setAction(e.target.value as "all" | Action)} className={selectCls}>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          <span className="mb-1 block">Endpoint</span>
          <select value={endpoint} onChange={(e) => setEndpoint(e.target.value)} className={selectCls}>
            <option value="all">all</option>
            {endpoints.map((ep) => (
              <option key={ep} value={ep}>
                {ep}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-muted">
          <span className="mb-1 block">Caller</span>
          <input value={caller} onChange={(e) => setCaller(e.target.value)} placeholder="key_… or ip_…" className={`${selectCls} w-44 font-mono`} />
        </label>
        <span className="ml-auto text-xs text-muted tabular-nums">
          {rows.length} of {events.length} shown (newest {MAX_ROWS} kept)
        </span>
      </div>

      {error && <InlineError message={error} />}

      <Card>
        {events.length === 0 ? (
          <EmptyState icon={Activity} title="Waiting for traffic" body="Send requests through the gateway (for example scripts/simulate_traffic.py) and they appear here." />
        ) : (
          <div className="max-h-[65vh] overflow-auto">
            <table className="w-full text-sm">
              <caption className="sr-only">Recent requests</caption>
              <thead className="sticky top-0 bg-surface">
                <tr className="text-left text-[11px] text-muted uppercase">
                  <th scope="col" className="px-4 py-2 font-medium">Time</th>
                  <th scope="col" className="px-4 py-2 font-medium">Endpoint</th>
                  <th scope="col" className="px-4 py-2 font-medium">Caller</th>
                  <th scope="col" className="px-4 py-2 font-medium">Status</th>
                  <th scope="col" className="px-4 py-2 font-medium">Action</th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Latency</th>
                  <th scope="col" className="px-4 py-2 font-medium">
                    <span className="sr-only">Details</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.req_id} className="border-t border-border/60">
                    <td className="px-4 py-1.5 text-xs whitespace-nowrap text-muted tabular-nums">{new Date(e.ts).toLocaleTimeString()}</td>
                    <td className="px-4 py-1.5 font-mono text-xs">
                      <span className="mr-1.5 text-muted">{e.method}</span>
                      {e.path_template}
                    </td>
                    <td className="px-4 py-1.5">
                      <CallerId value={e.caller} />
                    </td>
                    <td className="px-4 py-1.5 tabular-nums">{e.status}</td>
                    <td className="px-4 py-1.5">
                      <span className="inline-flex items-center gap-1">
                        <ActionBadge action={e.action} />
                        {e.action !== "allow" && (
                          <WhyTooltip label={`Why was this request ${pastTense[e.action]}?`}>
                            The gateway {actionMeaning[e.action]}
                            {e.rule_hits.length ? ` because it matched: ${e.rule_hits.join(", ")}.` : "."}
                          </WhyTooltip>
                        )}
                      </span>
                    </td>
                    <td className="px-4 py-1.5 text-right text-xs tabular-nums">{formatMs(e.latency_ms)}</td>
                    <td className="px-4 py-1.5 text-right">
                      <Button variant="ghost" size="sm" onClick={() => setSelected(e)}>
                        Rule hits ({e.rule_hits.length})
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <EventDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
