import { useEffect, useMemo, useRef, useState } from "react";
import { Pause, Play } from "lucide-react";
import { trafficApi } from "@/api/endpoints";
import type { Action, TrafficEvent } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { ActionTag, actionMeaning } from "@/components/domain/ActionBadge";
import { EmptyState } from "@/components/domain/EmptyState";
import { CallerId } from "@/components/domain/MaskedValue";
import { Term } from "@/components/domain/Term";
import { Button } from "@/components/ui/Button";
import { InlineError, Sheet } from "@/components/ui/Dialog";
import { DataTable, PageHeader, StatusDot, Td, Th, THead, Tr } from "@/components/ui/Primitives";
import { describeError } from "@/lib/errors";
import { formatMs } from "@/lib/format";

/** The table keeps the newest MAX_ROWS events. That stays small enough to render without
 * virtualization; older events are on the Overview charts. */
export const MAX_ROWS = 300;
const ACTIONS: ("all" | Action)[] = ["all", "allow", "log", "block", "throttle", "challenge"];
const pastTense: Record<Action, string> = { allow: "allowed", log: "logged", block: "blocked", throttle: "throttled", challenge: "challenged" };
const selectCls = "h-8 rounded-sm border border-border-strong bg-surface px-2 text-sm";

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
          <dl className="border-t border-border">
            {(
              [
                ["Endpoint", <span className="font-mono text-[13px]">{event.method} {event.path_template}</span>],
                ["Caller", <CallerId value={event.caller} />],
                [
                  "Outcome",
                  <span className="flex items-center gap-3">
                    <ActionTag action={event.action} />
                    <span className="font-mono">{event.status}</span>
                  </span>,
                ],
                ["Latency", <span className="font-mono">{formatMs(event.latency_ms)}</span>],
                [
                  "Shape",
                  <span>
                    <span className="font-mono text-xs">{event.shape_hash}</span>
                    <span className="block text-xs text-muted">field names and types, not values</span>
                  </span>,
                ],
              ] as const
            ).map(([k, v]) => (
              <div key={k} className="grid grid-cols-[6rem_1fr] gap-x-3 border-b border-border py-2">
                <dt className="eyebrow pt-0.5">{k}</dt>
                <dd>{v}</dd>
              </div>
            ))}
          </dl>
          <section>
            <h3 className="eyebrow mb-2 text-fg">
              <Term tip="The gateway rules and checks this request matched. In ENFORCE a block, throttle or challenge hit decides the outcome; in MONITOR they are only recorded.">
                Rule hits
              </Term>
            </h3>
            {event.rule_hits.length ? (
              <ul className="border-t border-border">
                {event.rule_hits.map((h) => (
                  <li key={h} className="border-b border-border py-1.5 font-mono text-xs">
                    {h}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="font-mono text-xs text-muted">No rule matched this request.</p>
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
    <div className="space-y-6">
      <PageHeader
        title="Live traffic"
        description="Every request through the gateway, newest first. Callers are pseudonymized; payloads are never shown."
        actions={
          <>
            <span role="status" className="text-muted">
              {paused ? (
                <StatusDot>Paused</StatusDot>
              ) : mode === "live" ? (
                <StatusDot tone="ok">Live stream</StatusDot>
              ) : (
                <StatusDot tone="ink">{mode === "polling" ? "Refreshing every 2 s" : "Connecting…"}</StatusDot>
              )}
            </span>
            <Button variant="secondary" size="sm" onClick={() => setPaused((p) => !p)} aria-pressed={paused}>
              {paused ? <Play className="size-3.5" aria-hidden /> : <Pause className="size-3.5" aria-hidden />}
              {paused ? "Resume" : "Pause"}
            </Button>
          </>
        }
      />

      <div className="flex flex-wrap items-end gap-4 border-b border-border pb-4">
        <label>
          <span className="eyebrow mb-1 block">Action</span>
          <select value={action} onChange={(e) => setAction(e.target.value as "all" | Action)} className={selectCls}>
            {ACTIONS.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="eyebrow mb-1 block">Endpoint</span>
          <select value={endpoint} onChange={(e) => setEndpoint(e.target.value)} className={selectCls}>
            <option value="all">all</option>
            {endpoints.map((ep) => (
              <option key={ep} value={ep}>
                {ep}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="eyebrow mb-1 block">Caller</span>
          <input value={caller} onChange={(e) => setCaller(e.target.value)} placeholder="key_… or ip_…" className={`${selectCls} w-44 font-mono`} />
        </label>
        <span className="ml-auto font-mono text-xs text-muted">
          {rows.length} of {events.length} shown · newest {MAX_ROWS} kept
        </span>
      </div>

      {error && <InlineError message={error} />}

      {events.length === 0 ? (
        <EmptyState title="0 requests received" body="Send traffic through the gateway, for example scripts/simulate_traffic.py." />
      ) : (
        <div className="rounded-lg border border-border bg-surface">
          <DataTable caption="Recent requests" maxHeight="68vh">
            <THead framed>
              <Th>Time</Th>
              <Th>Endpoint</Th>
              <Th>Caller</Th>
              <Th align="right">Status</Th>
              <Th>Action</Th>
              <Th align="right">Latency</Th>
              <Th>
                <span className="sr-only">Details</span>
              </Th>
            </THead>
            <tbody>
              {rows.map((e) => (
                <Tr key={e.req_id}>
                  <Td mono className="text-xs whitespace-nowrap text-muted">
                    {new Date(e.ts).toLocaleTimeString()}
                  </Td>
                  <Td mono className="text-xs">
                    <span className="mr-1.5 text-muted">{e.method}</span>
                    {e.path_template}
                  </Td>
                  <Td>
                    <CallerId value={e.caller} />
                  </Td>
                  <Td align="right" mono className={e.status >= 400 ? "text-signal" : undefined}>
                    {e.status}
                  </Td>
                  <Td>
                    {e.action !== "allow" ? (
                      <Term tip={`The gateway ${actionMeaning[e.action]}${e.rule_hits.length ? ` because it matched: ${e.rule_hits.join(", ")}.` : "."}`}>
                        <ActionTag action={e.action} />
                        <span className="sr-only"> (why was this request {pastTense[e.action]}?)</span>
                      </Term>
                    ) : (
                      <ActionTag action={e.action} />
                    )}
                  </Td>
                  <Td align="right" mono className="text-xs">
                    {formatMs(e.latency_ms)}
                  </Td>
                  <Td align="right">
                    <Button variant="ghost" size="sm" onClick={() => setSelected(e)}>
                      Rule hits ({e.rule_hits.length})
                    </Button>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </DataTable>
        </div>
      )}
      <EventDrawer event={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
