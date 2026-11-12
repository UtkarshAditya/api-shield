import { Check, EyeOff, Map, Minus } from "lucide-react";
import { useEndpointInventory } from "@/api/queries";
import type { EndpointInventoryItem } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { EmptyState } from "@/components/domain/EmptyState";
import { SeverityBadge, severityForScore } from "@/components/domain/SeverityBadge";
import { WhyTooltip } from "@/components/domain/WhyTooltip";
import { Card, CardError } from "@/components/ui/Card";
import { Skeleton } from "@/components/ui/Skeleton";
import { formatNumber } from "@/lib/format";

const sourceLabel: Record<EndpointInventoryItem["source"], string> = { spec: "Spec only", observed: "Observed only", both: "Spec + traffic" };

function YesNo({ value, yes, no }: { value: boolean; yes: string; no: string }) {
  return value ? (
    <span className="inline-flex items-center gap-1 text-act-allow">
      <Check className="size-3.5" aria-hidden /> {yes}
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 text-muted">
      <Minus className="size-3.5" aria-hidden /> {no}
    </span>
  );
}

export default function InventoryPage() {
  const { upstreamId } = useWorkspace();
  const inv = useEndpointInventory(upstreamId);
  const items = inv.data?.items ?? [];
  const shadows = items.filter((i) => i.shadow).length;

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">API map</h1>
        <p className="text-sm text-muted">
          Every endpoint from your OpenAPI spec and from traffic seen in the last 24 hours.
          {shadows > 0 && ` ${shadows} shadow endpoint${shadows === 1 ? "" : "s"} found: called, but not documented.`}
        </p>
      </div>
      <Card>
        {inv.isError ? (
          <CardError onRetry={() => inv.refetch()} />
        ) : inv.isLoading ? (
          <Skeleton className="m-5 h-60" />
        ) : items.length === 0 ? (
          <EmptyState icon={Map} title="No endpoints yet" body="Configure an OpenAPI spec or send traffic through the gateway." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <caption className="sr-only">Endpoint inventory</caption>
              <thead>
                <tr className="text-left text-[11px] text-muted uppercase">
                  <th scope="col" className="px-4 py-2 font-medium">Endpoint</th>
                  <th scope="col" className="px-4 py-2 font-medium">Source</th>
                  <th scope="col" className="px-4 py-2 font-medium">Auth</th>
                  <th scope="col" className="px-4 py-2 font-medium">Rate limit</th>
                  <th scope="col" className="px-4 py-2 font-medium">
                    <span className="inline-flex items-center gap-1">
                      Risk
                      <WhyTooltip label="Where does the risk come from?">The latest scan's score for this endpoint (0 to 10). Applied mitigating rules lower it.</WhyTooltip>
                    </span>
                  </th>
                  <th scope="col" className="px-4 py-2 text-right font-medium">Requests 24 h</th>
                </tr>
              </thead>
              <tbody>
                {items.map((e) => (
                  <tr key={`${e.method} ${e.path}`} className="border-t border-border/60">
                    <td className="px-4 py-2 font-mono text-xs">
                      <span className="mr-1.5 text-muted">{e.method}</span>
                      {e.path}
                      {e.shadow && (
                        <span className="ml-2 inline-flex items-center gap-1 rounded-full border border-sev-high/30 bg-sev-high/12 px-2 py-0.5 font-sans text-[11px] font-medium text-sev-high">
                          <EyeOff className="size-3" aria-hidden /> Shadow
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-xs text-muted">{sourceLabel[e.source]}</td>
                    <td className="px-4 py-2 text-xs">
                      <YesNo value={e.auth_required} yes="Required" no="Public" />
                    </td>
                    <td className="px-4 py-2 text-xs">
                      <YesNo value={e.rate_limited} yes="Limited" no="None" />
                    </td>
                    <td className="px-4 py-2">
                      {e.risk_score > 0 ? (
                        <span className="inline-flex items-center gap-2 tabular-nums">
                          {e.risk_score.toFixed(1)} <SeverityBadge severity={severityForScore(e.risk_score)} />
                        </span>
                      ) : (
                        <span className="text-xs text-muted">not scored</span>
                      )}
                    </td>
                    <td className="px-4 py-2 text-right tabular-nums">{formatNumber(e.requests_24h)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
