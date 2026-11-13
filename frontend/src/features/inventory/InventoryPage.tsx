import { useEndpointInventory } from "@/api/queries";
import type { EndpointInventoryItem } from "@/api/schemas";
import { useWorkspace } from "@/app/WorkspaceContext";
import { EmptyState } from "@/components/domain/EmptyState";
import { SeverityMark, severityForScore } from "@/components/domain/SeverityBadge";
import { Term } from "@/components/domain/Term";
import { CardError } from "@/components/ui/Card";
import { DataTable, PageHeader, Td, Th, THead, Tr } from "@/components/ui/Primitives";
import { Skeleton } from "@/components/ui/Skeleton";
import { cn } from "@/lib/cn";
import { formatNumber } from "@/lib/format";

const sourceLabel: Record<EndpointInventoryItem["source"], string> = { spec: "spec only", observed: "observed only", both: "spec + traffic" };

/** Plain text with a small mark: filled = protected, hollow = not. */
function Flag({ on, yes, no }: { on: boolean; yes: string; no: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[13px]">
      <span aria-hidden className={cn("inline-block size-2 border", on ? "border-ok bg-ok" : "border-border-strong")} />
      <span className={on ? "text-fg" : "text-muted"}>{on ? yes : no}</span>
    </span>
  );
}

export default function InventoryPage() {
  const { upstreamId } = useWorkspace();
  const inv = useEndpointInventory(upstreamId);
  const items = inv.data?.items ?? [];
  const shadows = items.filter((i) => i.shadow).length;
  const maxReq = Math.max(1, ...items.map((i) => i.requests_24h));

  return (
    <div className="space-y-6">
      <PageHeader
        title="API map"
        description={
          <>
            Every endpoint from the OpenAPI spec and from traffic in the last 24 hours.
            {shadows > 0 && ` ${shadows} shadow endpoint${shadows === 1 ? "" : "s"}: called, but not documented.`}
          </>
        }
      />
      <div className="border-y border-border">
        {inv.isError ? (
          <CardError onRetry={() => inv.refetch()} />
        ) : inv.isLoading ? (
          <Skeleton className="my-4 h-60" />
        ) : items.length === 0 ? (
          <EmptyState title="0 endpoints" body="Configure an OpenAPI spec or send traffic through the gateway." />
        ) : (
          <DataTable caption="Endpoint inventory">
            <THead>
              <Th>Endpoint</Th>
              <Th>Source</Th>
              <Th>Auth</Th>
              <Th>Rate limit</Th>
              <Th>
                <Term tip="The latest scan's score for this endpoint (0 to 10). Applied mitigating rules lower it.">Risk</Term>
              </Th>
              <Th align="right" className="w-56">Requests 24 h</Th>
            </THead>
            <tbody>
              {items.map((e) => (
                <Tr key={`${e.method} ${e.path}`}>
                  <Td mono>
                    <span className="mr-2 inline-block w-14 text-muted">{e.method}</span>
                    {e.path}
                    {e.shadow && (
                      <Term tip="Seen in traffic but not in the OpenAPI spec. Undocumented endpoints are often forgotten and unprotected." className="ml-3">
                        <span className="font-mono text-[11px] font-medium tracking-wider text-signal uppercase">Shadow</span>
                      </Term>
                    )}
                  </Td>
                  <Td className="font-mono text-xs text-muted">{sourceLabel[e.source]}</Td>
                  <Td>
                    <Flag on={e.auth_required} yes="required" no="public" />
                  </Td>
                  <Td>
                    <Flag on={e.rate_limited} yes="limited" no="none" />
                  </Td>
                  <Td>
                    {e.risk_score > 0 ? (
                      <span className="inline-flex items-center gap-3">
                        <span className="w-8 font-mono text-[13px]">{e.risk_score.toFixed(1)}</span>
                        <SeverityMark severity={severityForScore(e.risk_score)} />
                      </span>
                    ) : (
                      <span className="font-mono text-xs text-muted">not scored</span>
                    )}
                  </Td>
                  <Td align="right">
                    <span className="relative inline-flex w-full justify-end">
                      <span aria-hidden className="absolute inset-y-0.5 right-0 bg-surface-2" style={{ width: `${(e.requests_24h / maxReq) * 100}%` }} />
                      <span className="relative pr-1 font-mono text-[13px]">{formatNumber(e.requests_24h)}</span>
                    </span>
                  </Td>
                </Tr>
              ))}
            </tbody>
          </DataTable>
        )}
      </div>
    </div>
  );
}
