import { ArrowDown, ArrowUp, CircleDot, Database, FileSearch, Radio, ShieldCheck } from 'lucide-react';
import { useListAlerts } from '@workspace/api-client-react';
import { EmptyBlock, ErrorBlock, formatTime, LoadingBlock, PageTitle, Surface } from '@/components/ui-kit';

// Rqm hqiqi: 'ddad l qwa3id l fa3lin f local.rules (khdim b sudo grep -cE "^alert|^drop|^pass|^reject" /etc/snort/rules/local.rules)
const ACTIVE_SNORT_RULES = 2;

export default function Traffic() {
  const alerts = useListAlerts(
  { limit: 50 },
  {
    query: {
      queryKey: ['/api/alerts', { limit: 50 }],
      refetchInterval: 5000,
      refetchIntervalInBackground: true,
    },
  },
);

  const totalAlerts = alerts.data?.length ?? 0;
  const pendingAI = alerts.data?.filter((a: any) => a.status === 'new').length ?? 0;
  const recentPackets = (alerts.data ?? []).slice(0, 8);

  const stages = [
    { label: 'Snort rules', icon: ShieldCheck, value: String(ACTIVE_SNORT_RULES), color: 'fuchsia' },
    { label: 'Detections', icon: FileSearch, value: String(totalAlerts), color: 'amber' },
    { label: 'AI queue', icon: Database, value: String(pendingAI), color: 'emerald' },
  ];

  return (
    <div className="animate-rise">
      <PageTitle
        eyebrow="Telemetry / packet flow"
        title="Traffic monitor"
        description="Watch the local sensor turn raw network traffic into prioritized decisions."
        action={
          <div className="flex items-center gap-2 rounded-lg border border-emerald-400/20 bg-emerald-400/5 px-3 py-2 text-xs font-semibold text-emerald-300">
            <Radio size={14} className="animate-pulse" /> Live from Snort
          </div>
        }
      />
      <Surface className="mb-5 overflow-hidden p-5">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <div className="text-sm font-bold">Detection pipeline</div>
            <div className="mt-1 text-xs text-slate-500">Sourced from local Snort sensor + AI triage</div>
          </div>
          <div className="font-mono text-[10px] text-slate-600">SENSOR / NS-LOCAL-01</div>
        </div>
        <div className="grid gap-3 md:grid-cols-3">
          {stages.map((stage, index) => {
            const Icon = stage.icon;
            return (
              <div key={stage.label} className="relative">
                <div className="rounded-xl border border-slate-800 bg-slate-900/60 p-4">
                  <div className={`mb-5 flex h-8 w-8 items-center justify-center rounded-lg bg-${stage.color}-400/10 text-${stage.color}-300`}>
                    <Icon size={16} />
                  </div>
                  <div className="font-mono text-xl font-medium">{stage.value}</div>
                  <div className="mt-1 text-xs text-slate-500">{stage.label}</div>
                </div>
                {index < stages.length - 1 && (
                  <div className="absolute -right-3 top-1/2 z-10 hidden text-slate-600 md:block">
                    <ArrowUp size={15} className="rotate-90" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Surface>
      <div className="grid gap-5 lg:grid-cols-[1.4fr_1fr]">
        <Surface className="overflow-hidden">
          <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
            <div className="flex items-center gap-2">
              <CircleDot size={15} className="text-emerald-300" />
              <span className="text-sm font-bold">Recent detections</span>
            </div>
            <span className="font-mono text-[10px] text-slate-500">FROM SNORT LOG</span>
          </div>
          {alerts.isLoading ? (
            <div className="p-5">
              <LoadingBlock />
            </div>
          ) : alerts.isError ? (
            <div className="p-5">
              <ErrorBlock retry={() => alerts.refetch()} />
            </div>
          ) : recentPackets.length === 0 ? (
            <div className="p-5">
              <EmptyBlock title="No traffic yet" body="Waiting for Snort to observe activity." />
            </div>
          ) : (
            <div className="divide-y divide-slate-800/70">
              {recentPackets.map((packet: any, index: number) => (
                <div
                  key={packet.id ?? index}
                  data-testid={`row-packet-${index}`}
                  className="grid grid-cols-[105px_1fr_1fr_45px] items-center gap-3 px-5 py-3 font-mono text-[10px]"
                >
                  <span className="text-slate-600">{formatTime(packet.detectedAt)}</span>
                  <span className="truncate text-slate-400">
                    {packet.sourceIp}
                    {packet.sourcePort ? `:${packet.sourcePort}` : ''}
                  </span>
                  <span className="truncate text-slate-400">
                    {packet.destIp}
                    {packet.destPort ? `:${packet.destPort}` : ''}
                  </span>
                  <span className="text-sky-300">{packet.protocol}</span>
                </div>
              ))}
            </div>
          )}
        </Surface>
        <Surface className="p-5">
          <div className="text-sm font-bold">Signal health</div>
          <div className="mt-1 text-xs text-slate-500">Everything required to make a decision is online.</div>
          <div className="mt-6 space-y-4">
            {[
              ['Snort engine', 'Running', 'text-emerald-300'],
              ['Active rules', String(ACTIVE_SNORT_RULES), 'text-violet-300'],
              ['Total detections', String(totalAlerts), 'text-sky-300'],
              ['Pending AI review', String(pendingAI), 'text-amber-300'],
            ].map(([label, value, tone]) => (
              <div key={label} className="flex items-center justify-between border-b border-slate-800/80 pb-3 text-xs">
                <span className="text-slate-500">{label}</span>
                <span className={tone as string}>{value}</span>
              </div>
            ))}
          </div>
          <div className="mt-6 rounded-lg border border-sky-400/10 bg-sky-400/5 p-3 text-xs leading-5 text-sky-200">
            <ArrowDown size={14} className="mb-2" />
            No packet leaves this workspace. Raw traffic remains local until you choose to export it.
          </div>
        </Surface>
      </div>
    </div>
  );
}
