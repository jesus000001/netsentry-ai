import { Plus, X } from 'lucide-react';
import { useState } from 'react';
import type { FormEvent } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { getListAlertsQueryKey, useCreateAlert } from '@workspace/api-client-react';
import { Busy } from '@/components/ui-kit';

const initial = { signature: '', signatureId: '', classification: '', sourceIp: '', destIp: '', protocol: 'TCP', severity: 'medium', priority: 2, rawLog: '' };

export function AlertComposer() {
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState(initial);
  const create = useCreateAlert();
  const qc = useQueryClient();
  const submit = (event: FormEvent) => {
    event.preventDefault();
    create.mutate({ data: { ...form, priority: Number(form.priority), status: 'new' } as any }, { onSuccess: () => { qc.invalidateQueries({ queryKey: getListAlertsQueryKey() }); setForm(initial); setOpen(false); } });
  };
  return <>
    <button data-testid="button-compose-alert" onClick={() => setOpen(true)} className="hidden items-center gap-2 rounded-lg border border-slate-700 bg-slate-900/70 px-3 py-2 text-xs font-bold text-slate-300 transition hover:border-violet-400/40 hover:text-violet-200 sm:flex"><Plus size={14} /> Ingest alert</button>
    {open && <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/75 p-4 backdrop-blur-sm"><form onSubmit={submit} className="w-full max-w-xl rounded-2xl border border-slate-700 bg-[#0d1422] p-5 shadow-2xl"><div className="flex items-center justify-between"><div><h2 className="text-lg font-bold">Ingest Snort alert</h2><p className="mt-1 text-xs text-slate-500">Add a local event to the triage queue.</p></div><button type="button" data-testid="button-close-compose-alert" onClick={() => setOpen(false)} className="rounded-lg p-2 text-slate-500 hover:bg-slate-800"><X size={16}/></button></div><div className="mt-5 grid gap-3 sm:grid-cols-2">{[['signature','Signature'],['signatureId','Signature ID'],['classification','Classification'],['sourceIp','Source IP'],['destIp','Destination IP']].map(([key,label]) => <label key={key} className="text-xs text-slate-400">{label}<input data-testid={`input-alert-${key}`} required={key === 'signature' || key === 'sourceIp' || key === 'destIp'} value={(form as any)[key]} onChange={e => setForm({ ...form, [key]: e.target.value })} className="mt-1.5 h-9 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 text-xs text-slate-200 outline-none focus:border-violet-400/50"/></label>)}<label className="text-xs text-slate-400">Severity<select data-testid="select-alert-severity" value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })} className="mt-1.5 h-9 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 text-xs text-slate-200 outline-none"><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option></select></label><label className="text-xs text-slate-400">Protocol<select data-testid="select-alert-protocol" value={form.protocol} onChange={e => setForm({ ...form, protocol: e.target.value })} className="mt-1.5 h-9 w-full rounded-lg border border-slate-800 bg-slate-950/60 px-3 text-xs text-slate-200 outline-none"><option>TCP</option><option>UDP</option><option>ICMP</option><option>IP</option></select></label><label className="text-xs text-slate-400 sm:col-span-2">Raw log<textarea data-testid="input-alert-raw-log" value={form.rawLog} onChange={e => setForm({ ...form, rawLog: e.target.value })} className="mt-1.5 min-h-20 w-full rounded-lg border border-slate-800 bg-slate-950/60 p-3 font-mono text-[10px] text-slate-200 outline-none focus:border-violet-400/50"/></label></div><button data-testid="button-submit-alert" disabled={create.isPending} className="mt-5 flex w-full justify-center rounded-lg bg-violet-500 py-3 text-xs font-bold text-white hover:bg-violet-400 disabled:opacity-50">{create.isPending ? <Busy label="Saving alert"/> : 'Add to triage queue'}</button></form></div>}
  </>;
}