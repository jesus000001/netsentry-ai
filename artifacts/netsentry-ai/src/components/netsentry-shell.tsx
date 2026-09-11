import { Activity, AlertTriangle, BrainCircuit, ChevronRight, Cpu, FileCode2, LayoutDashboard, Network, Radio, Search, Server, ShieldCheck, Terminal, X } from 'lucide-react';
import { Link, useLocation } from 'wouter';
import { useState, type ReactNode } from 'react';
import { AlertComposer } from '@/components/alert-composer';

const nav = [
  { href: '/', label: 'Overview', icon: LayoutDashboard },
  { href: '/traffic', label: 'Traffic monitor', icon: Network },
  { href: '/snort', label: 'Snort alerts', icon: AlertTriangle },
  { href: '/logs', label: 'Raw logs', icon: Terminal },
  { href: '/ai-model', label: 'AI model', icon: BrainCircuit },
  { href: '/analysis', label: 'Analysis', icon: FileCode2 },
  { href: '/machines', label: 'Machines', icon: Server },
];

export function WorkspaceShell({ children }: { children: ReactNode }) {
  const [location] = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  return (
    <div className="min-h-[100dvh] bg-[#080d18] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -left-24 -top-32 h-80 w-80 rounded-full bg-violet-600/10 blur-3xl" />
        <div className="absolute right-0 top-1/3 h-96 w-96 rounded-full bg-sky-500/8 blur-3xl" />
        <div className="netsentry-grid absolute inset-0 opacity-35" />
      </div>
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-[240px] flex-col border-r border-slate-800/80 bg-[#090f1c]/90 px-4 py-5 backdrop-blur-xl lg:flex">
        <Brand />
        <div className="mt-8 mb-3 px-3 text-[10px] font-bold uppercase tracking-[.22em] text-slate-500">Operations</div>
        <nav className="space-y-1">
          {nav.map((item) => <NavItem key={item.href} item={item} active={location === item.href} />)}
        </nav>
        <div className="mt-auto space-y-4">
          <div className="rounded-xl border border-emerald-400/15 bg-emerald-400/5 p-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-emerald-300"><Radio size={13} className="animate-pulse" /> Local sensor online</div>
            <div className="mt-2 font-mono text-[10px] text-slate-500">127.0.0.1 · encrypted</div>
          </div>
          <div className="flex items-center gap-3 rounded-xl border border-slate-800 bg-slate-900/40 p-3">
            <div className="grid h-8 w-8 place-items-center rounded-lg bg-gradient-to-br from-violet-500 to-fuchsia-500 text-xs font-bold text-white">SO</div>
            <div className="min-w-0"><div className="truncate text-xs font-semibold">Security operator</div><div className="font-mono text-[10px] text-slate-500">LOCAL WORKSPACE</div></div>
          </div>
        </div>
      </aside>
      {mobileOpen && <div className="fixed inset-0 z-30 bg-slate-950/70 lg:hidden" onClick={() => setMobileOpen(false)} />}
      <aside className={`fixed inset-y-0 left-0 z-40 w-[250px] border-r border-slate-800 bg-[#090f1c] px-4 py-5 transition-transform lg:hidden ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex items-center justify-between"><Brand /><button data-testid="button-close-mobile-nav" onClick={() => setMobileOpen(false)} className="rounded-md p-2 text-slate-500 hover:bg-slate-800 hover:text-white"><X size={17} /></button></div>
        <nav className="mt-8 space-y-1">{nav.map((item) => <NavItem key={item.href} item={item} active={location === item.href} onClick={() => setMobileOpen(false)} />)}</nav>
      </aside>
      <main className="relative min-h-[100dvh] lg:pl-[240px]">
        <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-slate-800/70 bg-[#080d18]/80 px-4 backdrop-blur-xl sm:px-7">
          <div className="flex items-center gap-3"><button data-testid="button-open-mobile-nav" onClick={() => setMobileOpen(true)} className="rounded-lg border border-slate-800 p-2 text-slate-400 lg:hidden"><Activity size={17} /></button><div className="hidden items-center gap-2 text-xs text-slate-500 sm:flex"><span className="h-1.5 w-1.5 rounded-full bg-emerald-400" /> Workspace protected <ChevronRight size={14} /> <span className="text-slate-300">Local instance</span></div></div>
          <div className="flex items-center gap-2 text-xs text-slate-500"><Search size={15} /><span className="hidden sm:inline">⌘ K to search</span><AlertComposer /><div className="ml-2 rounded-md border border-slate-700 bg-slate-900 px-2 py-1 font-mono text-[10px] text-slate-400">v0.8.4</div></div>
        </header>
        <div className="border-b border-slate-800/70 px-4 py-3 lg:hidden overflow-x-auto"><div className="flex min-w-max gap-2">{nav.map((item) => <NavItem key={item.href} item={item} active={location === item.href} compact />)}</div></div>
        <div className="mx-auto max-w-[1540px] p-4 sm:p-7">{children}</div>
      </main>
    </div>
  );
}

function Brand() {
  return <Link href="/" data-testid="link-brand" className="flex items-center gap-3"><div className="relative grid h-9 w-9 place-items-center rounded-xl bg-gradient-to-br from-violet-500 via-fuchsia-500 to-sky-400 shadow-lg shadow-violet-500/20"><ShieldCheck size={19} className="text-white" /></div><div><div className="text-sm font-extrabold tracking-tight text-white">NetSentry<span className="text-fuchsia-400">.AI</span></div><div className="font-mono text-[9px] uppercase tracking-[.2em] text-slate-500">security cockpit</div></div></Link>;
}

function NavItem({ item, active, onClick, compact }: { item: typeof nav[number]; active: boolean; onClick?: () => void; compact?: boolean }) {
  const Icon = item.icon;
  return <Link href={item.href} onClick={onClick} data-testid={`link-nav-${item.label.toLowerCase().replaceAll(' ', '-')}`} className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-semibold transition-all ${active ? 'bg-violet-500/15 text-violet-200 ring-1 ring-violet-400/20' : 'text-slate-500 hover:bg-slate-800/70 hover:text-slate-200'} ${compact ? 'whitespace-nowrap px-3' : ''}`}><Icon size={16} className={active ? 'text-violet-300' : 'text-slate-500'} /><span>{item.label}</span>{active && !compact && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-fuchsia-400" />}</Link>;
}