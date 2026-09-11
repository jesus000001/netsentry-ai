import { ShieldOff } from 'lucide-react';
import { Link } from 'wouter';

export default function NotFound() {
  return <div className="grid min-h-[100dvh] place-items-center bg-[#080d18] px-5 text-center text-slate-100"><div><ShieldOff size={32} className="mx-auto mb-5 text-rose-300"/><div className="font-mono text-xs uppercase tracking-[.25em] text-slate-500">Signal lost · 404</div><h1 className="mt-3 text-3xl font-extrabold">This route does not exist.</h1><p className="mt-3 text-sm text-slate-500">The local workspace could not resolve that coordinate.</p><Link href="/" data-testid="link-return-overview" className="mt-7 inline-flex rounded-lg bg-violet-500 px-4 py-2.5 text-xs font-bold">Return to overview</Link></div></div>;
}
