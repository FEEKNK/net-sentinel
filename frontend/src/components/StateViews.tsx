import { AlertCircle, BookOpen, Inbox, Loader2, RefreshCw } from "lucide-react";

export function LoadingState({ message = "กำลังโหลดข้อมูลจริงจากระบบ…" }: { message?: string }) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex flex-col items-center justify-center rounded-xl border border-slate-800 bg-slate-900/60 p-10 text-slate-300"
    >
      <Loader2 className="h-7 w-7 animate-spin text-cyan-400" aria-hidden="true" />
      <p className="mt-3 text-sm">{message}</p>
    </div>
  );
}

export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry?: () => void;
}) {
  return (
    <div
      role="alert"
      className="rounded-xl border border-rose-500/40 bg-rose-950/30 p-6 text-rose-100"
    >
      <div className="flex items-start gap-3">
        <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-rose-400" aria-hidden="true" />
        <div className="min-w-0 flex-1">
          <h4 className="text-sm font-semibold">ไม่สามารถเชื่อมต่อ Backend หรือฐานข้อมูลได้</h4>
          <p className="mt-1 break-words text-xs leading-relaxed text-rose-200">{message}</p>
          {onRetry && (
            <button
              type="button"
              onClick={onRetry}
              className="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-rose-500/50 bg-rose-900/40 px-3 py-1.5 text-xs font-medium text-rose-100 transition-colors duration-150 hover:bg-rose-800/50"
            >
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
              ลองเชื่อมต่อใหม่
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  actionLabel,
  onAction,
}: {
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-slate-800 bg-slate-900/40 p-8 text-center">
      <Inbox className="h-8 w-8 text-slate-400" aria-hidden="true" />
      <h4 className="mt-3 text-sm font-semibold text-slate-200">{title}</h4>
      <p className="mt-1 max-w-md text-xs leading-relaxed text-slate-400">{description}</p>
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="mt-4 rounded-lg bg-cyan-600 px-3.5 py-2 text-xs font-semibold text-white transition-colors duration-150 hover:bg-cyan-500"
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}

export function LearnBanner({ title, summary }: { title: string; summary: string }) {
  return (
    <div className="rounded-xl border border-slate-800 bg-slate-900/60 px-4 py-3 text-xs leading-relaxed text-slate-300">
      <div className="flex items-start gap-2.5">
        <BookOpen className="mt-0.5 h-4 w-4 shrink-0 text-cyan-400" aria-hidden="true" />
        <div>
          <span className="font-semibold text-cyan-300">{title}: </span>
          <span>{summary}</span>
        </div>
      </div>
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: string }) {
  const sev = severity.toLowerCase();
  const styles: Record<string, string> = {
    critical: "border-rose-500/50 bg-rose-500/15 text-rose-300",
    high: "border-orange-500/50 bg-orange-500/15 text-orange-300",
    medium: "border-amber-500/50 bg-amber-500/15 text-amber-300",
    low: "border-sky-500/50 bg-sky-500/15 text-sky-300",
  };
  return (
    <span
      translate="no"
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${
        styles[sev] ?? "border-slate-600 bg-slate-800 text-slate-300"
      }`}
    >
      {sev}
    </span>
  );
}
