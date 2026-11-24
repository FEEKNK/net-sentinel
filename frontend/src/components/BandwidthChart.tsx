import type { SnmpMetric } from "../types";

export function formatBps(bps: number): string {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(2)} Mbps`;
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`;
  return `${Math.round(bps)} bps`;
}

export function BandwidthChart({ metrics }: { metrics: SnmpMetric[] }) {
  if (metrics.length === 0) {
    return (
      <div className="flex h-48 items-center justify-center rounded-lg border border-dashed border-slate-800 text-xs text-slate-500">
        ยังไม่มีข้อมูล Bandwidth ในฐานข้อมูล — ระบบจะเก็บค่าทุก 5 วินาที หรือกด Poll ทันที
      </div>
    );
  }

  const width = 680;
  const height = 180;
  const padX = 12;
  const padY = 16;

  const maxBps = Math.max(
    1024,
    ...metrics.map((m) => Math.max(m.in_bps, m.out_bps))
  );

  const buildPoints = (selector: (m: SnmpMetric) => number) => {
    if (metrics.length === 1) {
      const y = height - padY - (selector(metrics[0]) / maxBps) * (height - padY * 2);
      return `${padX},${y.toFixed(1)} ${width - padX},${y.toFixed(1)}`;
    }
    return metrics
      .map((m, idx) => {
        const x = padX + (idx / (metrics.length - 1)) * (width - padX * 2);
        const y = height - padY - (selector(m) / maxBps) * (height - padY * 2);
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");
  };

  const inPoints = buildPoints((m) => m.in_bps);
  const outPoints = buildPoints((m) => m.out_bps);
  const latest = metrics[metrics.length - 1];

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-4">
          <span className="inline-flex items-center gap-1.5 text-cyan-300">
            <span className="h-2.5 w-2.5 rounded-full bg-cyan-400" />
            Inbound: <strong>{formatBps(latest.in_bps)}</strong>
          </span>
          <span className="inline-flex items-center gap-1.5 text-emerald-300">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400" />
            Outbound: <strong>{formatBps(latest.out_bps)}</strong>
          </span>
        </div>
        <span className="text-slate-400">Peak scale: {formatBps(maxBps)}</span>
      </div>

      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-44 w-full overflow-visible rounded-lg bg-slate-950/70 p-1"
        role="img"
        aria-label="Real-time network inbound and outbound bandwidth chart"
      >
        <line x1={padX} y1={height / 2} x2={width - padX} y2={height / 2} stroke="#1e293b" strokeDasharray="4 4" />
        <line x1={padX} y1={height - padY} x2={width - padX} y2={height - padY} stroke="#1e293b" />
        <polyline fill="none" stroke="#22d3ee" strokeWidth="2.5" strokeLinejoin="round" points={inPoints} />
        <polyline fill="none" stroke="#34d399" strokeWidth="2.5" strokeLinejoin="round" points={outPoints} />
      </svg>
    </div>
  );
}
