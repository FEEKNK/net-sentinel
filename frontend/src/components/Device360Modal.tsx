import { useEffect, useState } from "react";
import { Activity, Clock, ShieldAlert, X } from "lucide-react";
import { api } from "../api";
import type { Device360Response } from "../types";
import { ErrorState, LoadingState, SeverityBadge } from "./StateViews";

interface Device360ModalProps {
  ip: string | null;
  onClose: () => void;
}

export function Device360Modal({ ip, onClose }: Device360ModalProps) {
  const [data, setData] = useState<Device360Response | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!ip) {
      setData(null);
      return;
    }
    const ctrl = new AbortController();
    setLoading(true);
    setError(null);
    api
      .getDevice360(ip, ctrl.signal)
      .then((res) => setData(res))
      .catch((err) => {
        if ((err as Error).name !== "AbortError") {
          setError(err instanceof Error ? err.message : "Failed to load device timeline");
        }
      })
      .finally(() => setLoading(false));

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => {
      ctrl.abort();
      window.removeEventListener("keydown", onKey);
    };
  }, [ip, onClose]);

  if (!ip) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-end bg-slate-950/80 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="device-360-title"
      onClick={onClose}
    >
      <div
        className="flex h-full w-full max-w-xl flex-col border-l border-slate-800 bg-slate-900 p-6 shadow-2xl overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div>
            <h2 id="device-360-title" className="text-base font-bold text-slate-100">
              Device 360° Timeline
            </h2>
            <p translate="no" className="font-mono text-xs text-cyan-300 tabular-nums">
              {ip}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="ปิดหน้าต่าง 360 Timeline"
            className="rounded-lg p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-4 space-y-5 text-xs">
          {loading && <LoadingState message="กำลังโหลดประวัติอุปกรณ์ 360°…" />}
          {error && <ErrorState message={error} />}

          {!loading && !error && data && (
            <>
              <div className="grid grid-cols-2 gap-3 rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div>
                  <span className="text-slate-400">Hostname / Label</span>
                  <p className="mt-0.5 font-medium text-slate-100">
                    {data.device?.custom_name || data.device?.hostname || "-"}
                  </p>
                </div>
                <div>
                  <span className="text-slate-400">MAC / Vendor</span>
                  <p translate="no" className="mt-0.5 font-mono text-slate-200">
                    {data.device?.mac || "-"}
                  </p>
                  <p className="text-[11px] text-slate-500">{data.device?.vendor || ""}</p>
                </div>
                <div>
                  <span className="text-slate-400">Risk Grade</span>
                  <p className="mt-0.5 font-mono font-semibold text-amber-300 tabular-nums">
                    Grade {data.risk.risk_grade} (Score: {data.risk.risk_score})
                  </p>
                </div>
                <div>
                  <span className="text-slate-400">Open Ports</span>
                  <p translate="no" className="mt-0.5 font-mono text-slate-300 tabular-nums">
                    {data.device?.open_ports?.length
                      ? data.device.open_ports.map((p) => `${p.port}/${p.service}`).join(", ")
                      : "None"}
                  </p>
                </div>
              </div>

              {data.risk.risk_reasons.length > 0 && (
                <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-amber-200">
                  <p className="font-semibold">Risk Factors:</p>
                  <ul className="mt-1 list-disc pl-4 space-y-0.5">
                    {data.risk.risk_reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="space-y-2">
                <h3 className="flex items-center gap-1.5 text-sm font-semibold text-slate-100">
                  <ShieldAlert className="h-4 w-4 text-rose-400" />
                  Related Alerts ({data.alerts.length})
                </h3>
                {data.alerts.length === 0 ? (
                  <p className="text-slate-500">ไม่พบ Alert ที่เกี่ยวข้องกับ IP นี้</p>
                ) : (
                  <div className="space-y-2">
                    {data.alerts.slice(0, 15).map((a) => (
                      <div
                        key={a.id}
                        className="rounded-lg border border-slate-800 bg-slate-950/60 p-3"
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-medium text-slate-100">{a.title}</span>
                          <SeverityBadge severity={a.severity} />
                        </div>
                        <p className="mt-1 text-slate-400">{a.description}</p>
                        <p className="mt-1 font-mono text-[11px] text-slate-500 tabular-nums">
                          {new Date(a.timestamp).toLocaleString()}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <h3 className="flex items-center gap-1.5 text-sm font-semibold text-slate-100">
                  <Clock className="h-4 w-4 text-cyan-400" />
                  Availability &amp; Latency History ({data.history.length})
                </h3>
                {data.history.length === 0 ? (
                  <p className="text-slate-500">ยังไม่มีประวัติการตรวจ Latency</p>
                ) : (
                  <div className="max-h-56 divide-y divide-slate-800 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950/60 px-3">
                    {data.history.slice(0, 25).map((h) => (
                      <div key={h.id} className="flex items-center justify-between py-1.5 tabular-nums">
                        <span className="flex items-center gap-1.5">
                          <Activity className="h-3 w-3 text-slate-500" />
                          <span
                            className={h.status === "online" ? "text-emerald-300" : "text-slate-400"}
                          >
                            {h.status}
                          </span>
                        </span>
                        <span translate="no" className="font-mono text-slate-300">
                          {h.latency_ms !== null ? `${h.latency_ms} ms` : "-"}
                        </span>
                        <span className="text-[11px] text-slate-500">
                          {new Date(h.recorded_at).toLocaleString()}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
