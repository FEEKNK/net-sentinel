import { useEffect, useMemo, useState } from "react";
import { ArrowRight, Search, Server, ShieldAlert, X } from "lucide-react";
import type { AlertRecord, DeviceRecord, TabId } from "../types";

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
  navItems: Array<{ id: TabId; label: string }>;
  devices: DeviceRecord[];
  alerts: AlertRecord[];
  onSelectTab: (tab: TabId) => void;
  onInspectDevice: (ip: string) => void;
}

export function CommandPalette({
  open,
  onClose,
  navItems,
  devices,
  alerts,
  onSelectTab,
  onInspectDevice,
}: CommandPaletteProps) {
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (!open) {
      setQuery("");
      return;
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const q = query.trim().toLowerCase();

  const matchedTabs = useMemo(
    () =>
      navItems
        .filter((item) => !q || item.label.toLowerCase().includes(q) || item.id.includes(q))
        .slice(0, 6),
    [navItems, q]
  );

  const matchedDevices = useMemo(
    () =>
      devices
        .filter(
          (d) =>
            !q ||
            d.ip.toLowerCase().includes(q) ||
            d.mac.toLowerCase().includes(q) ||
            (d.custom_name || d.hostname || d.vendor || "").toLowerCase().includes(q)
        )
        .slice(0, 5),
    [devices, q]
  );

  const matchedAlerts = useMemo(
    () =>
      alerts
        .filter(
          (a) =>
            !q ||
            a.title.toLowerCase().includes(q) ||
            a.source_ip.toLowerCase().includes(q) ||
            a.detector_type.toLowerCase().includes(q)
        )
        .slice(0, 5),
    [alerts, q]
  );

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-slate-950/80 px-4 pt-20 backdrop-blur-xs"
      role="dialog"
      aria-modal="true"
      aria-labelledby="cmd-palette-title"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl rounded-xl border border-slate-700 bg-slate-900 shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-slate-800 px-4 py-3">
          <Search className="h-4 w-4 text-slate-400" aria-hidden="true" />
          <label id="cmd-palette-title" htmlFor="cmd-palette-input" className="sr-only">
            ค้นหาหน้า อุปกรณ์ IP และแจ้งเตือน
          </label>
          <input
            id="cmd-palette-input"
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="พิมพ์ชื่อหน้า, IP, MAC หรือคำค้นหาแจ้งเตือน (กด Esc เพื่อปิด)"
            className="w-full bg-transparent text-sm text-slate-100 placeholder:text-slate-500 focus:outline-none"
          />
          <button
            type="button"
            onClick={onClose}
            aria-label="ปิดหน้าต่างค้นหา"
            className="rounded-lg p-1 text-slate-400 hover:bg-slate-800 hover:text-white"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="max-h-96 space-y-4 overflow-y-auto p-4 text-sm">
          <div>
            <p className="mb-1.5 text-xs font-medium tracking-wide text-slate-400 uppercase">
              Navigation Tabs
            </p>
            <div className="grid grid-cols-1 gap-1 sm:grid-cols-2">
              {matchedTabs.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => {
                    onSelectTab(item.id);
                    onClose();
                  }}
                  className="flex items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-left text-slate-200 hover:border-cyan-500/40 hover:bg-slate-800"
                >
                  <span>{item.label}</span>
                  <ArrowRight className="h-3.5 w-3.5 text-slate-500" />
                </button>
              ))}
            </div>
          </div>

          {matchedDevices.length > 0 && (
            <div>
              <p className="mb-1.5 text-xs font-medium tracking-wide text-slate-400 uppercase">
                Devices (Open 360° Timeline)
              </p>
              <div className="space-y-1">
                {matchedDevices.map((d) => (
                  <button
                    key={d.ip}
                    type="button"
                    onClick={() => {
                      onInspectDevice(d.ip);
                      onClose();
                    }}
                    className="flex w-full items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-left hover:border-cyan-500/40 hover:bg-slate-800"
                  >
                    <span className="flex items-center gap-2">
                      <Server className="h-3.5 w-3.5 text-cyan-400" />
                      <span translate="no" className="font-mono text-xs text-slate-100 tabular-nums">
                        {d.ip}
                      </span>
                      <span className="text-xs text-slate-400">
                        {d.custom_name || d.hostname || d.vendor || "Unknown"}
                      </span>
                    </span>
                    <span translate="no" className="font-mono text-xs text-slate-500">
                      {d.mac}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {matchedAlerts.length > 0 && (
            <div>
              <p className="mb-1.5 text-xs font-medium tracking-wide text-slate-400 uppercase">
                Recent Alerts (Jump to IDS)
              </p>
              <div className="space-y-1">
                {matchedAlerts.map((a) => (
                  <button
                    key={a.id}
                    type="button"
                    onClick={() => {
                      onSelectTab("ids");
                      onClose();
                    }}
                    className="flex w-full items-center justify-between rounded-lg border border-slate-800 bg-slate-950/70 px-3 py-2 text-left hover:border-cyan-500/40 hover:bg-slate-800"
                  >
                    <span className="flex items-center gap-2 truncate">
                      <ShieldAlert className="h-3.5 w-3.5 shrink-0 text-amber-400" />
                      <span className="truncate text-slate-200">{a.title}</span>
                    </span>
                    <span translate="no" className="ml-2 shrink-0 font-mono text-xs text-slate-400 tabular-nums">
                      {a.source_ip}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
