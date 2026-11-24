import { useEffect, useRef } from "react";
import type { AlertRecord, PacketSummary, SnmpMetric } from "../types";

export interface LiveHandlers {
  onAlert?: (alert: AlertRecord) => void;
  onPacket?: (packet: PacketSummary) => void;
  onSnmpMetric?: (metric: SnmpMetric) => void;
  onAnyEvent?: (type: string, data: unknown) => void;
  onConnectionChange?: (connected: boolean) => void;
}

export function useLiveSocket(handlers: LiveHandlers) {
  const handlersRef = useRef(handlers);
  handlersRef.current = handlers;

  useEffect(() => {
    let closed = false;
    let ws: WebSocket | null = null;
    let reconnectTimer: number | null = null;

    const connect = () => {
      if (closed) return;
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const url = `${protocol}//${window.location.host}/ws/live`;
      ws = new WebSocket(url);

      ws.onopen = () => {
        handlersRef.current.onConnectionChange?.(true);
      };

      ws.onmessage = (evt) => {
        try {
          const msg = JSON.parse(evt.data) as { type: string; data: unknown };
          if (msg.type === "alert") {
            handlersRef.current.onAlert?.(msg.data as AlertRecord);
          } else if (msg.type === "packet") {
            handlersRef.current.onPacket?.(msg.data as PacketSummary);
          } else if (msg.type === "snmp_metric") {
            handlersRef.current.onSnmpMetric?.(msg.data as SnmpMetric);
          }
          handlersRef.current.onAnyEvent?.(msg.type, msg.data);
        } catch {
          // Ignore malformed WS frame safely
        }
      };

      ws.onclose = () => {
        handlersRef.current.onConnectionChange?.(false);
        if (!closed) {
          reconnectTimer = window.setTimeout(connect, 3000);
        }
      };

      ws.onerror = () => {
        ws?.close();
      };
    };

    connect();

    return () => {
      closed = true;
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
      }
      if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        ws.close();
      }
    };
  }, []);
}
