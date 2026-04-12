import { useEffect } from "react";
import type { RealtimeEvent } from "../types";

type UseEventStreamOptions = {
  userId?: number;
  onEvent: (payload: RealtimeEvent) => void;
};

export function useEventStream({ userId, onEvent }: UseEventStreamOptions) {
  useEffect(() => {
    if (!userId) {
      return;
    }

    let source: EventSource | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let disposed = false;

    const connect = () => {
      if (disposed) return;

      source = new EventSource(`/events?userId=${userId}`);
      source.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as RealtimeEvent;
          if (payload && typeof payload === "object" && "type" in payload) {
            onEvent(payload);
          }
        } catch {
          // Ignore malformed events
        }
      };

      source.onerror = () => {
        source?.close();
        if (!disposed) {
          reconnectTimer = setTimeout(connect, 2500);
        }
      };
    };

    connect();

    return () => {
      disposed = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
      source?.close();
    };
  }, [userId, onEvent]);
}
