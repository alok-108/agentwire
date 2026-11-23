import React, { useEffect, useRef, useState } from "react";
import { TraceViewer } from "./components/TraceViewer";
import { FALLBACK_TRACES } from "./data/sampleTraces";
import { TraceEvent } from "./types";

export const App: React.FC = () => {
  const [events, setEvents] = useState<TraceEvent[]>(FALLBACK_TRACES);
  const [sourceLabel, setSourceLabel] = useState<string>("Built-in AW01 reference trace");
  const [liveConnected, setLiveConnected] = useState<boolean>(false);
  const sseRef = useRef<EventSource | null>(null);

  // Attempt to load freshly benchmark-exported `/sample-trace.jsonl` on mount
  useEffect(() => {
    let cancelled = false;
    fetch("/sample-trace.jsonl")
      .then((res) => {
        if (!res.ok) throw new Error("no sample trace file");
        return res.text();
      })
      .then((text) => {
        if (cancelled) return;
        const parsed: TraceEvent[] = [];
        for (const line of text.split(/\r?\n/)) {
          const trimmed = line.trim();
          if (!trimmed) continue;
          try {
            parsed.push(JSON.parse(trimmed) as TraceEvent);
          } catch {
            // Skip malformed line
          }
        }
        if (parsed.length > 0) {
          setEvents(parsed);
          setSourceLabel("public/sample-trace.jsonl (Rust AW01 benchmark capture)");
        }
      })
      .catch(() => {
        // Keep FALLBACK_TRACES cleanly
      });

    return () => {
      cancelled = true;
      sseRef.current?.close();
    };
  }, []);

  const handleConnectLive = (url: string) => {
    sseRef.current?.close();
    const es = new EventSource(url);
    sseRef.current = es;
    const liveBuffer: TraceEvent[] = [];

    es.onopen = () => {
      setLiveConnected(true);
      setSourceLabel(`Live SSE (${url})`);
    };

    es.onmessage = (msg) => {
      try {
        const parsed = JSON.parse(msg.data) as TraceEvent;
        liveBuffer.push(parsed);
        setEvents([...liveBuffer]);
      } catch {
        // Ignore keepalive or invalid messages
      }
    };

    es.onerror = () => {
      setLiveConnected(false);
      es.close();
      setSourceLabel(`SSE connection failed (${url}) — showing last loaded trace`);
    };
  };

  const handleDisconnectLive = () => {
    sseRef.current?.close();
    sseRef.current = null;
    setLiveConnected(false);
    setSourceLabel("Disconnected — showing captured session");
  };

  const handleUploadJsonl = (uploaded: TraceEvent[], filename: string) => {
    sseRef.current?.close();
    setLiveConnected(false);
    setEvents(uploaded);
    setSourceLabel(`Imported JSONL (${filename})`);
  };

  return (
    <TraceViewer
      events={events}
      sourceLabel={sourceLabel}
      liveConnected={liveConnected}
      onConnectLive={handleConnectLive}
      onDisconnectLive={handleDisconnectLive}
      onUploadJsonl={handleUploadJsonl}
    />
  );
};

export default App;
