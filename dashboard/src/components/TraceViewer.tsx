import React, { useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  Binary,
  CheckCircle2,
  Cpu,
  DollarSign,
  FileCode2,
  Filter,
  Radio,
  ShieldAlert,
  ShieldCheck,
  Upload,
  Zap,
} from "lucide-react";
import { TraceEvent } from "../types";

interface TraceViewerProps {
  events: TraceEvent[];
  sourceLabel: string;
  liveConnected: boolean;
  onConnectLive: (url: string) => void;
  onDisconnectLive: () => void;
  onUploadJsonl: (events: TraceEvent[], filename: string) => void;
}

const ACTION_COLORS: Record<string, string> = {
  QUERY: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  MUTATE: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  DELEGATE: "bg-violet-500/15 text-violet-300 border-violet-500/30",
  YIELD: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  ASSERT: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
};

interface HexByteInfo {
  hex: string;
  region: "magic" | "header" | "payload" | "crc32";
}

function annotateHexBytes(rawHex: string): HexByteInfo[] {
  const tokens = rawHex.trim().split(/\s+/).filter(Boolean);
  return tokens.map((hex, idx) => {
    if (idx < 4) return { hex, region: "magic" };
    if (idx < 10) return { hex, region: "header" };
    if (idx >= tokens.length - 4) return { hex, region: "crc32" };
    return { hex, region: "payload" };
  });
}

const REGION_STYLE: Record<HexByteInfo["region"], string> = {
  magic: "text-cyan-300 bg-cyan-500/15 border-cyan-500/30",
  header: "text-violet-300 bg-violet-500/10 border-violet-500/20",
  payload: "text-slate-300 bg-slate-800/60 border-slate-700/50",
  crc32: "text-emerald-300 bg-emerald-500/15 border-emerald-500/30",
};

export const TraceViewer: React.FC<TraceViewerProps> = ({
  events,
  sourceLabel,
  liveConnected,
  onConnectLive,
  onDisconnectLive,
  onUploadJsonl,
}) => {
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [statusFilter, setStatusFilter] = useState<"ALL" | "ALLOWED" | "REJECTED">("ALL");
  const [sseUrl, setSseUrl] = useState<string>("http://127.0.0.1:8765/api/stream");

  const filteredEvents = useMemo(() => {
    return events.filter((ev) => {
      if (statusFilter === "ALLOWED") return ev.allowed;
      if (statusFilter === "REJECTED") return !ev.allowed;
      return true;
    });
  }, [events, statusFilter]);

  const activeEvent =
    filteredEvents[Math.min(selectedIndex, Math.max(0, filteredEvents.length - 1))] ?? null;

  const stats = useMemo(() => {
    if (events.length === 0) {
      return {
        byteReductionPct: 0,
        tokenReductionPct: 0,
        usdSaved100k: 0,
        passed: 0,
        blocked: 0,
        avgLatencyUs: 0,
      };
    }
    const baseBytes = events.reduce((acc, e) => acc + e.baseline_bytes, 0);
    const wireBytes = events.reduce((acc, e) => acc + e.wire_bytes, 0);
    const baseTokens = events.reduce((acc, e) => acc + e.baseline_tokens, 0);
    const wireTokens = events.reduce((acc, e) => acc + e.wire_tokens, 0);
    const passed = events.filter((e) => e.allowed).length;
    const blocked = events.length - passed;
    const avgLatencyUs =
      events.reduce((acc, e) => acc + e.encode_us + e.validate_us + e.decompile_us, 0) /
      events.length;

    const avgSavedTokPerHop = Math.max(0, (baseTokens - wireTokens) / events.length);
    const usdSaved100k = ((avgSavedTokPerHop * 100_000) / 1_000_000) * 3.0;

    return {
      byteReductionPct: baseBytes > 0 ? (1 - wireBytes / baseBytes) * 100 : 0,
      tokenReductionPct: baseTokens > 0 ? (1 - wireTokens / baseTokens) * 100 : 0,
      usdSaved100k,
      passed,
      blocked,
      avgLatencyUs,
    };
  }, [events]);

  const annotatedHex = useMemo(
    () => (activeEvent ? annotateHexBytes(activeEvent.raw_hex) : []),
    [activeEvent]
  );

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const text = await file.text();
    const parsed: TraceEvent[] = [];
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        parsed.push(JSON.parse(trimmed) as TraceEvent);
      } catch {
        // Ignore malformed trailing lines
      }
    }
    if (parsed.length > 0) {
      onUploadJsonl(parsed, file.name);
      setSelectedIndex(0);
    }
    e.target.value = "";
  };

  return (
    <div className="min-h-screen bg-[#090d14] text-slate-100 flex flex-col">
      {/* Top Bar */}
      <header className="border-b border-slate-800/90 bg-[#0d131f]/95 backdrop-blur sticky top-0 z-20">
        <div className="max-w-[1600px] mx-auto px-5 py-3.5 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-violet-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Binary className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white">AgentWire</h1>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                  AW01 v1
                </span>
                <span className="text-xs text-slate-400 hidden sm:inline">
                  Binary RPC Wire Protocol &amp; Live AST Decompiler
                </span>
              </div>
              <p className="text-[11px] font-mono text-slate-400">Source: {sourceLabel}</p>
            </div>
          </div>

          {/* Stream Controls */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center bg-slate-900 border border-slate-700/80 rounded-lg overflow-hidden">
              <input
                type="text"
                value={sseUrl}
                onChange={(e) => setSseUrl(e.target.value)}
                className="bg-transparent text-xs font-mono text-slate-200 px-3 py-1.5 w-60 focus:outline-none"
                placeholder="http://127.0.0.1:8765/api/stream"
              />
              {liveConnected ? (
                <button
                  onClick={onDisconnectLive}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-rose-500/20 text-rose-300 hover:bg-rose-500/30 border-l border-slate-700/80 transition"
                >
                  <Radio className="w-3.5 h-3.5 animate-pulse" />
                  Disconnect
                </button>
              ) : (
                <button
                  onClick={() => onConnectLive(sseUrl)}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border-l border-slate-700/80 transition"
                >
                  <Radio className="w-3.5 h-3.5" />
                  Connect SSE
                </button>
              )}
            </div>

            <label className="cursor-pointer flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/90 hover:bg-slate-700/80 border border-slate-700 text-slate-200 transition">
              <Upload className="w-3.5 h-3.5 text-cyan-400" />
              Import JSONL
              <input
                type="file"
                accept=".jsonl,.json,.txt"
                onChange={handleFileChange}
                className="hidden"
              />
            </label>
          </div>
        </div>
      </header>

      <main className="max-w-[1600px] w-full mx-auto px-5 py-5 flex-1 flex flex-col gap-5">
        {/* KPI Stats Bar */}
        <section className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          <StatCard
            icon={<Zap className="w-4 h-4 text-emerald-400" />}
            label="Token Reduction"
            value={`${stats.tokenReductionPct.toFixed(1)}%`}
            sub="vs. verbose JSON handoffs"
            accent="text-emerald-400"
          />
          <StatCard
            icon={<Binary className="w-4 h-4 text-cyan-400" />}
            label="Wire Byte Reduction"
            value={`${stats.byteReductionPct.toFixed(1)}%`}
            sub="AW01 binary + static dict"
            accent="text-cyan-300"
          />
          <StatCard
            icon={<DollarSign className="w-4 h-4 text-amber-400" />}
            label="Est. Savings / 100k Hops"
            value={`$${stats.usdSaved100k.toFixed(2)}`}
            sub="@ $3.00 / 1M input tokens"
            accent="text-amber-300"
          />
          <StatCard
            icon={<ShieldCheck className="w-4 h-4 text-emerald-400" />}
            label="Policy Guard-Gate"
            value={`${stats.passed} ok / ${stats.blocked} blocked`}
            sub="Zero-cost pre-flight checks"
            accent={stats.blocked > 0 ? "text-rose-300" : "text-emerald-300"}
          />
          <StatCard
            icon={<Cpu className="w-4 h-4 text-violet-400" />}
            label="Avg Rust Pipeline"
            value={`${stats.avgLatencyUs.toFixed(1)} µs`}
            sub="Encode + Validate + Decompile"
            accent="text-violet-300"
          />
        </section>

        {/* Agent Hop Strip + Filter Bar */}
        <section className="bg-[#0e1524] border border-slate-800/90 rounded-xl p-4">
          <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h2 className="text-sm font-semibold text-slate-200">
                Multi-Agent Wire Hop Timeline
              </h2>
              <span className="text-xs font-mono text-slate-400">
                ({filteredEvents.length} frame{filteredEvents.length === 1 ? "" : "s"})
              </span>
            </div>

            <div className="flex items-center gap-1.5">
              <Filter className="w-3.5 h-3.5 text-slate-400 mr-1" />
              {(["ALL", "ALLOWED", "REJECTED"] as const).map((mode) => (
                <button
                  key={mode}
                  onClick={() => {
                    setStatusFilter(mode);
                    setSelectedIndex(0);
                  }}
                  className={`px-2.5 py-1 rounded-md text-xs font-mono transition border ${
                    statusFilter === mode
                      ? "bg-cyan-500/20 text-cyan-200 border-cyan-500/40"
                      : "bg-slate-900/70 text-slate-400 border-slate-800 hover:text-slate-200"
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
          </div>

          <div className="flex gap-2.5 overflow-x-auto pb-1">
            {filteredEvents.map((ev, idx) => {
              const isSelected = activeEvent === ev;
              const bytePct =
                ev.baseline_bytes > 0
                  ? ((1 - ev.wire_bytes / ev.baseline_bytes) * 100).toFixed(0)
                  : "0";
              return (
                <button
                  key={`${ev.trace_id}-${ev.span_id}-${idx}`}
                  onClick={() => setSelectedIndex(idx)}
                  className={`min-w-[240px] text-left rounded-lg p-3 border transition flex flex-col gap-1.5 ${
                    isSelected
                      ? ev.allowed
                        ? "bg-slate-800/90 border-cyan-400/70 shadow-lg shadow-cyan-500/10"
                        : "bg-rose-950/50 border-rose-500/70 shadow-lg shadow-rose-500/10"
                      : ev.allowed
                      ? "bg-slate-900/70 border-slate-800 hover:border-slate-700"
                      : "bg-rose-950/25 border-rose-900/60 hover:border-rose-700/70"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] font-mono text-slate-400">
                      span #{ev.span_id} · hop {ev.hop_depth}
                    </span>
                    {ev.allowed ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                        <CheckCircle2 className="w-3 h-3" />
                        PASS
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40">
                        <ShieldAlert className="w-3 h-3" />
                        BLOCKED
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-1.5 text-xs font-semibold text-white">
                    <span className="truncate">{ev.source_agent}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                    <span className="truncate">{ev.target_agent}</span>
                  </div>

                  <div className="flex items-center justify-between gap-2 mt-0.5">
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                        ACTION_COLORS[ev.action] ??
                        "bg-slate-800 text-slate-300 border-slate-700"
                      }`}
                    >
                      {ev.action}
                    </span>
                    <span className="text-[11px] font-mono text-slate-400">
                      {ev.wire_bytes}B <span className="text-emerald-400">(-{bytePct}%)</span>
                    </span>
                  </div>
                </button>
              );
            })}
          </div>
        </section>

        {/* Split Pane: Left = Raw Binary Wire Frame | Right = Lossless Human-Readable Decompiler */}
        {activeEvent ? (
          <section className="grid grid-cols-1 lg:grid-cols-2 gap-5 flex-1">
            {/* LEFT PANE: RAW WIRE FRAME */}
            <div className="bg-[#0e1524] border border-slate-800/90 rounded-xl flex flex-col overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-800 bg-[#111a2c] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Binary className="w-4 h-4 text-cyan-400" />
                  <h3 className="text-sm font-semibold text-white">
                    Raw Binary Wire Frame (AW01)
                  </h3>
                </div>
                <span className="text-xs font-mono text-cyan-300">
                  {activeEvent.wire_bytes} bytes · CRC32 verified
                </span>
              </div>

              <div className="p-4 flex flex-col gap-4 flex-1">
                {/* Compression Comparison Bar */}
                <div className="bg-slate-950/70 border border-slate-800 rounded-lg p-3.5 flex flex-col gap-2.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Payload Footprint Comparison</span>
                    <span className="font-mono text-emerald-400 font-semibold">
                      {(
                        (1 - activeEvent.wire_bytes / Math.max(1, activeEvent.baseline_bytes)) *
                        100
                      ).toFixed(1)}
                      % smaller on wire
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    <div>
                      <div className="flex justify-between text-[11px] font-mono text-slate-400 mb-1">
                        <span>Baseline Verbose JSON</span>
                        <span>
                          {activeEvent.baseline_bytes} B / {activeEvent.baseline_tokens} tok
                        </span>
                      </div>
                      <div className="w-full h-2 rounded bg-slate-800 overflow-hidden">
                        <div className="h-full bg-slate-500/80 w-full" />
                      </div>
                    </div>
                    <div>
                      <div className="flex justify-between text-[11px] font-mono text-cyan-300 mb-1">
                        <span>AgentWire AW01 Frame</span>
                        <span>
                          {activeEvent.wire_bytes} B / {activeEvent.wire_tokens} tok
                        </span>
                      </div>
                      <div className="w-full h-2 rounded bg-slate-800 overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-cyan-400 to-emerald-400"
                          style={{
                            width: `${Math.max(
                              4,
                              Math.min(
                                100,
                                (activeEvent.wire_bytes / Math.max(1, activeEvent.baseline_bytes)) *
                                  100
                              )
                            )}%`,
                          }}
                        />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Annotated Hex Dump */}
                <div className="flex flex-col gap-2">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono">
                    <span className="text-slate-400 uppercase tracking-wider">
                      Annotated Hex Bytes
                    </span>
                    <div className="flex items-center gap-2">
                      <LegendDot color="bg-cyan-400" label="Magic (AW01)" />
                      <LegendDot color="bg-violet-400" label="Header/Varints" />
                      <LegendDot color="bg-slate-400" label="Dict+AST" />
                      <LegendDot color="bg-emerald-400" label="CRC32" />
                    </div>
                  </div>
                  <div className="bg-[#070b12] border border-slate-800 rounded-lg p-3.5 font-mono text-xs leading-relaxed flex flex-wrap gap-1.5 max-h-60 overflow-y-auto">
                    {annotatedHex.map((b, i) => (
                      <span
                        key={i}
                        className={`px-1.5 py-0.5 rounded border text-[11px] ${REGION_STYLE[b.region]}`}
                      >
                        {b.hex}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Microsecond Timing Breakdown */}
                <div className="grid grid-cols-3 gap-2.5 mt-auto">
                  <TimingPill label="Encode" value={`${activeEvent.encode_us.toFixed(1)} µs`} />
                  <TimingPill
                    label="Policy Guard"
                    value={`${activeEvent.validate_us.toFixed(1)} µs`}
                  />
                  <TimingPill
                    label="Decompile"
                    value={`${activeEvent.decompile_us.toFixed(1)} µs`}
                  />
                </div>
              </div>
            </div>

            {/* RIGHT PANE: LOSSLESS DECOMPILED HUMAN TRACE */}
            <div className="bg-[#0e1524] border border-slate-800/90 rounded-xl flex flex-col overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-800 bg-[#111a2c] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <FileCode2 className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-semibold text-white">
                    Lossless Decompiled Human Trace
                  </h3>
                </div>
                <span className="text-xs font-mono text-slate-400">
                  {activeEvent.tokenizer}
                </span>
              </div>

              <div className="p-4 flex flex-col gap-4 flex-1">
                {/* Guard-Gate Verdict Banner */}
                {activeEvent.allowed ? (
                  <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3.5 flex items-start gap-3">
                    <ShieldCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-mono font-semibold text-emerald-300">
                        POLICY GUARD-GATE PASSED — GUARD_VERIFIED
                      </div>
                      <p className="text-xs text-emerald-100/80 mt-0.5">
                        Capability RBAC, hop depth ({activeEvent.hop_depth}), budget cap (
                        {activeEvent.budget_tokens} tok / ${activeEvent.budget_usd.toFixed(4)}),
                        and forbidden-field invariants verified in{" "}
                        {activeEvent.validate_us.toFixed(1)} µs.
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-lg border border-rose-500/40 bg-rose-500/15 p-3.5 flex items-start gap-3">
                    <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-mono font-semibold text-rose-300">
                        BLOCKED PRE-FLIGHT — {activeEvent.reason_code}
                      </div>
                      <p className="text-xs text-rose-100/90 mt-0.5">
                        {activeEvent.detail ?? "Frame violated deterministic safety policy."}
                      </p>
                      <p className="text-[11px] font-mono text-rose-300/80 mt-1">
                        Zero downstream LLM tokens spent · Intercepted in{" "}
                        {activeEvent.validate_us.toFixed(1)} µs
                      </p>
                    </div>
                  </div>
                )}

                {/* Human-Readable Narrative */}
                <div>
                  <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                    Human-Readable Projection
                  </div>
                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 text-sm text-slate-100 leading-relaxed">
                    {activeEvent.human_readable}
                  </div>
                </div>

                {/* Canonical 1:1 AST */}
                <div>
                  <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                    Canonical Semantic AST (1:1 Lossless)
                  </div>
                  <pre className="bg-[#070b12] border border-slate-800 rounded-lg p-3.5 text-xs font-mono text-cyan-200 whitespace-pre-wrap break-words">
                    {activeEvent.canonical_ast}
                  </pre>
                </div>

                {/* Structured Trace Lines */}
                <div className="mt-auto">
                  <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                    Structured Wire Telemetry
                  </div>
                  <pre className="bg-[#070b12] border border-slate-800 rounded-lg p-3.5 text-[11px] font-mono text-slate-300 whitespace-pre-wrap break-words leading-relaxed">
                    {activeEvent.structured_lines.join("\n")}
                  </pre>
                </div>
              </div>
            </div>
          </section>
        ) : (
          <div className="flex-1 flex items-center justify-center text-slate-500 font-mono text-sm">
            No frames match the selected filter.
          </div>
        )}
      </main>
    </div>
  );
};

const StatCard: React.FC<{
  icon: React.ReactNode;
  label: string;
  value: string;
  sub: string;
  accent: string;
}> = ({ icon, label, value, sub, accent }) => (
  <div className="bg-[#0e1524] border border-slate-800/90 rounded-xl p-3.5 flex flex-col gap-1">
    <div className="flex items-center justify-between text-xs text-slate-400">
      <span>{label}</span>
      {icon}
    </div>
    <div className={`text-xl font-bold font-mono tracking-tight ${accent}`}>{value}</div>
    <div className="text-[11px] text-slate-500">{sub}</div>
  </div>
);

const LegendDot: React.FC<{ color: string; label: string }> = ({ color, label }) => (
  <span className="inline-flex items-center gap-1 text-slate-400">
    <span className={`w-2 h-2 rounded-full ${color}`} />
    {label}
  </span>
);

const TimingPill: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="bg-slate-950/80 border border-slate-800 rounded-lg px-3 py-2 text-center">
    <div className="text-[10px] font-mono uppercase text-slate-500">{label}</div>
    <div className="text-sm font-mono font-semibold text-slate-100 mt-0.5">{value}</div>
  </div>
);
