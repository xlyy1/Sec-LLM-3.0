"use client";

import { useEffect, useRef } from "react";

interface AgentLogStreamProps {
  logs: string[];
  status: string | null;
  findingsCount: number;
}

export default function AgentLogStream({ logs, status, findingsCount }: AgentLogStreamProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  const getLogColor = (msg: string) => {
    if (msg.includes("[ERROR]") || msg.includes("[FATAL]")) return "text-red-400";
    if (msg.includes("[FINDING]")) return "text-yellow-400";
    if (msg.includes("[DONE]") || msg.includes("[REPORT]")) return "text-green-400";
    if (msg.includes("[EXEC]")) return "text-cyan-400";
    if (msg.includes("[PLAN]")) return "text-purple-400";
    return "text-gray-300";
  };

  return (
    <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <span className="text-green-400">&#9654;</span> Agent Log
        </h2>
        <div className="flex items-center gap-3 text-xs">
          {status && (
            <span
              className={`px-2 py-1 rounded ${
                status === "completed"
                  ? "bg-green-500/20 text-green-400"
                  : status === "failed"
                  ? "bg-red-500/20 text-red-400"
                  : "bg-yellow-500/20 text-yellow-400"
              }`}
            >
              {status}
            </span>
          )}
          <span className="text-gray-400">
            {findingsCount} finding{findingsCount !== 1 ? "s" : ""}
          </span>
        </div>
      </div>

      <div
        ref={containerRef}
        className="bg-slate-950 border border-white/5 rounded-lg p-3 h-80 overflow-y-auto font-mono text-xs space-y-0.5"
      >
        {logs.length === 0 && (
          <div className="text-gray-500 italic">Waiting for agent to start...</div>
        )}
        {logs.map((msg, i) => (
          <div key={i} className={getLogColor(msg)}>
            {msg}
          </div>
        ))}
      </div>
    </div>
  );
}
