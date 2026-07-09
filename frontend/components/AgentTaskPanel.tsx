"use client";

import { useEffect, useRef, useState } from "react";
import { runAgentTask, createAgentStream } from "@/lib/agent-api";

interface AgentTaskPanelProps {
  onTaskStart: (sessionId: string) => void;
  onLog: (msg: string) => void;
  onDone: (status: string, findingsCount: number) => void;
}

export default function AgentTaskPanel({ onTaskStart, onLog, onDone }: AgentTaskPanelProps) {
  const [target, setTarget] = useState("");
  const [taskType, setTaskType] = useState("web_scan");
  const [provider, setProvider] = useState("local");
  const [running, setRunning] = useState(false);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const streamRef = useRef<AbortController | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    return () => {
      mountedRef.current = false;
      streamRef.current?.abort();
    };
  }, []);

  const handleSubmit = async () => {
    if (!target.trim()) return;
    setError(null);
    setRunning(true);
    try {
      const result = await runAgentTask({ target: target.trim(), task_type: taskType, provider });
      if (!mountedRef.current) return;
      setSessionId(result.session_id);
      onTaskStart(result.session_id);

      // Close previous stream if any
      streamRef.current?.abort();
      // Start new SSE stream
      streamRef.current = createAgentStream(
        result.session_id,
        (msg) => { if (mountedRef.current) onLog(msg); },
        (status, count) => {
          if (mountedRef.current) { onDone(status, count); setRunning(false); }
        },
        (err) => {
          if (mountedRef.current) { setError(err); setRunning(false); }
        }
      );
    } catch (e: any) {
      if (mountedRef.current) { setError(e.message || "Failed to start agent task"); setRunning(false); }
    }
  };

  return (
    <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6 space-y-4">
      <h2 className="text-lg font-semibold text-white flex items-center gap-2">
        <span className="text-cyan-400">&#9878;</span> Agent Task
      </h2>

      {/* Target input */}
      <div>
        <label className="text-xs text-gray-400 mb-1 block">Target</label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="https://example.com or 192.168.1.1 or path/to/code"
          className="w-full px-3 py-2 bg-slate-800 border border-white/5 rounded-lg text-white text-sm placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
          disabled={running}
        />
      </div>

      {/* Task type + provider */}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="text-xs text-gray-400 mb-1 block">Task Type</label>
          <select
            value={taskType}
            onChange={(e) => setTaskType(e.target.value)}
            className="w-full px-3 py-2 bg-slate-800 border border-white/5 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            disabled={running}
          >
            <option value="web_scan">Web Scan</option>
            <option value="code_audit">Code Audit</option>
            <option value="threat_intel">Threat Intel</option>
            <option value="comprehensive">Comprehensive</option>
          </select>
        </div>
        <div>
          <label className="text-xs text-gray-400 mb-1 block">LLM Provider</label>
          <select
            value={provider}
            onChange={(e) => setProvider(e.target.value)}
            className="w-full px-3 py-2 bg-slate-800 border border-white/5 rounded-lg text-white text-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
            disabled={running}
          >
            <option value="local">Local (Ollama)</option>
            <option value="cloud">Cloud (DeepSeek)</option>
          </select>
        </div>
      </div>

      {/* Submit */}
      <button
        onClick={handleSubmit}
        disabled={running || !target.trim()}
        className={`w-full py-2 rounded-lg font-medium text-sm transition-all ${
          running
            ? "bg-slate-700 text-gray-400 cursor-not-allowed"
            : "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/30"
        }`}
      >
        {running ? "Running..." : "Start Agent Task"}
      </button>

      {/* Session ID + Error */}
      {sessionId && (
        <div className="text-xs text-gray-400">
          Session: <code className="text-cyan-400">{sessionId}</code>
        </div>
      )}
      {error && <div className="text-xs text-red-400">{error}</div>}
    </div>
  );
}
