"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Shield, Activity } from "lucide-react";
import AgentTaskPanel from "@/components/AgentTaskPanel";
import AgentLogStream from "@/components/AgentLogStream";
import { getAgentReport, listAgentSessions } from "@/lib/agent-api";

export default function AgentPage() {
  const router = useRouter();
  const [isAuth, setIsAuth] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [status, setStatus] = useState<string | null>(null);
  const [findingsCount, setFindingsCount] = useState(0);
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [report, setReport] = useState<string | null>(null);
  const [sessions, setSessions] = useState<any[]>([]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      router.push("/login");
      return;
    }
    setIsAuth(true);
    refreshSessions();
  }, [router]);

  const refreshSessions = async () => {
    try {
      const data = await listAgentSessions();
      setSessions(data.sessions || []);
    } catch {
      // ignore
    }
  };

  const handleTaskStart = (sid: string) => {
    setSessionId(sid);
    setLogs([]);
    setStatus("running");
    setFindingsCount(0);
    setReport(null);
  };

  const handleLog = (msg: string) => {
    setLogs((prev) => [...prev, msg]);
  };

  const handleDone = async (finalStatus: string, count: number) => {
    setStatus(finalStatus);
    setFindingsCount(count);
    refreshSessions();

    if (sessionId && finalStatus === "completed") {
      try {
        const data = await getAgentReport(sessionId);
        setReport(data.report);
      } catch {
        // ignore
      }
    }
  };

  if (!isAuth) return null;

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 bg-slate-900 flex flex-col border-r border-slate-800 p-4">
        <div className="flex items-center gap-2 mb-6">
          <Shield className="w-6 h-6 text-cyan-400" />
          <span className="text-lg font-bold text-white">Sec-LLM Agent</span>
        </div>
        <button
          onClick={() => router.push("/")}
          className="text-sm text-gray-400 hover:text-white mb-4 text-left"
        >
          &larr; Dashboard
        </button>

        <AgentTaskPanel onTaskStart={handleTaskStart} onLog={handleLog} onDone={handleDone} />

        {/* Recent sessions */}
        {sessions.length > 0 && (
          <div className="mt-4">
            <h3 className="text-xs text-gray-500 mb-2">Recent Sessions</h3>
            <div className="space-y-1">
              {sessions.slice(0, 10).map((s: any) => (
                <button
                  key={s.id}
                  onClick={() => {
                    setSessionId(s.id);
                    setLogs([]);
                    setStatus(s.status);
                    setFindingsCount(s.findings_count);
                    setReport(null);
                  }}
                  className={`w-full text-left text-xs px-2 py-1 rounded ${
                    sessionId === s.id
                      ? "bg-cyan-500/20 text-cyan-400"
                      : "text-gray-400 hover:text-white"
                  }`}
                >
                  <span className={s.status === "completed" ? "text-green-400" : "text-yellow-400"}>
                    {s.status === "completed" ? "O" : "~"}
                  </span>{" "}
                  {s.target?.slice(0, 25)}
                </button>
              ))}
            </div>
          </div>
        )}
      </aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col overflow-hidden">
        <header className="h-14 bg-slate-900/50 border-b border-white/5 flex items-center px-6">
          <h1 className="text-lg font-bold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            Agent Console
            {sessionId && (
              <code className="text-xs text-gray-400 ml-2 bg-slate-800 px-2 py-0.5 rounded">
                {sessionId}
              </code>
            )}
          </h1>
        </header>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          <AgentLogStream logs={logs} status={status} findingsCount={findingsCount} />

          {report && (
            <div className="bg-slate-900/50 border border-white/5 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-white mb-3">Report</h2>
              <div className="prose prose-invert max-w-none text-sm text-gray-300 whitespace-pre-wrap font-mono">
                {report}
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
