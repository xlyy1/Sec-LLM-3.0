"use client";

import { useEffect, useMemo, useState } from "react";
import { Network } from "lucide-react";
import { AgentGraph, GraphNode, getAgentGraph } from "@/lib/agent-api";

/**
 * 资产 → 服务 → CPE → CVE → 弱点/修复版本 的分层关联图。
 *
 * 用分层布局而不是力导向：这张图表达的是"一条推断链"，从左到右就是推理顺序；
 * 力导向会把它揉成一团，反而看不出因果。顺带也不需要引入 d3。
 */

const COLUMN: Record<string, number> = {
  asset: 0,
  service: 1,
  cpe: 2,
  cve: 3,
  cwe: 4,
  fix: 4,
};

const COL_WIDTH = 200;
const ROW_HEIGHT = 64;
const PAD = 32;
const NODE_W = 152;
const NODE_H = 30;

const SEVERITY_COLOR: Record<string, string> = {
  Critical: "#f87171",
  High: "#fb923c",
  Medium: "#facc15",
  Low: "#38bdf8",
  Unknown: "#94a3b8",
};

function colorOf(node: GraphNode): string {
  switch (node.type) {
    case "asset":
      return "#22d3ee";
    case "service":
      return "#818cf8";
    case "cpe":
      return "#fbbf24";
    case "cve":
      return SEVERITY_COLOR[String(node.attrs?.severity ?? "Unknown")] ?? SEVERITY_COLOR.Unknown;
    case "cwe":
      return "#c084fc";
    case "fix":
      return "#4ade80";
    default:
      return "#94a3b8";
  }
}

function truncate(text: string, limit = 22): string {
  return text.length > limit ? `${text.slice(0, limit - 1)}…` : text;
}

export default function AssetCveGraph({
  sessionId,
  refreshKey,
}: {
  sessionId: string | null;
  refreshKey?: string | null;
}) {
  const [graph, setGraph] = useState<AgentGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<GraphNode | null>(null);
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    if (!sessionId) {
      setGraph(null);
      return;
    }
    let active = true;
    setLoading(true);
    setError(null);
    getAgentGraph(sessionId)
      .then((data) => {
        if (active) setGraph(data);
      })
      .catch((err: Error) => {
        if (active) setError(err.message || "关联图加载失败");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [sessionId, refreshKey]);

  const layout = useMemo(() => {
    if (!graph) return null;
    const columns = new Map<number, GraphNode[]>();
    graph.nodes.forEach((node) => {
      const column = COLUMN[node.type] ?? 4;
      const bucket = columns.get(column) ?? [];
      bucket.push(node);
      columns.set(column, bucket);
    });
    const positions = new Map<string, { x: number; y: number }>();
    let maxRows = 1;
    columns.forEach((bucket, column) => {
      maxRows = Math.max(maxRows, bucket.length);
      bucket.forEach((node, index) => {
        positions.set(node.id, {
          x: PAD + column * COL_WIDTH,
          y: PAD + index * ROW_HEIGHT + 8,
        });
      });
    });
    return {
      positions,
      width: PAD * 2 + 4 * COL_WIDTH + NODE_W,
      height: PAD * 2 + maxRows * ROW_HEIGHT,
    };
  }, [graph]);

  if (!sessionId) return null;

  const hasNodes = Boolean(graph && graph.nodes.length > 0);

  return (
    <div className="bg-slate-900/50 border border-white/5 rounded-lg">
      <button
        onClick={() => setCollapsed((previous) => !previous)}
        className="w-full flex items-center gap-2 px-6 py-3 text-left"
      >
        <Network className="w-4 h-4 text-cyan-400" />
        <span className="text-sm font-semibold text-white">资产-CVE 关联图</span>
        {graph && (
          <span className="text-xs text-gray-400">
            {graph.summary.cves} 个 CVE · {graph.summary.nodes} 个节点
            {graph.snapshot ? ` · 快照 ${graph.snapshot}` : ""}
          </span>
        )}
        <span className="ml-auto text-xs text-gray-500">{collapsed ? "展开" : "收起"}</span>
      </button>

      {!collapsed && (
        <div className="px-6 pb-6">
          {loading && <p className="text-xs text-gray-400">加载中…</p>}

          {error && !loading && (
            <p className="text-xs text-red-400">关联图加载失败：{error}</p>
          )}

          {!loading && !error && graph && !hasNodes && (
            <p className="text-xs text-gray-400">
              本次会话没有可展示的组件关联。{graph.reason ?? ""}
            </p>
          )}

          {!loading && !error && graph && hasNodes && layout && (
            <div className="flex gap-4">
              <div className="flex-1 overflow-auto max-h-[420px] rounded border border-white/5 bg-slate-950/60">
                <svg width={layout.width} height={layout.height} role="img" aria-label="资产与 CVE 关联图">
                  <defs>
                    <marker id="kg-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                            markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                      <path d="M 0 0 L 10 5 L 0 10 z" fill="#475569" />
                    </marker>
                  </defs>

                  {graph.edges.map((edge) => {
                    const from = layout.positions.get(edge.source);
                    const to = layout.positions.get(edge.target);
                    if (!from || !to) return null;
                    const x1 = from.x + NODE_W;
                    const y1 = from.y + NODE_H / 2;
                    const x2 = to.x;
                    const y2 = to.y + NODE_H / 2;
                    const mid = (x1 + x2) / 2;
                    return (
                      <g key={`${edge.source}-${edge.target}-${edge.rel}`}>
                        <title>{`${edge.rel} · 来源 ${edge.source_of_truth} · 置信度 ${edge.confidence}`}</title>
                        <path
                          d={`M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`}
                          fill="none"
                          stroke="#475569"
                          strokeWidth={edge.confidence < 0.5 ? 1 : 1.5}
                          strokeDasharray={edge.confidence < 0.5 ? "4 3" : undefined}
                          markerEnd="url(#kg-arrow)"
                        />
                      </g>
                    );
                  })}

                  {graph.nodes.map((node) => {
                    const position = layout.positions.get(node.id);
                    if (!position) return null;
                    const active = selected?.id === node.id;
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${position.x}, ${position.y})`}
                        onClick={() => setSelected(node)}
                        style={{ cursor: "pointer" }}
                        role="button"
                        tabIndex={0}
                        aria-label={node.label}
                      >
                        <title>{node.id}</title>
                        <rect
                          width={NODE_W}
                          height={NODE_H}
                          rx={6}
                          fill={active ? "#1e293b" : "#0f172a"}
                          stroke={colorOf(node)}
                          strokeWidth={active ? 2 : 1}
                        />
                        <text x={8} y={19} fontSize={11} fill="#e2e8f0">
                          {truncate(node.label)}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>

              <div className="w-56 shrink-0 text-xs text-gray-400">
                <div className="mb-3 space-y-1">
                  <LegendItem color="#22d3ee" text="资产" />
                  <LegendItem color="#818cf8" text="服务" />
                  <LegendItem color="#fbbf24" text="CPE" />
                  <LegendItem color="#f87171" text="CVE（按 CVSS 分级）" />
                  <LegendItem color="#c084fc" text="CWE" />
                  <LegendItem color="#4ade80" text="修复版本" />
                </div>
                <p className="leading-relaxed text-[11px] text-gray-500">{graph.disclaimer}</p>
                <p className="mt-2 text-[11px] text-gray-500">
                  虚线表示低置信度边（CPE 为查表推断或来自 AND 组合节点）。
                </p>
                {selected && (
                  <div className="mt-3 rounded border border-white/10 bg-slate-950/80 p-2">
                    <p className="text-[11px] text-cyan-300 mb-1">{selected.type}</p>
                    <p className="text-[11px] text-gray-300 break-all">{selected.id}</p>
                    {Object.entries(selected.attrs || {}).map(([key, value]) => (
                      value === null || value === undefined || value === "" ? null : (
                        <p key={key} className="text-[11px] text-gray-400 mt-1">
                          {key}: <span className="text-gray-200">{String(value)}</span>
                        </p>
                      )
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function LegendItem({ color, text }: { color: string; text: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="inline-block w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: color }} />
      <span className="text-[11px]">{text}</span>
    </div>
  );
}
