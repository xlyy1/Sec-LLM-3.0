'use client';

import { useState } from 'react';
import { FileSearch, Upload } from 'lucide-react';
import SecurityToolsShell from '@/components/SecurityToolsShell';
import { explainScanReport, type ReportExplainResult } from '@/lib/api';

export default function ReportExplainerPage() {
  const [reportInput, setReportInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ReportExplainResult | null>(null);

  const handleAnalyze = async () => {
    if (!reportInput.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await explainScanReport(reportInput);
      if (data.status === 'success') setResult(data.result);
      else setError('解析失败，请稍后重试');
    } catch (err: any) {
      setError(err?.response?.data?.detail || '解析失败，请稍后重试');
    } finally {
      setLoading(false);
    }
  };

  const handleFileLoad = async (file?: File) => {
    if (!file) return;
    const text = await file.text();
    setReportInput(text);
  };

  return (
    <SecurityToolsShell title="扫描报告解析" subtitle="将技术扫描结果转换为可执行的管理层摘要" activeTool="report-explainer">
      <section className="bg-slate-900/50 border border-white/5 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-3">
          <FileSearch className="w-5 h-5 text-cyan-400" />
          输入或上传扫描报告
        </h2>
        <div className="flex flex-wrap gap-3 mb-3">
          <label className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg cursor-pointer inline-flex items-center gap-2">
            <Upload className="w-4 h-4" />
            上传 .txt/.xml
            <input
              type="file"
              accept=".txt,.xml,.log,.json"
              className="hidden"
              onChange={(e) => handleFileLoad(e.target.files?.[0])}
            />
          </label>
          <button
            onClick={handleAnalyze}
            disabled={loading || !reportInput.trim()}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? '解析中...' : '开始解析'}
          </button>
        </div>
        <textarea
          value={reportInput}
          onChange={(e) => setReportInput(e.target.value)}
          placeholder="粘贴 Nmap/Nessus 扫描内容，或先上传文件..."
          rows={12}
          className="w-full px-4 py-3 bg-slate-800/50 border border-white/5 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        />
        {error && <div className="mt-3 text-sm text-red-400">{error}</div>}
      </section>

      {result && (
        <section className="mt-4 bg-slate-900/50 border border-white/5 rounded-lg p-6 text-sm text-gray-200 space-y-3">
          <div>
            <h3 className="text-white font-semibold mb-1">执行摘要</h3>
            <p>{result.executive_summary}</p>
          </div>
          <div>
            <h3 className="text-white font-semibold mb-1">关键风险点</h3>
            {result.critical_findings?.length ? (
              <div className="space-y-2">
                {result.critical_findings.map((item, idx) => (
                  <div key={`${item.item}-${idx}`} className="bg-slate-800/40 border border-white/5 rounded-lg p-3">
                    <div className="font-medium text-white">{item.item}</div>
                    <div className="text-xs text-gray-400 mt-1">风险：{item.risk}</div>
                    <div className="mt-1">影响：{item.impact}</div>
                    <div className="mt-1 text-cyan-200">建议：{item.action}</div>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-gray-400">未提取到关键风险点。</p>
            )}
          </div>
          <div>
            <h3 className="text-white font-semibold mb-1">暴露端口/服务</h3>
            <p>{result.exposed_ports?.length ? result.exposed_ports.join(' , ') : '无'}</p>
          </div>
          <div>
            <h3 className="text-white font-semibold mb-1">优先行动清单</h3>
            {result.priority_actions?.length ? (
              <ul className="list-disc list-inside text-gray-300 space-y-1">
                {result.priority_actions.map((item, idx) => (
                  <li key={`${item}-${idx}`}>{item}</li>
                ))}
              </ul>
            ) : (
              <p className="text-gray-400">无</p>
            )}
          </div>
          <div>
            <h3 className="text-white font-semibold mb-1">大白话说明</h3>
            <p>{result.plain_language_brief || '无'}</p>
          </div>
        </section>
      )}
    </SecurityToolsShell>
  );
}
