'use client';

import { useState } from 'react';
import { MailWarning } from 'lucide-react';
import SecurityToolsShell from '@/components/SecurityToolsShell';
import { analyzePhishingEmail, type PhishingAnalyzeResult } from '@/lib/api';

export default function PhishingAnalyzerPage() {
  const [emailInput, setEmailInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<PhishingAnalyzeResult | null>(null);

  const handleAnalyze = async () => {
    if (!emailInput.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await analyzePhishingEmail(emailInput);
      if (data.status === 'success') setResult(data.result);
      else setError('分析失败，请稍后重试');
    } catch (err: any) {
      setError(err?.response?.data?.detail || '分析失败，请稍后重试');
    } finally {
      setLoading(false);
    }
  };

  return (
    <SecurityToolsShell title="钓鱼邮件智能鉴定" subtitle="识别伪造、诱导、恶意链接与附件风险" activeTool="phishing">
      <section className="bg-slate-900/50 border border-white/5 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-3">
          <MailWarning className="w-5 h-5 text-cyan-400" />
          输入可疑邮件内容
        </h2>
        <textarea
          value={emailInput}
          onChange={(e) => setEmailInput(e.target.value)}
          placeholder="粘贴邮件主题、发件人、正文或邮件头..."
          rows={10}
          className="w-full px-4 py-3 bg-slate-800/50 border border-white/5 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        />
        <div className="mt-3 flex items-center gap-3">
          <button
            onClick={handleAnalyze}
            disabled={loading || !emailInput.trim()}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? '分析中...' : '开始鉴定'}
          </button>
          {error && <span className="text-sm text-red-400">{error}</span>}
        </div>
        {result && (
          <div className="mt-4 bg-slate-800/40 border border-white/5 rounded-lg p-4 text-sm text-gray-200 space-y-2">
            <div>风险指数：<span className="text-cyan-300 font-semibold">{result.risk_score}</span> / 100</div>
            <div>判定结果：<span className="font-semibold">{result.verdict}</span></div>
            <div>摘要：{result.summary}</div>
            <div>可疑 URL：{result.suspicious_urls?.length ? result.suspicious_urls.join(' , ') : '无'}</div>
            <div>可疑 IP：{result.suspicious_ips?.length ? result.suspicious_ips.join(' , ') : '无'}</div>
          </div>
        )}
      </section>
    </SecurityToolsShell>
  );
}
