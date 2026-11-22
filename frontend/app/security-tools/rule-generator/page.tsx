'use client';

import { useState } from 'react';
import { ClipboardList, Copy } from 'lucide-react';
import SecurityToolsShell from '@/components/SecurityToolsShell';

export default function RuleGeneratorPage() {
  const [ruleType, setRuleType] = useState('yara');
  const [ruleInput, setRuleInput] = useState('');
  const [ruleLoading, setRuleLoading] = useState(false);
  const [ruleError, setRuleError] = useState<string | null>(null);
  const [ruleOutput, setRuleOutput] = useState('');

  const handleRuleGenerate = async () => {
    const authToken = localStorage.getItem('token');
    if (!ruleInput.trim() || !authToken) return;
    setRuleLoading(true);
    setRuleError(null);
    setRuleOutput('');
    try {
      const backendBaseUrl = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000').replace(/\/$/, '');
      const response = await fetch(`${backendBaseUrl}/api/security-tools/rule-generator`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({ requirement: ruleInput, rule_type: ruleType }),
      });
      if (!response.ok) throw new Error(response.statusText);
      if (!response.body) throw new Error('No response body');

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let content = '';
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        content += decoder.decode(value, { stream: true });
        setRuleOutput(content);
      }
    } catch (err: any) {
      setRuleError(err?.message || '生成失败，请稍后重试');
    } finally {
      setRuleLoading(false);
    }
  };

  return (
    <SecurityToolsShell title="蓝队防御规则生成器" subtitle="自然语言一键生成检测/拦截规则" activeTool="rule-generator">
      <section className="bg-slate-900/50 border border-white/5 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-3">
          <ClipboardList className="w-5 h-5 text-cyan-400" />
          生成规则
        </h2>
        <div className="flex gap-3 mb-3">
          <select
            value={ruleType}
            onChange={(e) => setRuleType(e.target.value)}
            className="px-3 py-2 bg-slate-800/50 border border-white/5 rounded-lg text-white"
          >
            <option value="yara">YARA</option>
            <option value="snort">Snort</option>
            <option value="regex">Regex</option>
            <option value="waf">WAF</option>
          </select>
          <button
            onClick={handleRuleGenerate}
            disabled={ruleLoading || !ruleInput.trim()}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {ruleLoading ? '生成中...' : '生成规则'}
          </button>
          <button
            onClick={() => navigator.clipboard.writeText(ruleOutput || '')}
            disabled={!ruleOutput}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            <Copy className="w-4 h-4" />
            复制
          </button>
        </div>
        <textarea
          value={ruleInput}
          onChange={(e) => setRuleInput(e.target.value)}
          placeholder="例如：帮我写一个 YARA 规则，拦截包含 'mimikatz' 且文件小于 5MB 的 PE 文件"
          rows={5}
          className="w-full px-4 py-3 mb-3 bg-slate-800/50 border border-white/5 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        />
        {ruleError && <div className="text-sm text-red-400 mb-2">{ruleError}</div>}
        <pre className="w-full min-h-[260px] whitespace-pre-wrap break-words px-4 py-3 bg-slate-950 border border-white/5 rounded-lg text-gray-200 text-sm">
          {ruleOutput || '规则生成结果将显示在这里...'}
        </pre>
      </section>
    </SecurityToolsShell>
  );
}
