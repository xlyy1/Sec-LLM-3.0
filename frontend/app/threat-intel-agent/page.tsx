'use client';

import { useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Home,
  MessageSquare,
  Eye,
  FileText,
  LogOut,
  Shield,
  Wrench,
  Activity,
  Globe,
  ShieldAlert,
} from 'lucide-react';
import LLMProviderToggle from '@/components/LLMProviderToggle';
import {
  enrichThreatIntel,
  logout,
  type ThreatIntelEnrichResponse,
  type ThreatIntelIocType,
  type UserInfo,
} from '@/lib/api';

const IOC_PATTERNS = {
  ipv4: /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/,
  md5: /^[a-fA-F0-9]{32}$/,
  sha256: /^[a-fA-F0-9]{64}$/,
  domain: /^(?!:\/\/)([a-zA-Z0-9-_]+\.)*[a-zA-Z0-9][a-zA-Z0-9-_]+\.[a-zA-Z]{2,11}?$/,
};

const isValidIPv4 = (value: string) => {
  if (!IOC_PATTERNS.ipv4.test(value)) return false;
  const parts = value.split('.').map((n) => Number(n));
  return parts.length === 4 && parts.every((n) => Number.isInteger(n) && n >= 0 && n <= 255);
};

const detectIocType = (input: string): ThreatIntelIocType | 'unknown' => {
  const value = input.trim();
  if (!value) return 'unknown';
  if (isValidIPv4(value)) return 'ip';
  if (IOC_PATTERNS.md5.test(value)) return 'md5';
  if (IOC_PATTERNS.sha256.test(value)) return 'sha256';
  if (IOC_PATTERNS.domain.test(value)) return 'domain';
  return 'unknown';
};

export default function ThreatIntelAgentPage() {
  const router = useRouter();
  const [activeMenu, setActiveMenu] = useState('threat-intel');
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);

  const [iocInput, setIocInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [enrichResult, setEnrichResult] = useState<ThreatIntelEnrichResponse | null>(null);

  const [reportLoading, setReportLoading] = useState(false);
  const [reportOutput, setReportOutput] = useState('');
  const [reportError, setReportError] = useState<string | null>(null);

  const detectedType = useMemo(() => detectIocType(iocInput), [iocInput]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      try {
        setUserInfo(JSON.parse(savedUser));
      } catch {
        // ignore
      }
    }
  }, [router]);

  const handleLogout = () => {
    void logout();
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    router.push('/login');
  };

  const handleMenuClick = (menu: string) => {
    setActiveMenu(menu);
    if (menu === 'dashboard') router.push('/');
    else if (menu === 'chat') router.push('/chat');
    else if (menu === 'analysis') router.push('/log-analysis');
    else if (menu === 'reports') router.push('/report-generation');
    else if (menu === 'security-tools') router.push('/security-tools');
    else if (menu === 'threat-intel') router.push('/threat-intel-agent');
  };

  const streamReport = async (result: ThreatIntelEnrichResponse) => {
    const token = localStorage.getItem('token');
    if (!token) return;
    setReportLoading(true);
    setReportError(null);
    setReportOutput('');
    try {
      const backendBaseUrl = (process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000').replace(/\/$/, '');
      const response = await fetch(`${backendBaseUrl}/api/security-tools/threat-intel/report`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          ioc: result.normalized_ioc,
          detected_type: result.detected_type,
          enrichment: result.enrichment,
        }),
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
        setReportOutput(content);
      }
      const savedPayload = {
        ioc: result.normalized_ioc,
        detectedType: result.detected_type,
        verdict: result.verdict,
        score: result.total_score,
        sourceHits: result.source_hits,
        enrichment: result.enrichment,
        reportText: content,
        savedAt: new Date().toISOString(),
      };
      localStorage.setItem('cyberguard_threat_intel_report', JSON.stringify(savedPayload));
    } catch (err: any) {
      setReportError(err?.message || '报告生成失败');
    } finally {
      setReportLoading(false);
    }
  };

  const handleAnalyze = async () => {
    const value = iocInput.trim();
    if (!value) return;
    setLoading(true);
    setError(null);
    setEnrichResult(null);
    setReportOutput('');
    setReportError(null);
    try {
      const result = await enrichThreatIntel(value, 'auto');
      setEnrichResult(result);
      await streamReport(result);
    } catch (err: any) {
      setError(err?.response?.data?.detail || '情报富化失败，请稍后重试');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">
      <aside className="w-64 bg-slate-900 flex flex-col border-r border-slate-800">
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div className="flex flex-col">
              <span className="text-xl font-bold text-white leading-tight">灵犀网卫</span>
              <span className="text-xl font-bold text-white leading-tight">Sec-LLM</span>
            </div>
          </div>
        </div>
        <nav className="flex-1 p-4 space-y-2">
          <button onClick={() => handleMenuClick('dashboard')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeMenu === 'dashboard' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-gray-400 hover:text-white hover:bg-slate-800/50'}`}><Home className="w-5 h-5" /><span className="font-medium">仪表盘</span></button>
          <button onClick={() => handleMenuClick('chat')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeMenu === 'chat' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-gray-400 hover:text-white hover:bg-slate-800/50'}`}><MessageSquare className="w-5 h-5" /><span className="font-medium">AI智能回答</span></button>
          <button onClick={() => handleMenuClick('threat-intel')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeMenu === 'threat-intel' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-gray-400 hover:text-white hover:bg-slate-800/50'}`}><Activity className="w-5 h-5" /><span className="font-medium">威胁情报研判</span></button>
          <button onClick={() => handleMenuClick('analysis')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeMenu === 'analysis' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-gray-400 hover:text-white hover:bg-slate-800/50'}`}><Eye className="w-5 h-5" /><span className="font-medium">日志分析</span></button>
          <button onClick={() => handleMenuClick('reports')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeMenu === 'reports' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-gray-400 hover:text-white hover:bg-slate-800/50'}`}><FileText className="w-5 h-5" /><span className="font-medium">报告生成</span></button>
          <div className="pt-2 mt-2 border-t border-slate-800">
            <button onClick={() => handleMenuClick('security-tools')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeMenu === 'security-tools' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-gray-400 hover:text-white hover:bg-slate-800/50'}`}><Wrench className="w-5 h-5" /><span className="font-medium">安全工具箱</span></button>
          </div>
        </nav>
        <div className="p-4 border-t border-slate-800">
          <button onClick={handleLogout} className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-gray-400 hover:text-white hover:bg-slate-800/50 transition-all">
            <LogOut className="w-5 h-5" />
            <span className="font-medium">登出</span>
          </button>
        </div>
      </aside>

      <main className="flex-1 flex flex-col overflow-hidden">
        <header className="bg-slate-900/50 backdrop-blur border-b border-white/5 px-6 py-3">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-xl font-bold text-white">威胁情报自动化研判</h1>
              <p className="text-xs text-gray-400">输入 IOC 自动富化最新情报，并生成中文研判报告</p>
            </div>
            <div className="flex items-center gap-4">
              <LLMProviderToggle onAuthExpired={handleLogout} />
              <div className="text-sm text-gray-300">{userInfo?.username || '用户'}</div>
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-6">
          <section className="bg-slate-900/50 border border-white/5 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-3">
              <Activity className="w-5 h-5 text-cyan-400" />
              IOC 自动识别与情报富化
            </h2>
            <div className="flex flex-col lg:flex-row gap-3">
              <input
                value={iocInput}
                onChange={(e) => setIocInput(e.target.value)}
                placeholder="输入可疑 IP / 域名 / MD5 / SHA256"
                className="flex-1 px-4 py-3 bg-slate-800/50 border border-white/5 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
              />
              <button
                onClick={handleAnalyze}
                disabled={loading || !iocInput.trim()}
                className="px-4 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? '情报查询中...' : '开始研判'}
              </button>
            </div>
            <div className="mt-3 text-sm text-gray-300">
              检测类型：
              <span className={`ml-2 font-semibold ${detectedType === 'unknown' ? 'text-amber-300' : 'text-cyan-300'}`}>
                {detectedType}
              </span>
            </div>
            {error && <div className="mt-3 text-sm text-red-400">{error}</div>}
          </section>

          {enrichResult && (
            <section className="mt-4 bg-slate-900/50 border border-white/5 rounded-lg p-6 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <div className="bg-slate-800/40 border border-white/5 rounded-lg p-3">
                  <div className="text-xs text-gray-400">IOC 类型</div>
                  <div className="text-white font-semibold mt-1">{enrichResult.detected_type}</div>
                </div>
                <div className="bg-slate-800/40 border border-white/5 rounded-lg p-3">
                  <div className="text-xs text-gray-400">风险评分</div>
                  <div className="text-white font-semibold mt-1">{enrichResult.total_score} / 100</div>
                </div>
                <div className="bg-slate-800/40 border border-white/5 rounded-lg p-3">
                  <div className="text-xs text-gray-400">判定结果</div>
                  <div className="text-white font-semibold mt-1">{enrichResult.verdict}</div>
                </div>
                <div className="bg-slate-800/40 border border-white/5 rounded-lg p-3">
                  <div className="text-xs text-gray-400">命中源</div>
                  <div className="text-white font-semibold mt-1">{enrichResult.source_hits}</div>
                </div>
              </div>

              <div className="bg-slate-800/40 border border-white/5 rounded-lg p-4">
                <div className="text-sm text-gray-300">标准化摘要：{enrichResult.enrichment.summary || '无'}</div>
                <div className="text-sm text-gray-300 mt-2">标签：{enrichResult.enrichment.tags?.length ? enrichResult.enrichment.tags.join(' , ') : '无'}</div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {Object.entries(enrichResult.source_status || {}).map(([source, statusObj]) => (
                  <div key={source} className="bg-slate-800/40 border border-white/5 rounded-lg p-3">
                    <div className="flex items-center gap-2 text-white">
                      <Globe className="w-4 h-4 text-cyan-400" />
                      <span className="font-medium">{source}</span>
                    </div>
                    <div className="text-xs text-gray-400 mt-1">状态：{statusObj.status}</div>
                    {statusObj.reason && <div className="text-xs text-gray-500 mt-1">原因：{statusObj.reason}</div>}
                  </div>
                ))}
              </div>
            </section>
          )}

          <section className="mt-4 bg-slate-900/50 border border-white/5 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white flex items-center gap-2 mb-3">
              <ShieldAlert className="w-5 h-5 text-cyan-400" />
              AI 研判报告
            </h2>
            {reportError && <div className="text-sm text-red-400 mb-2">{reportError}</div>}
            <pre className="w-full min-h-[260px] whitespace-pre-wrap break-words px-4 py-3 bg-slate-950 border border-white/5 rounded-lg text-gray-200 text-sm">
              {reportOutput || (reportLoading ? '正在生成研判报告...' : '完成情报富化后将自动生成研判报告。')}
            </pre>
          </section>
        </div>
      </main>
    </div>
  );
}
