'use client';

import { useEffect, useState, type ReactNode } from 'react';
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
  MailWarning,
  Code2,
  ClipboardList,
  FileSearch,
} from 'lucide-react';
import type { UserInfo } from '@/lib/api';
import LLMProviderToggle from '@/components/LLMProviderToggle';

type ToolKey = 'hub' | 'phishing' | 'code-audit' | 'rule-generator' | 'report-explainer';

interface SecurityToolsShellProps {
  title: string;
  subtitle: string;
  activeTool: ToolKey;
  children: ReactNode;
}

const toolTabs: Array<{ key: ToolKey; label: string; path: string; icon: ReactNode }> = [
  { key: 'hub', label: '工具箱首页', path: '/security-tools', icon: <Wrench className="w-4 h-4" /> },
  { key: 'phishing', label: '钓鱼邮件鉴定', path: '/security-tools/phishing-analyzer', icon: <MailWarning className="w-4 h-4" /> },
  { key: 'code-audit', label: '源码漏洞审计', path: '/security-tools/code-vulnerability-scanner', icon: <Code2 className="w-4 h-4" /> },
  { key: 'rule-generator', label: '蓝队规则生成', path: '/security-tools/rule-generator', icon: <ClipboardList className="w-4 h-4" /> },
  { key: 'report-explainer', label: '扫描报告解析', path: '/security-tools/report-explainer', icon: <FileSearch className="w-4 h-4" /> },
];

export default function SecurityToolsShell({ title, subtitle, activeTool, children }: SecurityToolsShellProps) {
  const router = useRouter();
  const [activeMenu, setActiveMenu] = useState('security-tools');
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);

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
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    router.push('/login');
  };

  const handleMenuClick = (menu: string) => {
    setActiveMenu(menu);
    if (menu === 'dashboard') router.push('/');
    else if (menu === 'chat') router.push('/chat');
    else if (menu === 'threat-intel') router.push('/threat-intel-agent');
    else if (menu === 'analysis') router.push('/log-analysis');
    else if (menu === 'reports') router.push('/report-generation');
    else if (menu === 'security-tools') router.push('/security-tools');
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
            <p className="px-2 text-xs text-gray-500 uppercase tracking-wider mb-2">安全工具箱</p>
            <button onClick={() => handleMenuClick('security-tools')} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${activeMenu === 'security-tools' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30' : 'text-gray-400 hover:text-white hover:bg-slate-800/50'}`}><Wrench className="w-5 h-5" /><span className="font-medium">Security Tools</span></button>
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
              <h1 className="text-xl font-bold text-white">{title}</h1>
              <p className="text-xs text-gray-400">{subtitle}</p>
            </div>
            <div className="flex items-center gap-4">
              <LLMProviderToggle onAuthExpired={handleLogout} />
              <div className="text-sm text-gray-300">{userInfo?.username || '用户'}</div>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-2">
            {toolTabs.map((tool) => (
              <button
                key={tool.key}
                onClick={() => router.push(tool.path)}
                className={`px-3 py-1.5 rounded-lg border text-xs flex items-center gap-1.5 ${
                  activeTool === tool.key
                    ? 'bg-cyan-500/20 border-cyan-500/40 text-cyan-300'
                    : 'bg-slate-800/40 border-white/5 text-gray-300 hover:text-white'
                }`}
              >
                {tool.icon}
                {tool.label}
              </button>
            ))}
          </div>
        </header>
        <div className="flex-1 overflow-y-auto p-6">{children}</div>
      </main>
    </div>
  );
}
