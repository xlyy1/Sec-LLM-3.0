'use client';

import { useRouter } from 'next/navigation';
import { MailWarning, Code2, ClipboardList, FileSearch, ArrowRight } from 'lucide-react';
import SecurityToolsShell from '@/components/SecurityToolsShell';

const toolCards = [
  {
    title: '钓鱼邮件智能鉴定',
    desc: '输入邮件内容，输出欺诈风险评分、可疑 URL/IP 和处置建议。',
    path: '/security-tools/phishing-analyzer',
    icon: MailWarning,
  },
  {
    title: '源代码漏洞审计',
    desc: '粘贴代码进行安全审计，识别漏洞并给出修复后的安全代码。',
    path: '/security-tools/code-vulnerability-scanner',
    icon: Code2,
  },
  {
    title: '蓝队防御规则生成器',
    desc: '将自然语言需求转换为 YARA/Snort/Regex/WAF 规则。',
    path: '/security-tools/rule-generator',
    icon: ClipboardList,
  },
  {
    title: '扫描报告解析',
    desc: '解析 Nmap/Nessus 报告，输出执行摘要和优先修复建议。',
    path: '/security-tools/report-explainer',
    icon: FileSearch,
  },
];

export default function SecurityToolsHubPage() {
  const router = useRouter();

  return (
    <SecurityToolsShell
      title="安全工具箱"
      subtitle="四个独立小应用：鉴定、审计、规则生成、报告解析"
      activeTool="hub"
    >
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {toolCards.map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.path}
              onClick={() => router.push(item.path)}
              className="text-left bg-slate-900/50 border border-white/5 rounded-xl p-5 hover:border-cyan-500/30 transition-all"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 text-white font-semibold">
                    <Icon className="w-5 h-5 text-cyan-400" />
                    {item.title}
                  </div>
                  <p className="text-sm text-gray-400 mt-2">{item.desc}</p>
                </div>
                <ArrowRight className="w-4 h-4 text-gray-500" />
              </div>
            </button>
          );
        })}
      </div>
    </SecurityToolsShell>
  );
}
