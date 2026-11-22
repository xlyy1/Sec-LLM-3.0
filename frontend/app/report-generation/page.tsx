'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import {
  Home,
  MessageSquare,
  Eye,
  FileText,
  LogOut,
  Shield,
  Download,
  FileDown,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Bot,
  User,
  Calendar,
  Clock,
  Wrench,
  Activity,
} from 'lucide-react';
import { type AnalysisResult } from '@/lib/api';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';

interface Message {
  role: 'user' | 'ai';
  content: string;
  sources?: string[];
}

interface LogAnalysisData {
  analysisResult: AnalysisResult;
  fileName: string;
  savedAt: string;
}

interface ThreatIntelReportData {
  ioc: string;
  detectedType: string;
  verdict: string;
  score: number;
  sourceHits: number;
  enrichment: {
    summary?: string;
    tags?: string[];
  };
  reportText: string;
  savedAt: string;
}

export default function ReportGenerationPage() {
  const router = useRouter();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [activeMenu, setActiveMenu] = useState('reports');
  const [chatHistory, setChatHistory] = useState<Message[]>([]);
  const [logAnalysis, setLogAnalysis] = useState<LogAnalysisData | null>(null);
  const [threatIntelReport, setThreatIntelReport] = useState<ThreatIntelReportData | null>(null);
  const [isExportingPDF, setIsExportingPDF] = useState(false);
  const [isExportingMarkdown, setIsExportingMarkdown] = useState(false);
  const [lastScanMinutes] = useState(() => Math.floor(Math.random() * 31));

  useEffect(() => {
    // 检查认证状态
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }
    setIsAuthenticated(true);

    // 从 localStorage 读取数据
    try {
      // 读取聊天记录
      const savedChatHistory = localStorage.getItem('cyberguard_chat_history');
      if (savedChatHistory) {
        const parsedChat = JSON.parse(savedChatHistory);
        if (Array.isArray(parsedChat) && parsedChat.length > 0) {
          setChatHistory(parsedChat);
        }
      }

      // 读取日志分析结果（注意：实际 key 是 cyberguard_log_analysis）
      const savedLogAnalysis = localStorage.getItem('cyberguard_log_analysis');
      if (savedLogAnalysis) {
        const parsedLog = JSON.parse(savedLogAnalysis);
        if (parsedLog.analysisResult) {
          setLogAnalysis(parsedLog);
        }
      }

      // 读取威胁情报研判结果
      const savedThreatIntel = localStorage.getItem('cyberguard_threat_intel_report');
      if (savedThreatIntel) {
        const parsedThreatIntel = JSON.parse(savedThreatIntel);
        if (parsedThreatIntel?.reportText) {
          setThreatIntelReport(parsedThreatIntel);
        }
      }
    } catch (error) {
      console.error('读取报告数据失败:', error);
    }
  }, [router]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    router.push('/login');
  };

  const handleMenuClick = (menu: string) => {
    setActiveMenu(menu);
    if (menu === 'dashboard') {
      router.push('/');
    } else if (menu === 'chat') {
      router.push('/chat');
    } else if (menu === 'analysis') {
      router.push('/log-analysis');
    } else if (menu === 'reports') {
      router.push('/report-generation');
    } else if (menu === 'threat-intel') {
      router.push('/threat-intel-agent');
    } else if (menu === 'security-tools') {
      router.push('/security-tools');
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'Critical':
        return 'text-red-400 border-red-500 bg-red-500/10';
      case 'High':
        return 'text-orange-400 border-orange-500 bg-orange-500/10';
      case 'Medium':
        return 'text-yellow-400 border-yellow-500 bg-yellow-500/10';
      case 'Low':
        return 'text-green-400 border-green-500 bg-green-500/10';
      default:
        return 'text-gray-400 border-gray-500 bg-gray-500/10';
    }
  };

  const getThreatLevelIcon = (level: string) => {
    switch (level) {
      case 'Critical':
        return <XCircle className="w-5 h-5" />;
      case 'High':
        return <ShieldAlert className="w-5 h-5" />;
      case 'Medium':
        return <AlertTriangle className="w-5 h-5" />;
      case 'Low':
        return <CheckCircle className="w-5 h-5" />;
      default:
        return <Shield className="w-5 h-5" />;
    }
  };

  const handleExportPDF = async () => {
    if (isExportingPDF) return;
    setIsExportingPDF(true);

    try {
      const element = document.getElementById('report-preview');
      if (!element) {
        alert('找不到报告预览区域');
        setIsExportingPDF(false);
        return;
      }

      // 检查元素是否有内容
      if (!element.textContent || element.textContent.trim().length === 0) {
        alert('报告预览区域没有内容，请先进行日志分析或 AI 对话');
        setIsExportingPDF(false);
        return;
      }

      // 滚动到元素位置，确保元素可见
      element.scrollIntoView({ behavior: 'instant', block: 'start' });
      
      // 等待渲染完成
      await new Promise(resolve => setTimeout(resolve, 1000));

      // 获取元素的实际尺寸
      const rect = element.getBoundingClientRect();
      console.log('Element rect:', rect);

      // 使用 html2canvas 截图 - 使用更简单的配置
      const canvas = await html2canvas(element, {
        scale: 1.5, // 降低 scale 以提高兼容性
        useCORS: true,
        backgroundColor: '#1e293b', // slate-800
        logging: true, // 临时开启日志
        allowTaint: true,
        width: rect.width,
        height: rect.height,
        x: 0,
        y: 0,
        scrollX: 0,
        scrollY: 0,
      });

      console.log('Canvas created:', canvas.width, 'x', canvas.height);
      console.log('Canvas data URL length:', canvas.toDataURL().length);
      
      if (!canvas || canvas.width === 0 || canvas.height === 0) {
        alert('无法捕获报告内容，请确保页面已完全加载');
        setIsExportingPDF(false);
        return;
      }

      // 创建 PDF (A4: 210mm x 297mm)
      const pdf = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4',
      });

      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = pdf.internal.pageSize.getHeight();
      const margin = 10;
      const contentWidth = pdfWidth - (margin * 2);
      const contentHeight = pdfHeight - (margin * 2);

      // 计算图片尺寸（像素转毫米，96 DPI）
      // html2canvas 返回的 canvas 尺寸是像素
      const imgWidthMM = (canvas.width * 25.4) / (96 * 1.5); // 除以 scale
      const imgHeightMM = (canvas.height * 25.4) / (96 * 1.5);
      
      // 计算缩放比例以适应页面宽度
      const scale = contentWidth / imgWidthMM;
      const scaledWidth = imgWidthMM * scale;
      const scaledHeight = imgHeightMM * scale;
      
      console.log('PDF dimensions:', pdfWidth, 'x', pdfHeight);
      console.log('Image dimensions (MM):', imgWidthMM, 'x', imgHeightMM);
      console.log('Scaled dimensions:', scaledWidth, 'x', scaledHeight);
      
      // 获取图片数据
      const imgData = canvas.toDataURL('image/png', 1.0);
      
      // 如果内容高度超过一页，需要分页
      if (scaledHeight <= contentHeight) {
        // 单页显示
        const xPos = (pdfWidth - scaledWidth) / 2;
        pdf.addImage(imgData, 'PNG', xPos, margin, scaledWidth, scaledHeight, undefined, 'FAST');
      } else {
        // 多页显示
        const totalPages = Math.ceil(scaledHeight / contentHeight);
        const pageImgHeightPx = canvas.height / totalPages;
        
        for (let i = 0; i < totalPages; i++) {
          if (i > 0) {
            pdf.addPage();
          }
          
          // 创建临时 canvas 裁剪当前页
          const pageCanvas = document.createElement('canvas');
          pageCanvas.width = canvas.width;
          pageCanvas.height = Math.ceil(pageImgHeightPx);
          const pageCtx = pageCanvas.getContext('2d');
          
          if (pageCtx) {
            const sourceY = Math.floor(i * pageImgHeightPx);
            const sourceHeight = Math.min(pageCanvas.height, canvas.height - sourceY);
            
            pageCtx.fillStyle = '#1e293b';
            pageCtx.fillRect(0, 0, pageCanvas.width, pageCanvas.height);
            
            pageCtx.drawImage(
              canvas,
              0, sourceY,
              canvas.width, sourceHeight,
              0, 0,
              canvas.width, sourceHeight
            );
            
            const pageImgData = pageCanvas.toDataURL('image/png', 1.0);
            const pageImgHeightMM = (sourceHeight * 25.4) / (96 * 1.5);
            const pageScaledHeight = pageImgHeightMM * scale;
            const xPos = (pdfWidth - scaledWidth) / 2;
            
            pdf.addImage(pageImgData, 'PNG', xPos, margin, scaledWidth, pageScaledHeight, undefined, 'FAST');
          }
        }
      }

      // 生成文件名并下载
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      pdf.save(`灵犀网卫—Sec-LLM_Report_${timestamp}.pdf`);
      
      console.log('PDF exported successfully');
    } catch (error) {
      console.error('导出 PDF 失败:', error);
      console.error('Error stack:', error instanceof Error ? error.stack : 'No stack');
      alert(`导出 PDF 失败: ${error instanceof Error ? error.message : '未知错误'}`);
    } finally {
      setIsExportingPDF(false);
    }
  };

  const handleExportMarkdown = () => {
    if (isExportingMarkdown) return;
    setIsExportingMarkdown(true);

    try {
      let markdown = '# 灵犀网卫—Sec-LLM 安全审计报告\n\n';
      markdown += `**生成时间**: ${new Date().toLocaleString('zh-CN')}\n\n`;
      markdown += '---\n\n';

      // 板块一：威胁审计结论
      if (logAnalysis && logAnalysis.analysisResult) {
        markdown += '## 📊 威胁审计结论\n\n';
        markdown += `**分析文件**: ${logAnalysis.fileName || '未知文件'}\n\n`;
        markdown += `**威胁等级**: ${logAnalysis.analysisResult.threat_level}\n\n`;
        markdown += `**摘要**: ${logAnalysis.analysisResult.summary}\n\n`;
        markdown += `**修复建议**: ${logAnalysis.analysisResult.advice}\n\n`;

        if (logAnalysis.analysisResult.details && logAnalysis.analysisResult.details.length > 0) {
          markdown += '### 威胁详情\n\n';
          logAnalysis.analysisResult.details.forEach((detail, index) => {
            markdown += `#### 威胁 ${index + 1}\n\n`;
            markdown += `- **类型**: ${detail.type}\n`;
            markdown += `- **源 IP**: ${detail.source_ip}\n`;
            markdown += `- **Payload**:\n\n`;
            markdown += '```\n';
            markdown += detail.payload;
            markdown += '\n```\n\n';
          });
        }
        markdown += '---\n\n';
      }

      // 板块二：交互式取证记录
      if (chatHistory && chatHistory.length > 0) {
        markdown += '## 💬 交互式取证记录\n\n';
        chatHistory.forEach((message, index) => {
          if (message.role === 'user') {
            markdown += `### 👤 用户提问 ${index + 1}\n\n`;
            markdown += `${message.content}\n\n`;
          } else {
            markdown += `### 🤖 AI 回复 ${Math.floor((index + 1) / 2)}\n\n`;
            markdown += `${message.content}\n\n`;
            if (message.sources && message.sources.length > 0) {
              markdown += `**参考来源**: ${message.sources.join(', ')}\n\n`;
            }
          }
        });
      }

      // 板块三：威胁情报自动化研判
      if (threatIntelReport && threatIntelReport.reportText) {
        markdown += '\n---\n\n';
        markdown += '## 🛰️ 威胁情报自动化研判\n\n';
        markdown += `**IOC**: ${threatIntelReport.ioc}\n\n`;
        markdown += `**检测类型**: ${threatIntelReport.detectedType}\n\n`;
        markdown += `**风险评分**: ${threatIntelReport.score}/100\n\n`;
        markdown += `**判定结果**: ${threatIntelReport.verdict}\n\n`;
        markdown += `**命中源数量**: ${threatIntelReport.sourceHits}\n\n`;
        if (threatIntelReport.enrichment?.summary) {
          markdown += `**情报摘要**: ${threatIntelReport.enrichment.summary}\n\n`;
        }
        if (threatIntelReport.enrichment?.tags?.length) {
          markdown += `**标签**: ${threatIntelReport.enrichment.tags.join(', ')}\n\n`;
        }
        markdown += '### AI 研判报告\n\n';
        markdown += `${threatIntelReport.reportText}\n\n`;
      }

      // 生成文件并下载
      const blob = new Blob([markdown], { type: 'text/markdown;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, -5);
      link.download = `灵犀网卫—Sec-LLM_Report_${timestamp}.md`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error('导出 Markdown 失败:', error);
      alert('导出 Markdown 失败，请重试');
    } finally {
      setIsExportingMarkdown(false);
    }
  };

  // 如果未认证，不渲染内容
  if (!isAuthenticated) {
    return null;
  }

  const hasData =
    (chatHistory && chatHistory.length > 0) ||
    (logAnalysis && logAnalysis.analysisResult) ||
    (threatIntelReport && threatIntelReport.reportText);

  return (
    <div className="flex h-screen bg-slate-950 overflow-hidden">
      {/* 左侧固定侧边栏 */}
      <aside className="w-64 bg-slate-900 flex flex-col border-r border-slate-800">
        {/* Logo */}
        <div className="p-6 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div className="flex flex-col">
              <span className="text-xl font-bold text-white leading-tight">灵犀网卫</span>
              <span className="text-xl font-bold text-white leading-tight">Sec-LLM</span>
            </div>
          </div>
        </div>

        {/* 导航菜单 */}
        <nav className="flex-1 p-4 space-y-2">
          <button
            onClick={() => handleMenuClick('dashboard')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'dashboard'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <Home className="w-5 h-5" />
            <span className="font-medium">仪表盘</span>
          </button>

          <button
            onClick={() => handleMenuClick('chat')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'chat'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <MessageSquare className="w-5 h-5" />
            <span className="font-medium">AI智能回答</span>
          </button>

          <button
            onClick={() => handleMenuClick('threat-intel')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'threat-intel'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <Activity className="w-5 h-5" />
            <span className="font-medium">威胁情报研判</span>
          </button>

          <button
            onClick={() => handleMenuClick('analysis')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'analysis'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <Eye className="w-5 h-5" />
            <span className="font-medium">日志分析</span>
          </button>

          <button
            onClick={() => handleMenuClick('reports')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'reports'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <FileText className="w-5 h-5" />
            <span className="font-medium">报告生成</span>
          </button>
          <button
            onClick={() => handleMenuClick('security-tools')}
            className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
              activeMenu === 'security-tools'
                ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
            }`}
          >
            <Wrench className="w-5 h-5" />
            <span className="font-medium">安全工具箱</span>
          </button>
        </nav>

        {/* 系统状态 */}
        <div className="p-4 border-t border-slate-800">
          <div className="flex items-center gap-2 mb-2">
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
            <span className="text-sm text-gray-400">系统安全</span>
          </div>
          <p className="text-xs text-gray-500">上次扫描: {lastScanMinutes} 分钟前</p>
        </div>

        {/* 登出按钮 */}
        <div className="p-4 border-t border-slate-800">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-gray-400 hover:text-white hover:bg-slate-800/50 transition-all"
          >
            <LogOut className="w-5 h-5" />
            <span className="font-medium">登出</span>
          </button>
        </div>
      </aside>

      {/* 主内容区域 */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* 顶部标题栏 */}
        <header className="h-16 bg-slate-900/50 backdrop-blur border-b border-white/5 flex items-center justify-between px-6">
          <div>
            <h1 className="text-xl font-bold text-white">安全报告生成</h1>
            <p className="text-xs text-gray-400">Security Report Generation</p>
          </div>
        </header>

        {/* 内容区域 */}
        <div className="flex-1 overflow-y-auto p-6 pb-32">
          {!hasData ? (
            // 空状态
            <div className="flex items-center justify-center h-full">
              <div className="text-center">
                <FileText className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                <h2 className="text-xl font-semibold text-gray-400 mb-2">暂无待生成的报告数据</h2>
                <p className="text-gray-500 mb-6">请先进行日志分析、AI 对话或威胁情报研判</p>
                <div className="flex gap-4 justify-center">
                  <button
                    onClick={() => router.push('/log-analysis')}
                    className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-all"
                  >
                    前往日志分析
                  </button>
                  <button
                    onClick={() => router.push('/chat')}
                    className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-all"
                  >
                    前往 AI 对话
                  </button>
                  <button
                    onClick={() => router.push('/threat-intel-agent')}
                    className="px-4 py-2 bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 rounded-lg hover:bg-cyan-500/30 transition-all"
                  >
                    前往情报研判
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <>
              {/* A4 纸比例的预览区域 */}
              <div
                id="report-preview"
                className="mx-auto bg-slate-800 border border-slate-700 rounded-lg shadow-2xl p-8 mb-24"
                style={{
                  width: '210mm',
                  minHeight: '297mm',
                  maxWidth: '100%',
                  position: 'relative',
                  zIndex: 1,
                }}
              >
                {/* 报告标题 */}
                <div className="border-b border-slate-700 pb-4 mb-6">
                  <div className="flex items-center gap-3 mb-2">
                    <Shield className="w-8 h-8 text-cyan-400" />
                    <div className="flex flex-col">
                      <h1 className="text-3xl font-bold text-white leading-tight">灵犀网卫</h1>
                      <h1 className="text-3xl font-bold text-white leading-tight">Sec-LLM 安全审计报告</h1>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-sm text-gray-400 mt-2">
                    <div className="flex items-center gap-2">
                      <Calendar className="w-4 h-4" />
                      <span>{new Date().toLocaleDateString('zh-CN')}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Clock className="w-4 h-4" />
                      <span>{new Date().toLocaleTimeString('zh-CN')}</span>
                    </div>
                  </div>
                </div>

                {/* 板块一：威胁审计结论 */}
                {logAnalysis && logAnalysis.analysisResult && (
                  <div className="mb-8">
                    <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                      <ShieldAlert className="w-6 h-6 text-cyan-400" />
                      威胁审计结论
                    </h2>

                    {/* 威胁等级卡片 */}
                    <div
                      className={`border-2 rounded-lg p-4 mb-4 ${getThreatLevelColor(
                        logAnalysis.analysisResult.threat_level
                      )}`}
                    >
                      <div className="flex items-center gap-3 mb-2">
                        {getThreatLevelIcon(logAnalysis.analysisResult.threat_level)}
                        <span className="font-bold text-lg">威胁等级: {logAnalysis.analysisResult.threat_level}</span>
                      </div>
                      {logAnalysis.fileName && (
                        <p className="text-sm text-gray-300 mt-1">分析文件: {logAnalysis.fileName}</p>
                      )}
                    </div>

                    {/* 摘要 */}
                    <div className="bg-slate-900/50 rounded-lg p-4 mb-4">
                      <h3 className="text-lg font-semibold text-cyan-400 mb-2">分析摘要</h3>
                      <p className="text-gray-300 leading-relaxed">{logAnalysis.analysisResult.summary}</p>
                    </div>

                    {/* 修复建议 */}
                    <div className="bg-slate-900/50 rounded-lg p-4 mb-4">
                      <h3 className="text-lg font-semibold text-cyan-400 mb-2">修复建议</h3>
                      <p className="text-gray-300 leading-relaxed">{logAnalysis.analysisResult.advice}</p>
                    </div>

                    {/* 威胁详情 */}
                    {logAnalysis.analysisResult.details && logAnalysis.analysisResult.details.length > 0 && (
                      <div className="mt-4">
                        <h3 className="text-lg font-semibold text-white mb-3">威胁详情</h3>
                        <div className="space-y-4">
                          {logAnalysis.analysisResult.details.map((detail, index) => (
                            <div key={index} className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                              <div className="flex items-center gap-2 mb-2">
                                <AlertTriangle className="w-5 h-5 text-yellow-400" />
                                <span className="font-semibold text-white">威胁 {index + 1}</span>
                              </div>
                              <div className="grid grid-cols-2 gap-2 mb-3 text-sm">
                                <div>
                                  <span className="text-gray-400">类型:</span>
                                  <span className="text-white ml-2">{detail.type}</span>
                                </div>
                                <div>
                                  <span className="text-gray-400">源 IP:</span>
                                  <span className="text-cyan-400 ml-2 font-mono">{detail.source_ip}</span>
                                </div>
                              </div>
                              <div>
                                <span className="text-gray-400 text-sm">Payload:</span>
                                <pre className="mt-2 p-3 bg-slate-950 border border-slate-700 rounded text-xs text-gray-300 overflow-x-auto">
                                  <code>{detail.payload}</code>
                                </pre>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 板块二：交互式取证记录 */}
                {chatHistory && chatHistory.length > 0 && (
                  <div className="mt-8 border-t border-slate-700 pt-6">
                    <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                      <MessageSquare className="w-6 h-6 text-cyan-400" />
                      交互式取证记录
                    </h2>

                    <div className="space-y-4">
                      {chatHistory.map((message, index) => (
                        <div
                          key={index}
                          className={`p-4 rounded-lg ${
                            message.role === 'user'
                              ? 'bg-cyan-500/10 border border-cyan-500/30'
                              : 'bg-slate-900/50 border border-slate-700'
                          }`}
                        >
                          <div className="flex items-start gap-3">
                            {message.role === 'user' ? (
                              <User className="w-5 h-5 text-cyan-400 mt-1 flex-shrink-0" />
                            ) : (
                              <Bot className="w-5 h-5 text-cyan-400 mt-1 flex-shrink-0" />
                            )}
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <span className="font-semibold text-white">
                                  {message.role === 'user' ? '用户提问' : 'AI 回复'}
                                </span>
                                {message.role === 'ai' && message.sources && message.sources.length > 0 && (
                                  <span className="text-xs text-gray-400">
                                    (参考来源: {message.sources.join(', ')})
                                  </span>
                                )}
                              </div>
                              <p className="text-gray-300 leading-relaxed whitespace-pre-wrap">{message.content}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 板块三：威胁情报自动化研判 */}
                {threatIntelReport && threatIntelReport.reportText && (
                  <div className="mt-8 border-t border-slate-700 pt-6">
                    <h2 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                      <Activity className="w-6 h-6 text-cyan-400" />
                      威胁情报自动化研判
                    </h2>
                    <div className="bg-slate-900/50 rounded-lg p-4 mb-4 border border-slate-700">
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div><span className="text-gray-400">IOC:</span> <span className="text-white font-mono">{threatIntelReport.ioc}</span></div>
                        <div><span className="text-gray-400">类型:</span> <span className="text-white">{threatIntelReport.detectedType}</span></div>
                        <div><span className="text-gray-400">风险评分:</span> <span className="text-cyan-300 font-semibold">{threatIntelReport.score}/100</span></div>
                        <div><span className="text-gray-400">判定:</span> <span className="text-white">{threatIntelReport.verdict}</span></div>
                      </div>
                      {threatIntelReport.enrichment?.summary && (
                        <p className="text-gray-300 mt-3">情报摘要：{threatIntelReport.enrichment.summary}</p>
                      )}
                    </div>
                    <div className="bg-slate-900/50 rounded-lg p-4 border border-slate-700">
                      <h3 className="text-lg font-semibold text-cyan-400 mb-2">AI 研判报告</h3>
                      <p className="text-gray-300 leading-relaxed whitespace-pre-wrap">{threatIntelReport.reportText}</p>
                    </div>
                  </div>
                )}

                {/* 报告页脚 */}
                <div className="mt-12 pt-6 pb-4 border-t border-slate-700 text-center text-sm text-gray-500">
                  <p className="mb-2">本报告由 灵犀网卫—Sec-LLM 安全平台自动生成</p>
                  <p>© 2026 灵犀网卫—Sec-LLM Platform. All rights reserved.</p>
                </div>
              </div>

              {/* 底部操作栏 */}
              <div className="fixed bottom-0 left-64 right-0 bg-slate-900/95 backdrop-blur border-t border-slate-800 p-4 flex items-center justify-center gap-4 z-50">
                <button
                  onClick={handleExportPDF}
                  disabled={isExportingPDF || !hasData}
                  className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white rounded-lg font-semibold hover:from-cyan-600 hover:to-blue-600 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <FileDown className="w-5 h-5" />
                  {isExportingPDF ? '导出中...' : '📄 导出 PDF'}
                </button>

                <button
                  onClick={handleExportMarkdown}
                  disabled={isExportingMarkdown || !hasData}
                  className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-purple-500 to-pink-500 text-white rounded-lg font-semibold hover:from-purple-600 hover:to-pink-600 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Download className="w-5 h-5" />
                  {isExportingMarkdown ? '导出中...' : '⬇️ 导出 Markdown'}
                </button>
              </div>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
