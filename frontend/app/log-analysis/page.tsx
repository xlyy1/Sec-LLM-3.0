'use client';

import { useEffect, useState, useRef } from 'react';
import { useRouter } from 'next/navigation';
import {
  Home,
  MessageSquare,
  Eye,
  FileText,
  LogOut,
  Shield,
  Search,
  Bell,
  User,
  HelpCircle,
  UploadCloud,
  ShieldAlert,
  CheckCircle,
  AlertTriangle,
  XCircle,
  Code,
  FileCode,
  Wrench,
  Activity,
} from 'lucide-react';
import {
  getLogRecords,
  deleteLogRecord,
  updateLogRecordStatus,
  uploadLogFile,
  type AnalysisResult,
  type LogRecord,
  type UserInfo,
} from '@/lib/api';
import LLMProviderToggle from '@/components/LLMProviderToggle';

export default function LogAnalysisPage() {
  const router = useRouter();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [activeMenu, setActiveMenu] = useState('analysis');
  const [isDragging, setIsDragging] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [showUserMenu, setShowUserMenu] = useState(false);
  const [logRecords, setLogRecords] = useState<LogRecord[]>([]);
  const [logRecordsError, setLogRecordsError] = useState<string | null>(null);
  const [lastScanMinutes] = useState(() => Math.floor(Math.random() * 31));
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dropZoneRef = useRef<HTMLDivElement>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);

  const loadLogRecords = async () => {
    try {
      setLogRecordsError(null);
      const response = await getLogRecords(50, 0);
      if (response.status === 'success') {
        setLogRecords(response.records || []);
      } else {
        setLogRecords([]);
        setLogRecordsError('日志记录获取失败');
      }
    } catch (err) {
      setLogRecords([]);
      setLogRecordsError('日志记录获取失败');
    }
  };

  useEffect(() => {
    // 检查认证状态
    const token = localStorage.getItem('token');
    if (!token) {
      router.push('/login');
      return;
    }
    setIsAuthenticated(true);

    // 读取用户信息
    const savedUser = localStorage.getItem('user');
    if (savedUser) {
      try {
        setUserInfo(JSON.parse(savedUser));
      } catch (e) {
        console.error('解析用户信息失败:', e);
      }
    }

    // 从 localStorage 恢复日志分析结果
    const savedAnalysis = localStorage.getItem('cyberguard_log_analysis');
    if (savedAnalysis) {
      try {
        const parsedData = JSON.parse(savedAnalysis);
        if (parsedData.analysisResult) {
          setAnalysisResult(parsedData.analysisResult);
        }
        if (parsedData.fileName) {
          setFileName(parsedData.fileName);
        }
      } catch (error) {
        console.error('恢复日志分析结果失败:', error);
      }
    }

    loadLogRecords();
  }, [router]);


  // 自动保存日志分析结果到 localStorage
  useEffect(() => {
    if (analysisResult) {
      try {
        const dataToSave = {
          analysisResult,
          fileName,
          savedAt: new Date().toISOString(),
        };
        localStorage.setItem('cyberguard_log_analysis', JSON.stringify(dataToSave));
      } catch (error) {
        console.error('保存日志分析结果失败:', error);
      }
    }
  }, [analysisResult, fileName]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setShowUserMenu(false);
    router.push('/login');
  };

  // 点击外部关闭用户菜单
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(event.target as Node)) {
        setShowUserMenu(false);
      }
    };

    if (showUserMenu) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => {
        document.removeEventListener('mousedown', handleClickOutside);
      };
    }
  }, [showUserMenu]);

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


  const handleFileUpload = async (file: File) => {
    if (!file) return;

    // 检查文件类型
    const allowedTypes = ['.txt', '.log', '.csv'];
    const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
    
    if (!allowedTypes.includes(fileExtension)) {
      setError('仅支持 TXT、LOG 和 CSV 文件');
      return;
    }

    setIsLoading(true);
    setError(null);
    setAnalysisResult(null);
    setFileName(file.name);

    try {
      const response = await uploadLogFile(file);
      
      if (response.status === 'success' && response.ai_analysis) {
        setAnalysisResult(response.ai_analysis);
        loadLogRecords();
      } else {
        setError('分析失败，请重试');
      }
    } catch (err: any) {
      setError(err.response?.data?.message || '上传失败，请稍后重试');
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileUpload(file);
    }
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const file = e.dataTransfer.files?.[0];
    if (file) {
      handleFileUpload(file);
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'Critical':
        return 'border-red-500 bg-red-500/10';
      case 'High':
        return 'border-red-400 bg-red-400/10';
      case 'Medium':
        return 'border-yellow-400 bg-yellow-400/10';
      case 'Low':
        return 'border-green-400 bg-green-400/10';
      default:
        return 'border-gray-500 bg-gray-500/10';
    }
  };

  const getThreatLevelTextColor = (level: string) => {
    switch (level) {
      case 'Critical':
        return 'text-red-400';
      case 'High':
        return 'text-red-400';
      case 'Medium':
        return 'text-yellow-400';
      case 'Low':
        return 'text-green-400';
      default:
        return 'text-gray-400';
    }
  };

  const statusLabel = (status: LogRecord['status']) => {
    switch (status) {
      case 'resolved':
        return '已解决';
      case 'ignored':
        return '忽略';
      default:
        return '未解决';
    }
  };

  const handleStatusChange = async (recordId: number, status: LogRecord['status']) => {
    try {
      const result = await updateLogRecordStatus(recordId, status);
      if (result.status === 'success') {
        setLogRecords((prev) =>
          prev.map((item) => (item.id === recordId ? { ...item, status } : item))
        );
      }
    } catch (error) {
      setLogRecordsError('状态更新失败');
    }
  };

  const handleDeleteRecord = async (recordId: number) => {
    if (!window.confirm('确认删除该日志记录吗？')) return;
    try {
      const result = await deleteLogRecord(recordId);
      if (result.status === 'success') {
        setLogRecords((prev) => prev.filter((item) => item.id !== recordId));
      }
    } catch (error) {
      setLogRecordsError('删除失败');
    }
  };

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'Critical':
      case 'High':
        return <ShieldAlert className="w-6 h-6 text-red-400" />;
      case 'Medium':
        return <AlertTriangle className="w-6 h-6 text-yellow-400" />;
      case 'Low':
        return <CheckCircle className="w-6 h-6 text-green-400" />;
      default:
        return <Shield className="w-6 h-6 text-gray-400" />;
    }
  };

  const formatLogTime = (value?: string) => {
    if (!value) return '-';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return value;
    return date.toLocaleString();
  };

  // 如果未认证，不渲染内容
  if (!isAuthenticated) {
    return null;
  }

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
        <header className="h-16 bg-slate-900/50 backdrop-blur border-b border-white/5 flex items-center justify-between px-6 relative z-50">
          <div>
            <h1 className="text-xl font-bold text-white">智能日志分析</h1>
            <p className="text-xs text-gray-400">AI-Powered Log Analysis</p>
          </div>
          
          <div className="flex items-center gap-4">
            <LLMProviderToggle onAuthExpired={handleLogout} />

            {/* 搜索框 */}
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                placeholder="搜索日志、IP、威胁..."
                className="pl-10 pr-4 py-2 bg-slate-800/50 border border-white/5 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 w-64"
              />
            </div>

            {/* 用户信息 */}
            <div className="flex items-center gap-3">
              <button className="p-2 text-gray-400 hover:text-white transition-colors">
                <Bell className="w-5 h-5" />
              </button>
              <button className="p-2 text-gray-400 hover:text-white transition-colors">
                <HelpCircle className="w-5 h-5" />
              </button>
              {/* 用户头像和信息 */}
              <div className="relative z-[9999]" ref={userMenuRef}>
                <button
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  className="flex items-center gap-2 hover:bg-slate-800/50 rounded-lg p-1.5 transition-colors"
                >
                  <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center border border-cyan-500/30">
                    <User className="w-4 h-4 text-cyan-400" />
                  </div>
                  <div className="text-right">
                    <p className="text-sm font-medium text-white">
                      {userInfo?.full_name || userInfo?.username || '用户'}
                    </p>
                    <p className="text-xs text-gray-400">
                      {userInfo?.role === 'admin' ? '系统管理员' : '普通用户'}
                    </p>
                  </div>
                </button>

                {/* 用户信息悬浮卡片 */}
                {showUserMenu && (
                  <div className="fixed top-16 right-6 w-72 bg-slate-900 border border-slate-700 rounded-lg shadow-2xl z-[9999] overflow-hidden">
                    {/* 头部背景 */}
                    <div className="bg-gradient-to-r from-cyan-500/20 to-blue-500/20 p-4 border-b border-slate-700">
                      <div className="flex items-center gap-3">
                        <div className="w-12 h-12 rounded-full bg-cyan-500/30 flex items-center justify-center border-2 border-cyan-500/50">
                          <User className="w-6 h-6 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-lg font-semibold text-white">
                            {userInfo?.full_name || userInfo?.username || '用户'}
                          </p>
                          <p className="text-sm text-cyan-400">@{userInfo?.username || 'user'}</p>
                        </div>
                      </div>
                    </div>

                    {/* 用户详情 */}
                    <div className="p-4 space-y-3">
                      <div className="flex items-center gap-3 text-sm">
                        <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                          <Shield className="w-4 h-4 text-cyan-400" />
                        </div>
                        <div>
                          <p className="text-gray-400 text-xs">角色</p>
                          <p className="text-white font-medium">
                            {userInfo?.role === 'admin' ? '系统管理员' : '普通用户'}
                          </p>
                        </div>
                      </div>

                      {userInfo?.email && (
                        <div className="flex items-center gap-3 text-sm">
                          <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                            <svg className="w-4 h-4 text-cyan-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
                            </svg>
                          </div>
                          <div>
                            <p className="text-gray-400 text-xs">邮箱</p>
                            <p className="text-white font-medium">{userInfo.email}</p>
                          </div>
                        </div>
                      )}

                      <div className="flex items-center gap-3 text-sm">
                        <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center">
                          <svg className="w-4 h-4 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                          </svg>
                        </div>
                        <div>
                          <p className="text-gray-400 text-xs">状态</p>
                          <p className="text-green-400 font-medium">在线</p>
                        </div>
                      </div>
                    </div>

                    {/* 操作按钮 */}
                    <div className="border-t border-slate-700 p-2">
                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                      >
                        <LogOut className="w-4 h-4" />
                        <span>退出登录</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </header>

        {/* 可滚动内容 */}
        <div className="flex-1 overflow-y-auto p-6 relative z-0">
          <div className="max-w-5xl mx-auto space-y-6">
            {/* 文件上传区域 */}
            <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-8">
              <h2 className="text-2xl font-bold text-white mb-2 flex items-center gap-2">
                <FileCode className="w-6 h-6 text-cyan-400" />
                日志文件上传
              </h2>
              <p className="text-gray-400 mb-6">上传日志文件，AI 将自动分析其中的安全威胁</p>

              {/* 隐藏的文件输入 */}
              <input
                ref={fileInputRef}
                type="file"
                accept=".txt,.log,.csv"
                onChange={handleFileSelect}
                className="hidden"
              />

              {/* 拖拽上传区域 */}
              <div
                ref={dropZoneRef}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-lg p-12 text-center cursor-pointer transition-all ${
                  isDragging
                    ? 'border-cyan-400 bg-cyan-400/10'
                    : 'border-gray-700 hover:border-cyan-500/50 hover:bg-slate-800/30'
                }`}
              >
                {isLoading ? (
                  <div className="space-y-4">
                    <div className="inline-block w-16 h-16 border-4 border-cyan-400 border-t-transparent rounded-full animate-spin"></div>
                    <p className="text-cyan-400 text-lg font-semibold">系统正在扫描中...</p>
                    <p className="text-gray-400 text-sm">正在分析日志文件，请稍候</p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <UploadCloud className="w-16 h-16 text-cyan-400 mx-auto" />
                    <div>
                      <p className="text-white text-lg font-semibold mb-2">
                        拖拽文件到此处或点击上传
                      </p>
                      <p className="text-gray-400 text-sm">
                        支持 TXT、LOG、CSV 格式文件
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* 错误提示 */}
              {error && (
                <div className="mt-4 p-4 bg-red-500/20 border border-red-500/30 rounded-lg flex items-center gap-3">
                  <XCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
                  <p className="text-red-400">{error}</p>
                </div>
              )}

              {/* 文件名显示 */}
              {fileName && !isLoading && (
                <div className="mt-4 p-4 bg-slate-800/50 rounded-lg flex items-center gap-3">
                  <FileCode className="w-5 h-5 text-cyan-400" />
                  <span className="text-gray-300">{fileName}</span>
                </div>
              )}
            </div>

            {/* 分析结果展示 */}
            {analysisResult && (
              <div className="space-y-6">
                {/* 威胁概览卡片 */}
                <div
                  className={`bg-slate-900/50 backdrop-blur border-2 rounded-lg p-6 ${getThreatLevelColor(
                    analysisResult.threat_level
                  )}`}
                >
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex items-center gap-3">
                      {getThreatIcon(analysisResult.threat_level)}
                      <div>
                        <h3 className="text-xl font-bold text-white">威胁分析结果</h3>
                        <p className={`text-sm font-semibold ${getThreatLevelTextColor(analysisResult.threat_level)}`}>
                          威胁级别: {analysisResult.threat_level}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* 摘要 */}
                  <div className="mb-4">
                    <p className="text-gray-300 leading-relaxed">{analysisResult.summary}</p>
                  </div>

                  {/* 建议 */}
                  <div className="p-4 bg-slate-800/50 rounded-lg border border-white/5">
                    <p className="text-sm font-semibold text-cyan-400 mb-2">💡 安全建议</p>
                    <p className="text-gray-300 text-sm">{analysisResult.advice}</p>
                  </div>
                </div>

                {/* 威胁详情列表 */}
                {analysisResult.details && analysisResult.details.length > 0 && (
                  <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
                    <h3 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
                      <ShieldAlert className="w-5 h-5 text-red-400" />
                      威胁详情
                    </h3>
                    <div className="space-y-4">
                      {analysisResult.details.map((detail, index) => (
                        <div
                          key={index}
                          className="bg-slate-800/50 border border-white/5 rounded-lg p-4 hover:border-red-500/30 transition-all"
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex items-center gap-2">
                              <div className="w-2 h-2 bg-red-400 rounded-full"></div>
                              <span className="text-red-400 font-semibold">{detail.type}</span>
                            </div>
                            <span className="text-gray-400 text-sm">#{index + 1}</span>
                          </div>

                          <div className="space-y-2">
                            {/* Payload 代码块 */}
                            <div>
                              <p className="text-xs text-gray-400 mb-1">Payload:</p>
                              <div className="bg-slate-950 border border-gray-700 rounded p-3 font-mono text-sm">
                                <code className="text-cyan-400 break-all">{detail.payload}</code>
                              </div>
                            </div>

                            {/* 源 IP */}
                            <div className="flex items-center gap-2 text-sm">
                              <span className="text-gray-400">源 IP:</span>
                              <span className="text-white font-mono">{detail.source_ip}</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* 日志审计记录 */}
            <div className="bg-slate-900/50 backdrop-blur border border-white/5 rounded-lg p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                  日志审计记录
                </h3>
                <button
                  onClick={loadLogRecords}
                  className="text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  刷新
                </button>
              </div>

              {logRecordsError && (
                <div className="mb-3 text-sm text-red-400">{logRecordsError}</div>
              )}

              {logRecords.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="text-left text-gray-400 border-b border-slate-700">
                        <th className="py-2 pr-4">时间</th>
                        <th className="py-2 pr-4">文件</th>
                        <th className="py-2 pr-4">等级</th>
                        <th className="py-2 pr-4">类型</th>
                        <th className="py-2 pr-4">源 IP</th>
                        <th className="py-2 pr-4">摘要</th>
                        <th className="py-2">状态</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logRecords.map((record) => (
                        <tr key={record.id} className="border-b border-slate-800 text-gray-300">
                          <td className="py-2 pr-4 whitespace-nowrap">{formatLogTime(record.upload_time)}</td>
                          <td className="py-2 pr-4">{record.filename || '-'}</td>
                          <td className={`py-2 pr-4 ${getThreatLevelTextColor(record.threat_level)}`}>
                            {record.threat_level || 'Unknown'}
                          </td>
                          <td className="py-2 pr-4">{record.attack_type || '-'}</td>
                          <td className="py-2 pr-4 font-mono">{record.source_ip || '-'}</td>
                          <td className="py-2 pr-4 max-w-[360px] truncate">{record.summary || '-'}</td>
                          <td className="py-2 flex items-center gap-2">
                            <select
                              value={record.status}
                              onChange={(event) =>
                                handleStatusChange(
                                  record.id,
                                  event.target.value as LogRecord['status']
                                )
                              }
                              className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-gray-200"
                            >
                              <option value="unresolved">未解决</option>
                              <option value="resolved">已解决</option>
                              <option value="ignored">忽略</option>
                            </select>
                            <span className="text-xs text-gray-400">{statusLabel(record.status)}</span>
                            <button
                              onClick={() => handleDeleteRecord(record.id)}
                              className="ml-2 text-xs text-red-400 hover:text-red-300"
                            >
                              删除
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="text-gray-400 text-sm">暂无日志审计记录</div>
              )}
            </div>

            {/* 空状态提示 */}
            {!analysisResult && !isLoading && !error && (
              <div className="text-center py-12">
                <Shield className="w-16 h-16 text-cyan-400 mx-auto mb-4 opacity-50" />
                <p className="text-gray-400 text-lg">上传日志文件开始分析</p>
                <p className="text-gray-500 text-sm mt-2">
                  AI 将自动检测日志中的安全威胁和异常行为
                </p>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
