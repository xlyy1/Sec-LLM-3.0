'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { User, Lock, Eye, EyeOff, ArrowRight, Shield, Mail } from 'lucide-react';
import { login, resendVerification } from '@/lib/api';
import Image from 'next/image';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [showResendBox, setShowResendBox] = useState(false);
  const [verifyEmail, setVerifyEmail] = useState('');
  const [resendLoading, setResendLoading] = useState(false);
  const [resendMessage, setResendMessage] = useState('');
  const [resendError, setResendError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      const response = await login({ username, password });
      
      // 清除之前的缓存数据
      localStorage.removeItem('cyberguard_chat_history');
      localStorage.removeItem('cyberguard_log_analysis');
      localStorage.removeItem('cyberguard_latest_log_report');
      
      // Save token to localStorage (使用新的 access_token)
      localStorage.setItem('token', response.access_token);
      
      // 存储用户信息
      localStorage.setItem('user', JSON.stringify(response.user));
      
      // Redirect to dashboard
      router.push('/');
    } catch (err: any) {
      const detail = err.response?.data?.detail || '登录失败，请检查用户名和密码';
      setError(detail);
      if (typeof detail === 'string' && detail.includes('账户未激活')) {
        setShowResendBox(true);
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendVerification = async () => {
    setResendError('');
    setResendMessage('');
    setResendLoading(true);
    try {
      const res = await resendVerification(verifyEmail);
      setResendMessage(res.message || '验证邮件已发送，请查收。');
    } catch (err: any) {
      setResendError(err.response?.data?.detail || '发送失败，请稍后重试');
    } finally {
      setResendLoading(false);
    }
  };

  return (
    <div className="flex h-screen">
      {/* Left Side - Branding Area */}
      <div className="relative w-1/2 h-full overflow-hidden">
        <Image
          src="/login-bg.jpg"
          alt="背景"
          fill
          className="object-cover"
          priority
        />
        <div className="absolute inset-0 bg-gradient-to-r from-black/60 via-black/40 to-transparent" />
        
        <div className="relative z-10 h-full flex flex-col justify-between p-12">
          {/* Logo */}
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-cyan-400" />
            <div className="flex flex-col">
              <span className="text-2xl font-bold text-white leading-tight">灵犀网卫</span>
              <span className="text-2xl font-bold text-white leading-tight">Sec-LLM</span>
            </div>
          </div>

          {/* Headline and Subtext */}
          <div className="flex-1 flex flex-col justify-center">
            <h1 className="text-5xl font-bold text-white mb-6">
              用智能赋能安全
            </h1>
            <p className="text-xl text-gray-300 max-w-lg">
              利用下一代人工智能的力量，通过预测性威胁分析和实时防御机制保护您的数字资产。
            </p>
          </div>

          {/* Footer */}
          <div className="text-sm text-gray-300">
            © 2026 灵犀网卫—Sec-LLM 平台。保留所有权利。
          </div>
        </div>
      </div>

      {/* Right Side - Login Form */}
      <div className="w-1/2 bg-slate-950 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          <div className="bg-slate-900 rounded-lg border border-slate-800 p-8 shadow-2xl">
            {/* Card Header */}
            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-white mb-2">欢迎回来</h2>
              <p className="text-gray-400">请输入您的凭据以访问安全门户。</p>
            </div>

            {/* Login Form */}
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Username Field */}
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-300 mb-2">
                  用户名
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="请输入您的用户名"
                    required
                    className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Password Field */}
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2">
                  密码
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="请输入您的密码"
                    required
                    className="w-full pl-10 pr-12 py-3 bg-slate-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-300"
                  >
                    {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
              </div>

              {/* Error Message */}
              {error && (
                <div className="text-red-400 text-sm text-center">{error}</div>
              )}

              {/* Resend Verification Entry */}
              <div className="text-sm">
                <button
                  type="button"
                  onClick={() => {
                    setShowResendBox(!showResendBox);
                    setResendError('');
                    setResendMessage('');
                  }}
                  className="text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  收不到邮件或账号未激活？重发验证邮件
                </button>

                {showResendBox && (
                  <div className="mt-3 rounded-lg border border-slate-700 bg-slate-800/60 p-3">
                    <label htmlFor="verifyEmail" className="block text-gray-300 mb-2">
                      注册邮箱
                    </label>
                    <div className="relative">
                      <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                      <input
                        id="verifyEmail"
                        type="email"
                        value={verifyEmail}
                        onChange={(e) => setVerifyEmail(e.target.value)}
                        placeholder="请输入注册时使用的邮箱"
                        className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                      />
                    </div>
                    {resendError && <p className="text-red-400 mt-2">{resendError}</p>}
                    {resendMessage && <p className="text-emerald-400 mt-2">{resendMessage}</p>}
                    <button
                      type="button"
                      onClick={handleResendVerification}
                      disabled={resendLoading || !verifyEmail}
                      className="mt-3 w-full py-2 px-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {resendLoading ? '发送中...' : '发送验证邮件'}
                    </button>
                  </div>
                )}
              </div>

              {/* Login Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 text-white font-semibold rounded-lg transition-all duration-200 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>登录中...</span>
                  </>
                ) : (
                  <>
                    <span>安全登录</span>
                    <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </button>

              {/* Additional Links */}
              <div className="flex text-sm">
                <a href="#" className="text-gray-400 hover:text-cyan-400 transition-colors">
                  忘记密码？
                </a>
              </div>

              {/* Register Link */}
              <div className="text-center text-sm text-gray-400">
                没有账户？{' '}
                <a href="/register" className="text-cyan-400 hover:text-cyan-300 transition-colors">
                  立即注册
                </a>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
