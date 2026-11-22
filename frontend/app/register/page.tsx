'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { User, Lock, Eye, EyeOff, ArrowRight, Shield, Mail, UserCircle } from 'lucide-react';
import { register } from '@/lib/api';
import Image from 'next/image';

export default function RegisterPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [email, setEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // 验证密码
    if (password !== confirmPassword) {
      setError('两次输入的密码不一致');
      return;
    }

    if (password.length < 6) {
      setError('密码长度至少为6位');
      return;
    }

    setIsLoading(true);

    try {
      const response = await register({
        username,
        password,
        email: email || undefined,
        full_name: fullName || undefined
      });

      alert(response.message || '注册成功！验证邮件已发送到您的邮箱，请查收链接以激活账户。');
      router.push('/login');
    } catch (err: any) {
      setError(err.response?.data?.detail || '注册失败，请稍后重试');
    } finally {
      setIsLoading(false);
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
              加入我们
            </h1>
            <p className="text-xl text-gray-300 max-w-lg">
              创建您的账户，开启智能安全防护之旅。享受 AI 驱动的威胁分析、日志审计和安全报告功能。
            </p>
          </div>

          {/* Footer */}
          <div className="text-sm text-gray-300">
            © 2026 灵犀网卫—Sec-LLM 平台。保留所有权利。
          </div>
        </div>
      </div>

      {/* Right Side - Register Form */}
      <div className="w-1/2 bg-slate-950 flex items-center justify-center p-8 overflow-y-auto">
        <div className="w-full max-w-md">
          <div className="bg-slate-900 rounded-lg border border-slate-800 p-8 shadow-2xl">
            {/* Card Header */}
            <div className="text-center mb-6">
              <h2 className="text-3xl font-bold text-white mb-2">创建账户</h2>
              <p className="text-gray-400">填写以下信息完成注册</p>
            </div>

            {/* Register Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Username Field */}
              <div>
                <label htmlFor="username" className="block text-sm font-medium text-gray-300 mb-2">
                  用户名 <span className="text-red-400">*</span>
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="请输入用户名"
                    required
                    className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Full Name Field */}
              <div>
                <label htmlFor="fullName" className="block text-sm font-medium text-gray-300 mb-2">
                  姓名
                </label>
                <div className="relative">
                  <UserCircle className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="fullName"
                    type="text"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="请输入您的姓名（选填）"
                    className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Email Field */}
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-2">
                  邮箱 <span className="text-red-400">*</span>
                </label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="请输入邮箱"
                    required
                    className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Password Field */}
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-2">
                  密码 <span className="text-red-400">*</span>
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="请输入密码（至少6位）"
                    required
                    minLength={6}
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

              {/* Confirm Password Field */}
              <div>
                <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-300 mb-2">
                  确认密码 <span className="text-red-400">*</span>
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    id="confirmPassword"
                    type={showPassword ? 'text' : 'password'}
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="请再次输入密码"
                    required
                    className="w-full pl-10 pr-4 py-3 bg-slate-900 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 focus:border-transparent"
                  />
                </div>
              </div>

              {/* Error Message */}
              {error && (
                <div className="text-red-400 text-sm text-center bg-red-400/10 py-2 rounded-lg">{error}</div>
              )}

              {/* Register Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 text-white font-semibold rounded-lg transition-all duration-200 flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed mt-6"
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>注册中...</span>
                  </>
                ) : (
                  <>
                    <span>立即注册</span>
                    <ArrowRight className="w-5 h-5" />
                  </>
                )}
              </button>

              {/* Login Link */}
              <div className="text-center text-sm text-gray-400 mt-4">
                已有账户？{' '}
                <a href="/login" className="text-cyan-400 hover:text-cyan-300 transition-colors">
                  立即登录
                </a>
              </div>
            </form>
          </div>
        </div>
      </div>
    </div>
  );
}
