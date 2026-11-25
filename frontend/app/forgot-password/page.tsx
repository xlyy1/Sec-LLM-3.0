'use client';

import { useState } from 'react';
import Link from 'next/link';
import { forgotPassword } from '@/lib/api';

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState('');
  const [message, setMessage] = useState('');
  const [resetLink, setResetLink] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setLoading(true);
    setError('');
    setMessage('');
    try {
      const result = await forgotPassword(email);
      setMessage(result.message || '如果该邮箱已注册，我们已发送重置链接');
      if (result.reset_token) {
        setResetLink(`/reset-password?token=${encodeURIComponent(result.reset_token)}`);
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || '发送失败，请稍后重试');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900/60 p-8">
        <h1 className="text-2xl font-semibold text-white mb-2">找回密码</h1>
        <p className="text-sm text-gray-400 mb-6">输入注册邮箱，我们会发送 30 分钟内有效的重置链接。</p>
        <form onSubmit={submit} className="space-y-4">
          <input
            type="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            placeholder="you@example.com"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          {error && <p className="text-sm text-red-400">{error}</p>}
          {message && <p className="text-sm text-emerald-400">{message}</p>}
          {resetLink && (
            <Link href={resetLink} className="block text-sm text-cyan-400 hover:text-cyan-300">
              开发环境重置链接（生产不会返回）
            </Link>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-cyan-500 py-3 font-medium text-slate-950 hover:bg-cyan-400 disabled:opacity-50"
          >
            {loading ? '发送中...' : '发送重置链接'}
          </button>
        </form>
        <div className="mt-6 text-sm text-gray-400">
          <Link href="/login" className="text-cyan-400 hover:text-cyan-300">返回登录</Link>
        </div>
      </div>
    </div>
  );
}
