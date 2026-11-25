'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { resetPassword } from '@/lib/api';

export default function ResetPasswordPage() {
  const [token, setToken] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    setToken(params.get('token') || '');
  }, []);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError('');
    setMessage('');
    if (password !== confirm) {
      setError('两次输入的密码不一致');
      return;
    }
    setLoading(true);
    try {
      const result = await resetPassword(token, password);
      setMessage(result.message || '密码已重置');
    } catch (err: any) {
      setError(err?.response?.data?.detail || '重置失败，链接可能已过期');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-6">
      <div className="w-full max-w-md rounded-2xl border border-white/10 bg-slate-900/60 p-8">
        <h1 className="text-2xl font-semibold text-white mb-2">设置新密码</h1>
        <p className="text-sm text-gray-400 mb-6">重置成功后所有已登录会话都会失效。</p>
        <form onSubmit={submit} className="space-y-4">
          <input
            type="password"
            required
            minLength={10}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="新密码（至少 10 位）"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          <input
            type="password"
            required
            minLength={10}
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            placeholder="再次输入新密码"
            className="w-full rounded-lg border border-slate-700 bg-slate-950 px-4 py-3 text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-cyan-500"
          />
          {error && <p className="text-sm text-red-400">{error}</p>}
          {message && <p className="text-sm text-emerald-400">{message}</p>}
          <button
            type="submit"
            disabled={loading || !token}
            className="w-full rounded-lg bg-cyan-500 py-3 font-medium text-slate-950 hover:bg-cyan-400 disabled:opacity-50"
          >
            {loading ? '提交中...' : '重置密码'}
          </button>
        </form>
        <div className="mt-6 text-sm text-gray-400">
          <Link href="/login" className="text-cyan-400 hover:text-cyan-300">返回登录</Link>
        </div>
      </div>
    </div>
  );
}
