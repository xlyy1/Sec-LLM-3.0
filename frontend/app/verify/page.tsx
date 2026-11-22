'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { verifyEmail } from '@/lib/api';
import { ArrowRight, CheckCircle2, XCircle } from 'lucide-react';

function VerifyContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const token = searchParams.get('token');
  const [tokenInput, setTokenInput] = useState(token || '');

  const [loading, setLoading] = useState(true);
  const [success, setSuccess] = useState(false);
  const [message, setMessage] = useState('正在验证您的邮箱，请稍候...');

  const runVerify = async (verifyToken: string) => {
    if (!verifyToken) {
      setSuccess(false);
      setMessage('请输入激活令牌。');
      setLoading(false);
      return;
    }

    try {
      const res = await verifyEmail(verifyToken);
      setSuccess(true);
      setMessage(res.message || '账户激活成功！现在可以登录了。');
    } catch (err: any) {
      setSuccess(false);
      setMessage(err.response?.data?.detail || '验证失败，链接可能已过期。');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const run = async () => {
      if (!token) {
        setSuccess(false);
        setMessage('未检测到链接令牌，可手动粘贴邮件中的激活令牌完成验证。');
        setLoading(false);
        return;
      }
      try {
        await runVerify(token);
      } finally {
        // runVerify already updates loading state.
      }
    };

    void run();
  }, [token]);

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center px-6">
      <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-slate-900 p-8 shadow-2xl">
        <h1 className="text-2xl font-bold text-white mb-3">邮箱验证</h1>
        <p className="text-gray-400 mb-8">Sec-LLM 账户激活流程</p>

        <div
          className={`rounded-xl border p-4 mb-8 ${
            loading
              ? 'border-cyan-700 bg-cyan-900/20'
              : success
              ? 'border-emerald-700 bg-emerald-900/20'
              : 'border-red-700 bg-red-900/20'
          }`}
        >
          <div className="flex items-start gap-3">
            {loading ? (
              <div className="mt-0.5 h-5 w-5 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
            ) : success ? (
              <CheckCircle2 className="h-5 w-5 text-emerald-400 mt-0.5" />
            ) : (
              <XCircle className="h-5 w-5 text-red-400 mt-0.5" />
            )}
            <p className="text-sm text-gray-200">{message}</p>
          </div>
        </div>

        {!success && (
          <div className="mb-6">
            <label htmlFor="manualToken" className="block text-sm text-gray-300 mb-2">
              手动激活令牌
            </label>
            <textarea
              id="manualToken"
              value={tokenInput}
              onChange={(e) => setTokenInput(e.target.value)}
              placeholder="粘贴邮件中的 token（eyJ...）"
              rows={4}
              className="w-full rounded-lg border border-slate-700 bg-slate-950 text-gray-100 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-cyan-500"
            />
            <button
              type="button"
              onClick={() => {
                setLoading(true);
                void runVerify(tokenInput.trim());
              }}
              disabled={loading || !tokenInput.trim()}
              className="mt-3 w-full py-2 px-3 bg-slate-700 hover:bg-slate-600 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? '验证中...' : '手动激活'}
            </button>
          </div>
        )}

        <button
          onClick={() => router.push('/login')}
          className="w-full py-3 px-4 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 text-white font-semibold rounded-lg transition-all duration-200 flex items-center justify-center gap-2"
        >
          <span>返回登录</span>
          <ArrowRight className="w-5 h-5" />
        </button>
      </div>
    </div>
  );
}

export default function VerifyPage() {
  return (
    <Suspense fallback={<div className="min-h-screen bg-slate-950 flex items-center justify-center"><div className="text-cyan-400 animate-pulse">加载中...</div></div>}>
      <VerifyContent />
    </Suspense>
  );
}
