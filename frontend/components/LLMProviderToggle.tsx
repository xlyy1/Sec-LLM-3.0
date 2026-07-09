'use client';

import { useEffect, useRef, useState } from 'react';
import { getLLMProvider, setLLMProvider, type LLMProvider } from '@/lib/api';

interface LLMProviderToggleProps {
  className?: string;
  onAuthExpired?: () => void;
  onProviderChange?: (provider: LLMProvider) => void;
}

export default function LLMProviderToggle({
  className,
  onAuthExpired,
  onProviderChange,
}: LLMProviderToggleProps) {
  const [activeProvider, setActiveProvider] = useState<LLMProvider>('local');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const onProviderChangeRef = useRef(onProviderChange);
  onProviderChangeRef.current = onProviderChange;

  useEffect(() => {
    const loadProvider = async () => {
      try {
        const data = await getLLMProvider();
        setActiveProvider(data.provider);
        onProviderChangeRef.current?.(data.provider);
      } catch (err: any) {
        if (err?.response?.status === 401 && onAuthExpired) {
          onAuthExpired();
          return;
        }
        setError(err?.response?.data?.detail || '引擎状态读取失败');
      }
    };
    void loadProvider();
  }, [onAuthExpired]);

  const handleToggle = async () => {
    if (loading) return;
    const targetProvider: LLMProvider = activeProvider === 'local' ? 'cloud' : 'local';
    setLoading(true);
    setError(null);
    try {
      const result = await setLLMProvider(targetProvider);
      setActiveProvider(result.provider);
      onProviderChangeRef.current?.(result.provider);
    } catch (err: any) {
      if (err?.response?.status === 401 && onAuthExpired) {
        onAuthExpired();
        return;
      }
      setError(err?.response?.data?.detail || '引擎切换失败');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={className}>
      <div className="flex items-center gap-3 px-3 py-2 bg-slate-800/50 border border-white/5 rounded-lg">
        <span className="text-xs text-gray-400">本地</span>
        <button
          onClick={handleToggle}
          disabled={loading}
          className={`relative inline-flex h-6 w-12 items-center rounded-full transition-colors ${
            activeProvider === 'cloud' ? 'bg-purple-500/80' : 'bg-cyan-500/80'
          } ${loading ? 'opacity-60 cursor-not-allowed' : ''}`}
          title="切换 AI 引擎"
        >
          <span
            className={`inline-block h-5 w-5 transform rounded-full bg-white transition-transform ${
              activeProvider === 'cloud' ? 'translate-x-6' : 'translate-x-1'
            }`}
          />
        </button>
        <span className="text-xs text-gray-300">云端</span>
      </div>
      {error && <div className="mt-1 text-xs text-red-400">{error}</div>}
    </div>
  );
}
