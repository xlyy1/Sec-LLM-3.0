'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import api from '@/lib/api';

type Role = 'admin' | 'operator' | 'viewer';

interface UserRow {
  id: number;
  username: string;
  email: string | null;
  full_name: string | null;
  role: Role | string;
  is_active: boolean;
  last_login: string | null;
}

const ROLES: Role[] = ['admin', 'operator', 'viewer'];

export default function AdminUsersPage() {
  const router = useRouter();
  const [users, setUsers] = useState<UserRow[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const response = await api.get('/api/admin/users');
      setUsers(response.data.users || []);
      setError('');
    } catch (err: any) {
      if (err?.response?.status === 401) {
        router.push('/login');
        return;
      }
      setError(err?.response?.data?.detail || '加载用户列表失败（需要管理员权限）');
    } finally {
      setLoading(false);
    }
  }, [router]);

  useEffect(() => {
    load();
  }, [load]);

  const changeRole = async (user: UserRow, role: Role) => {
    try {
      await api.put(`/api/admin/users/${user.id}/role`, { role });
      await load();
    } catch (err: any) {
      setError(err?.response?.data?.detail || '修改角色失败');
    }
  };

  const toggleActive = async (user: UserRow) => {
    try {
      await api.put(`/api/admin/users/${user.id}/active`, { is_active: !user.is_active });
      await load();
    } catch (err: any) {
      setError(err?.response?.data?.detail || '修改状态失败');
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-semibold">用户与角色</h1>
            <p className="text-sm text-slate-400 mt-1">
              admin 可管理全部用户；operator 可执行扫描与对话；viewer 只读。
            </p>
          </div>
          <Link href="/" className="text-sm text-cyan-400 hover:text-cyan-300">
            返回控制台
          </Link>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        <div className="overflow-hidden rounded-xl border border-slate-800">
          <table className="w-full text-sm">
            <thead className="bg-slate-900 text-slate-400">
              <tr>
                <th className="px-4 py-3 text-left">用户</th>
                <th className="px-4 py-3 text-left">邮箱</th>
                <th className="px-4 py-3 text-left">角色</th>
                <th className="px-4 py-3 text-left">状态</th>
                <th className="px-4 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className="border-t border-slate-800/80">
                  <td className="px-4 py-3">
                    <div className="font-medium">{user.username}</div>
                    <div className="text-xs text-slate-500">{user.full_name || '—'}</div>
                  </td>
                  <td className="px-4 py-3 text-slate-400">{user.email || '—'}</td>
                  <td className="px-4 py-3">
                    <select
                      value={ROLES.includes(user.role as Role) ? user.role : 'viewer'}
                      onChange={(event) => changeRole(user, event.target.value as Role)}
                      className="rounded-md border border-slate-700 bg-slate-900 px-2 py-1"
                    >
                      {ROLES.map((role) => (
                        <option key={role} value={role}>{role}</option>
                      ))}
                    </select>
                  </td>
                  <td className="px-4 py-3">
                    <span className={user.is_active ? 'text-emerald-400' : 'text-slate-500'}>
                      {user.is_active ? '启用' : '停用'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => toggleActive(user)}
                      className="rounded-md border border-slate-700 px-3 py-1 text-xs hover:bg-slate-800"
                    >
                      {user.is_active ? '停用' : '启用'}
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && users.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                    暂无用户
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
