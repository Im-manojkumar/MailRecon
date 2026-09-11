'use client';

import React, { useState } from 'react';
import { useAuth } from '@/lib/auth-context';
import { api } from '@/lib/api';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Shield } from 'lucide-react';

export default function LoginPage() {
  const [email, setEmail] = useState('analyst@mailrecon.io');
  const [password, setPassword] = useState('Password123!');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const res = await api.auth.login(email, password);
      await login(res.access_token);
      router.push('/');
    } catch (err: any) {
      setError(err.message || 'Login failed. Check credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center">
      <div className="bg-surface p-8 rounded-lg border border-gray-800 w-full max-w-md shadow-2xl">
        <div className="flex flex-col items-center mb-8">
          <Shield className="w-12 h-12 text-primary-500 mb-2" />
          <h1 className="text-2xl font-bold text-white">Analyst Login</h1>
          <div className="mt-2 text-xs bg-primary-950/60 border border-primary-800 text-primary-300 px-3 py-1.5 rounded-full flex items-center gap-1.5">
            <span>Demo:</span>
            <span className="font-mono text-white">analyst@mailrecon.io</span>
            <span>/</span>
            <span className="font-mono text-white">Password123!</span>
          </div>
        </div>
        
        {error && <div className="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded mb-6 text-sm">{error}</div>}
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Email</label>
            <input 
              type="email" 
              required
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Password</label>
            <input 
              type="password" 
              required
              value={password}
              onChange={e => setPassword(e.target.value)}
              className="w-full bg-gray-900 border border-gray-700 rounded px-4 py-2 text-white focus:outline-none focus:border-primary-500 focus:ring-1 focus:ring-primary-500"
            />
          </div>
          <button 
            type="submit" 
            disabled={loading}
            className="w-full bg-primary-600 hover:bg-primary-500 text-white font-medium py-2 px-4 rounded transition-colors disabled:opacity-50 mt-4"
          >
            {loading ? 'Authenticating...' : 'Sign In'}
          </button>
        </form>
        
        <div className="mt-6 text-center text-sm text-gray-500">
          Need an account? <Link href="/register" className="text-primary-400 hover:underline">Register</Link>
        </div>
      </div>
    </div>
  );
}
