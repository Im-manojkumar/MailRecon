'use client';

import React from 'react';
import Link from 'next/link';
import { Shield } from 'lucide-react';
import { AuthProvider, useAuth } from '@/lib/auth-context';

function Navbar() {
  const { analyst, logout } = useAuth();
  
  return (
    <header className="bg-surface border-b border-gray-800">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        <Link href="/" className="flex items-center space-x-2 text-primary-400 hover:text-primary-300 transition-colors">
          <Shield className="w-6 h-6" />
          <span className="font-bold text-lg tracking-wide">MailRecon AI</span>
        </Link>
        <nav className="flex items-center space-x-6">
          {analyst ? (
            <>
              <Link href="/" className="text-sm font-medium text-gray-300 hover:text-white transition-colors">Cases</Link>
              <Link href="/campaigns" className="text-sm font-medium text-gray-300 hover:text-white transition-colors flex items-center gap-1.5">
                <span>Threat Campaigns</span>
                <span className="px-1.5 py-0.2 bg-purple-950 text-purple-300 border border-purple-800 rounded text-[10px] font-mono">CORRELATED</span>
              </Link>
              <div className="h-4 w-px bg-gray-700" />
              <span className="text-sm text-gray-400">{analyst.display_name}</span>
              <button onClick={logout} className="text-sm font-medium text-red-400 hover:text-red-300">
                Logout
              </button>
            </>
          ) : (
            <>
              <Link href="/login" className="text-sm font-medium text-gray-300 hover:text-white">Login</Link>
              <Link href="/register" className="text-sm font-medium bg-primary-600 hover:bg-primary-500 text-white px-3 py-1.5 rounded">Register</Link>
            </>
          )}
        </nav>
      </div>
    </header>
  );
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col bg-background text-gray-200">
        <AuthProvider>
          <Navbar />
          <main className="flex-grow max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8">
            {children}
          </main>
          <footer className="bg-surface border-t border-gray-800 py-6 mt-auto">
            <div className="max-w-7xl mx-auto px-4 text-center text-sm text-gray-500">
              MailRecon AI &mdash; Evidence-First Threat Detection
            </div>
          </footer>
        </AuthProvider>
      </body>
    </html>
  );
}
