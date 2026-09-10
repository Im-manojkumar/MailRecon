'use client';

import React, { useEffect, useState } from 'react';
import ProtectedRoute from '@/components/ProtectedRoute';
import FileUpload from '@/components/FileUpload';
import { api } from '@/lib/api';
import { CaseDetail } from '@/lib/types';
import StatusBadge from '@/components/StatusBadge';
import Link from 'next/link';

export default function Dashboard() {
  const [cases, setCases] = useState<CaseDetail[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.cases.list()
      .then(res => {
        setCases(res.cases);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  return (
    <ProtectedRoute>
      <div className="space-y-8">
        <section className="text-center py-12">
          <h1 className="text-4xl font-extrabold text-white tracking-tight mb-4">
            Evidence-First Email Threat Detection
          </h1>
          <p className="text-xl text-gray-400 max-w-2xl mx-auto">
            Upload raw .eml files for automated parsing, indicator extraction, and AI-driven analysis.
          </p>
        </section>

        <section className="max-w-2xl mx-auto">
          <FileUpload />
        </section>

        <section className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-8">
          <div className="bg-surface p-6 rounded-lg border border-gray-800">
            <h3 className="text-lg font-semibold text-gray-200 mb-2">Total Cases Analyzed</h3>
            <p className="text-3xl font-bold text-primary-400">{cases.length}</p>
          </div>
          <div className="bg-surface p-6 rounded-lg border border-gray-800">
            <h3 className="text-lg font-semibold text-gray-200 mb-2">Threats Detected</h3>
            <p className="text-3xl font-bold text-red-400">0 <span className="text-sm font-normal text-gray-500">(Placeholder)</span></p>
          </div>
        </section>

        <section className="pt-8">
          <h2 className="text-2xl font-bold text-white mb-6">Recent Cases</h2>
          {loading ? (
            <p className="text-gray-400">Loading cases...</p>
          ) : cases.length === 0 ? (
            <div className="bg-surface p-8 rounded-lg border border-gray-800 text-center">
              <p className="text-gray-400">No cases found. Upload an email to get started.</p>
            </div>
          ) : (
            <div className="bg-surface border border-gray-800 rounded-lg overflow-hidden">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-gray-900 border-b border-gray-800 text-gray-400 text-sm">
                    <th className="px-6 py-3 font-medium">File Name</th>
                    <th className="px-6 py-3 font-medium">Status</th>
                    <th className="px-6 py-3 font-medium">Created At</th>
                    <th className="px-6 py-3 font-medium text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {cases.map((c) => (
                    <tr key={c.id} className="hover:bg-gray-800/50 transition-colors">
                      <td className="px-6 py-4 text-sm font-medium text-gray-200">{c.file_name}</td>
                      <td className="px-6 py-4"><StatusBadge status={c.status} /></td>
                      <td className="px-6 py-4 text-sm text-gray-400">{new Date(c.created_at).toLocaleString()}</td>
                      <td className="px-6 py-4 text-right">
                        <Link href={`/cases/${c.id}`} className="text-primary-400 hover:text-primary-300 text-sm font-medium">
                          View Details &rarr;
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </ProtectedRoute>
  );
}
