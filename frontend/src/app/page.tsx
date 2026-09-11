'use client';

import React, { useEffect, useState } from 'react';
import ProtectedRoute from '@/components/ProtectedRoute';
import FileUpload from '@/components/FileUpload';
import { api } from '@/lib/api';
import { CaseResponse } from '@/lib/types';
import StatusBadge from '@/components/StatusBadge';
import Link from 'next/link';
import { Shield, ShieldAlert, AlertTriangle, CheckCircle, Search, Filter, ArrowRight } from 'lucide-react';

export default function Dashboard() {
  const [cases, setCases] = useState<CaseResponse[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');

  useEffect(() => {
    api.cases.list()
      .then(res => {
        setCases(res.items || res.cases || []);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  const threatCount = cases.filter(
    (c) => (c.risk_score != null && c.risk_score >= 40) || (c.threat_category && c.threat_category !== 'LEGITIMATE')
  ).length;

  const criticalCount = cases.filter(
    (c) => (c.risk_score != null && c.risk_score >= 70) || c.threat_category === 'MALWARE_DELIVERY' || c.threat_category === 'PAYMENT_DIVERSION'
  ).length;

  const filteredCases = cases.filter((c) => {
    const filename = (c.filename || c.file_name || '').toLowerCase();
    const category = (c.threat_category || '').toLowerCase();
    const matchesSearch = filename.includes(searchTerm.toLowerCase()) || category.includes(searchTerm.toLowerCase());
    const matchesCategory = selectedCategory === 'ALL' || c.threat_category === selectedCategory;
    return matchesSearch && matchesCategory;
  });

  const getThreatCategoryBadge = (category?: string | null, label?: string | null) => {
    if (!category) {
      return <span className="text-xs text-gray-500 font-mono">Unclassified</span>;
    }

    switch (category) {
      case 'CREDENTIAL_PHISHING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-950 text-rose-300 border border-rose-800">
            <ShieldAlert className="w-3 h-3" />
            <span>Phishing</span>
          </span>
        );
      case 'PAYMENT_DIVERSION':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950 text-amber-300 border border-amber-800">
            <AlertTriangle className="w-3 h-3" />
            <span>Wire Fraud</span>
          </span>
        );
      case 'MALWARE_DELIVERY':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-red-950 text-red-300 border border-red-800">
            <ShieldAlert className="w-3 h-3" />
            <span>Malware</span>
          </span>
        );
      case 'CEO_IMPERSONATION':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-800">
            <ShieldAlert className="w-3 h-3" />
            <span>Executive Impersonation</span>
          </span>
        );
      case 'SPAM_RECONNAISSANCE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-yellow-950 text-yellow-300 border border-yellow-800">
            <span>Spam Recon</span>
          </span>
        );
      case 'LEGITIMATE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
            <CheckCircle className="w-3 h-3" />
            <span>Clean</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono bg-gray-800 text-gray-300 border border-gray-700">
            {label || category}
          </span>
        );
    }
  };

  return (
    <ProtectedRoute>
      <div className="space-y-8 max-w-7xl mx-auto pb-12">
        <section className="text-center py-10">
          <h1 className="text-4xl font-extrabold text-white tracking-tight mb-3 font-mono">
            Evidence-First Email Threat Forensics
          </h1>
          <p className="text-base text-gray-400 max-w-2xl mx-auto">
            Automated RFC 5322 MIME dissection, live GeoIP origin traceability, wire fraud forensics, and cross-case campaign clustering.
          </p>
        </section>

        <section className="max-w-2xl mx-auto">
          <FileUpload />
        </section>

        {/* Executive Metrics Overview */}
        <section className="grid grid-cols-1 md:grid-cols-3 gap-5 pt-4">
          <div className="bg-surface p-6 rounded-lg border border-gray-800 space-y-1">
            <div className="flex items-center justify-between text-xs font-mono text-gray-400 uppercase tracking-wider">
              <span>Total Cases Analyzed</span>
              <Shield className="w-4 h-4 text-indigo-400" />
            </div>
            <p className="text-3xl font-black text-white font-mono">{cases.length}</p>
            <p className="text-xs text-gray-500">Forensic email investigations registered</p>
          </div>

          <div className="bg-surface p-6 rounded-lg border border-gray-800 space-y-1">
            <div className="flex items-center justify-between text-xs font-mono text-gray-400 uppercase tracking-wider">
              <span>Threats Detected</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <p className="text-3xl font-black text-amber-400 font-mono">{threatCount}</p>
            <p className="text-xs text-gray-500">Phishing, wire fraud, and spoofing attacks</p>
          </div>

          <div className="bg-surface p-6 rounded-lg border border-gray-800 space-y-1">
            <div className="flex items-center justify-between text-xs font-mono text-gray-400 uppercase tracking-wider">
              <span>Critical Incidents</span>
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <p className="text-3xl font-black text-red-400 font-mono">{criticalCount}</p>
            <p className="text-xs text-gray-500">Requiring immediate containment action</p>
          </div>
        </section>

        {/* Cases Management Workspace */}
        <section className="pt-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-gray-800 pb-4">
            <div>
              <h2 className="text-xl font-bold text-white tracking-tight">Forensic Case Records</h2>
              <p className="text-xs text-gray-400">Search, filter, and inspect verified evidence chains</p>
            </div>

            <div className="flex items-center gap-3">
              <div className="relative">
                <Search className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search cases or threats..."
                  className="pl-9 pr-3 py-1.5 bg-gray-900 border border-gray-800 rounded-md text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-indigo-500 w-52 sm:w-64"
                />
              </div>

              <select
                value={selectedCategory}
                onChange={(e) => setSelectedCategory(e.target.value)}
                className="px-3 py-1.5 bg-gray-900 border border-gray-800 rounded-md text-xs text-gray-300 focus:outline-none focus:border-indigo-500 font-mono"
              >
                <option value="ALL">All Threat Categories</option>
                <option value="CREDENTIAL_PHISHING">Phishing</option>
                <option value="PAYMENT_DIVERSION">Wire Fraud / Diversion</option>
                <option value="MALWARE_DELIVERY">Malware Delivery</option>
                <option value="CEO_IMPERSONATION">Executive Impersonation</option>
                <option value="LEGITIMATE">Clean Communication</option>
              </select>
            </div>
          </div>

          {loading ? (
            <div className="bg-surface p-12 rounded-lg border border-gray-800 text-center text-gray-400 text-sm">
              <Shield className="w-8 h-8 text-indigo-500 animate-pulse mx-auto mb-2" />
              Loading forensic case database...
            </div>
          ) : filteredCases.length === 0 ? (
            <div className="bg-surface p-12 rounded-lg border border-gray-800 text-center space-y-2">
              <p className="text-gray-300 text-sm font-semibold">No cases match your filter criteria.</p>
              <p className="text-gray-500 text-xs">Upload an .eml email file above to initiate automated forensic analysis.</p>
            </div>
          ) : (
            <div className="bg-surface border border-gray-800 rounded-lg overflow-hidden shadow-lg shadow-black/20">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-gray-900/80 border-b border-gray-800 text-gray-400 text-xs uppercase tracking-wider font-mono">
                      <th className="px-5 py-3 font-semibold">Evidence File</th>
                      <th className="px-5 py-3 font-semibold">Threat Classification</th>
                      <th className="px-5 py-3 font-semibold">Risk Score</th>
                      <th className="px-5 py-3 font-semibold">Status</th>
                      <th className="px-5 py-3 font-semibold">Ingestion Timestamp</th>
                      <th className="px-5 py-3 font-semibold text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/80 text-xs">
                    {filteredCases.map((c) => (
                      <tr key={c.id} className="hover:bg-gray-800/40 transition-colors">
                        <td className="px-5 py-3.5 font-mono text-gray-200 font-medium">
                          <Link href={`/cases/${c.id}`} className="hover:text-indigo-400 transition-colors">
                            {c.filename || c.file_name || `case_${c.id.substring(0, 8)}.eml`}
                          </Link>
                        </td>
                        <td className="px-5 py-3.5">
                          {getThreatCategoryBadge(c.threat_category, c.category_label)}
                        </td>
                        <td className="px-5 py-3.5">
                          {c.risk_score != null ? (
                            <span className={`px-2 py-0.5 rounded font-mono font-bold text-[11px] ${
                              c.risk_score >= 70 ? 'bg-red-950 text-red-300 border border-red-800' :
                              c.risk_score >= 40 ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                              'bg-emerald-950 text-emerald-300 border border-emerald-800'
                            }`}>
                              {Math.round(c.risk_score)} / 100
                            </span>
                          ) : (
                            <span className="text-gray-500 font-mono">Pending</span>
                          )}
                        </td>
                        <td className="px-5 py-3.5">
                          <StatusBadge status={c.status} />
                        </td>
                        <td className="px-5 py-3.5 text-gray-400 font-mono text-[11px]">
                          {new Date(c.created_at).toLocaleString()}
                        </td>
                        <td className="px-5 py-3.5 text-right">
                          <Link
                            href={`/cases/${c.id}`}
                            className="inline-flex items-center space-x-1 text-indigo-400 hover:text-indigo-300 font-semibold"
                          >
                            <span>Investigate</span>
                            <ArrowRight className="w-3.5 h-3.5" />
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </section>
      </div>
    </ProtectedRoute>
  );
}
