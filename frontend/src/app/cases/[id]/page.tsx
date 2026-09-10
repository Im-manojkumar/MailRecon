'use client';

import React, { useState, useEffect } from 'react';
import ProtectedRoute from '@/components/ProtectedRoute';
import { api } from '@/lib/api';
import { CaseDetail, RiskScoreResponse, FindingResponse, Severity } from '@/lib/types';
import StatusBadge from '@/components/StatusBadge';
import SeverityBadge from '@/components/SeverityBadge';

export default function CaseDetailPage({ params }: { params: { id: string } }) {
  const [activeTab, setActiveTab] = useState('summary');
  const [caseData, setCaseData] = useState<CaseDetail | null>(null);
  const [score, setScore] = useState<RiskScoreResponse | null>(null);
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      api.cases.get(params.id),
      api.cases.getScore(params.id).catch(() => null),
      api.cases.getFindings(params.id).catch(() => ({ findings: [] }))
    ]).then(([caseRes, scoreRes, findingsRes]) => {
      setCaseData(caseRes);
      setScore(scoreRes);
      setFindings(findingsRes.findings);
      setLoading(false);
    }).catch(err => {
      console.error(err);
      setLoading(false);
    });
  }, [params.id]);

  if (loading) return <ProtectedRoute><div className="text-gray-400">Loading case details...</div></ProtectedRoute>;
  if (!caseData) return <ProtectedRoute><div className="text-red-400">Case not found</div></ProtectedRoute>;

  const tabs = ['summary', 'headers', 'findings', 'graph', 'route map', 'report'];

  return (
    <ProtectedRoute>
      <div className="space-y-6">
        <div className="flex items-center justify-between border-b border-gray-800 pb-4">
          <div>
            <h1 className="text-2xl font-bold text-white mb-2">{caseData.file_name}</h1>
            <div className="flex space-x-4 text-sm text-gray-400">
              <span>ID: {caseData.id}</span>
              <span>Created: {new Date(caseData.created_at).toLocaleString()}</span>
            </div>
          </div>
          <StatusBadge status={caseData.status} />
        </div>

        <div className="flex space-x-1 border-b border-gray-800">
          {tabs.map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2 text-sm font-medium capitalize border-b-2 transition-colors ${
                activeTab === tab 
                  ? 'border-primary-500 text-primary-400' 
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="bg-surface border border-gray-800 rounded-lg p-6 min-h-[400px]">
          {activeTab === 'summary' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-6 border border-gray-800 rounded-lg bg-gray-900/50">
                <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center justify-between">
                  Risk Score
                  <span className="text-xs bg-gray-800 text-gray-300 px-2 py-1 rounded">Heuristic</span>
                </h3>
                {score ? (
                  <div className="text-center py-6">
                    <div className="text-5xl font-black text-white mb-2">{score.score}</div>
                    <div className="text-xl text-primary-400 capitalize">{score.label}</div>
                  </div>
                ) : (
                  <div className="text-gray-500 text-center py-6">Score not calculated yet</div>
                )}
              </div>
              <div className="p-6 border border-gray-800 rounded-lg bg-gray-900/50">
                <h3 className="text-lg font-semibold text-gray-200 mb-4">Case Info</h3>
                <dl className="space-y-4 text-sm">
                  <div className="grid grid-cols-3 gap-4">
                    <dt className="text-gray-500">File Name</dt>
                    <dd className="col-span-2 text-gray-200 font-mono">{caseData.file_name}</dd>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <dt className="text-gray-500">Status</dt>
                    <dd className="col-span-2"><StatusBadge status={caseData.status} /></dd>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <dt className="text-gray-500">Created</dt>
                    <dd className="col-span-2 text-gray-300">{new Date(caseData.created_at).toLocaleString()}</dd>
                  </div>
                </dl>
              </div>
            </div>
          )}

          {activeTab === 'headers' && (
            <div className="text-gray-400 flex items-center justify-center h-64">
              Headers will be displayed here after analysis
            </div>
          )}

          {activeTab === 'findings' && (
            <div>
              {findings.length === 0 ? (
                <div className="text-gray-400 flex items-center justify-center h-64">
                  No findings detected yet.
                </div>
              ) : (
                <table className="w-full text-left border-collapse">
                  <thead>
                    <tr className="bg-gray-900 border-b border-gray-800 text-gray-400 text-sm">
                      <th className="px-4 py-3 font-medium">Severity</th>
                      <th className="px-4 py-3 font-medium">Detector</th>
                      <th className="px-4 py-3 font-medium">Title</th>
                      <th className="px-4 py-3 font-medium">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800 text-sm">
                    {findings.map((f) => (
                      <tr key={f.id} className="hover:bg-gray-800/50">
                        <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                        <td className="px-4 py-3 text-gray-400 font-mono">{f.detector_name}</td>
                        <td className="px-4 py-3 text-gray-200">{f.title}</td>
                        <td className="px-4 py-3 text-gray-400">{(f.confidence * 100).toFixed(0)}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {activeTab === 'graph' && (
            <div className="text-gray-400 flex items-center justify-center h-[500px] border border-dashed border-gray-700 rounded">
              Indicator graph will appear after analysis
            </div>
          )}

          {activeTab === 'route map' && (
            <div className="text-gray-400 flex items-center justify-center h-[500px] border border-dashed border-gray-700 rounded">
              Route map will appear after GeoIP enrichment
            </div>
          )}

          {activeTab === 'report' && (
            <div className="space-y-6">
              <button className="bg-primary-600 hover:bg-primary-500 text-white font-medium py-2 px-4 rounded transition-colors">
                Generate Report
              </button>
              <div className="text-gray-400 pt-8 border-t border-gray-800">
                No reports generated yet.
              </div>
            </div>
          )}
        </div>
      </div>
    </ProtectedRoute>
  );
}
