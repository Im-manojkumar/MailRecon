'use client';

import React from 'react';
import { RiskScoreResponse } from '@/lib/types';
import { AlertTriangle, CheckCircle2, HelpCircle, ShieldAlert, ShieldCheck } from 'lucide-react';

interface Props {
  score: RiskScoreResponse | null;
}

export default function RiskScoreCard({ score }: Props) {
  if (!score) {
    return (
      <div className="p-6 border border-gray-800 rounded-lg bg-gray-900/50 flex flex-col items-center justify-center min-h-[220px]">
        <HelpCircle className="w-8 h-8 text-gray-500 mb-2 animate-pulse" />
        <p className="text-gray-400 text-sm">Risk score pending analysis...</p>
      </div>
    );
  }

  const getScoreColor = (val: number) => {
    if (val >= 75) return { text: 'text-red-400', border: 'border-red-500/30', bg: 'bg-red-950/40', bar: 'bg-red-500' };
    if (val >= 50) return { text: 'text-orange-400', border: 'border-orange-500/30', bg: 'bg-orange-950/40', bar: 'bg-orange-500' };
    if (val >= 25) return { text: 'text-yellow-400', border: 'border-yellow-500/30', bg: 'bg-yellow-950/40', bar: 'bg-yellow-500' };
    return { text: 'text-emerald-400', border: 'border-emerald-500/30', bg: 'bg-emerald-950/40', bar: 'bg-emerald-500' };
  };

  const getThreatLabel = (val: number) => {
    if (val >= 75) return 'Malicious Threat';
    if (val >= 50) return 'High Risk';
    if (val >= 25) return 'Suspicious';
    return 'Low / Clean';
  };

  const getUncertaintyBadge = (uncertainty: string) => {
    const map: Record<string, { label: string; style: string }> = {
      definitive: { label: 'Definitive', style: 'bg-emerald-950 text-emerald-300 border-emerald-700' },
      probable: { label: 'Probable', style: 'bg-blue-950 text-blue-300 border-blue-700' },
      inconclusive: { label: 'Inconclusive', style: 'bg-yellow-950 text-yellow-300 border-yellow-700' },
      unverifiable: { label: 'Unverifiable', style: 'bg-red-950 text-red-300 border-red-700' },
    };
    const item = map[uncertainty.toLowerCase()] || { label: uncertainty, style: 'bg-gray-800 text-gray-300 border-gray-700' };
    return (
      <span className={`px-2 py-0.5 text-xs font-semibold uppercase tracking-wider border rounded ${item.style}`}>
        {item.label}
      </span>
    );
  };

  const colors = getScoreColor(score.score);
  const confidencePct = Math.round((score.confidence ?? 0) * 100);
  const coveragePct = Math.round((score.coverage ?? 0) * 100);

  return (
    <div className={`p-6 border rounded-lg bg-gray-900/60 ${colors.border} space-y-6`}>
      {/* Header with Heuristic Notice */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          {score.score >= 50 ? (
            <ShieldAlert className="w-5 h-5 text-red-400" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          )}
          <h3 className="text-base font-semibold text-gray-200">Forensic Threat Assessment</h3>
        </div>
        <div className="flex items-center space-x-2">
          {getUncertaintyBadge(score.uncertainty_label)}
          <span className="px-2 py-0.5 text-xs font-mono font-semibold uppercase tracking-wider bg-indigo-950/80 text-indigo-300 border border-indigo-700/60 rounded">
            Heuristic
          </span>
        </div>
      </div>

      {/* Main Score & Threat Level */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-lg bg-black/40 border border-gray-800/80">
        <div className="flex items-baseline space-x-3">
          <span className={`text-6xl font-black font-mono tracking-tight ${colors.text}`}>
            {Math.round(score.score)}
          </span>
          <span className="text-lg text-gray-500 font-mono">/100</span>
        </div>
        <div className="sm:text-right">
          <div className={`text-lg font-bold ${colors.text}`}>
            {getThreatLabel(score.score)}
          </div>
          <p className="text-xs text-gray-400 mt-0.5">
            Non-linear saturation curve (no fabricated certainty)
          </p>
        </div>
      </div>

      {/* Progress Bars: Confidence & Coverage */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        {/* Heuristic Confidence */}
        <div className="space-y-1.5 p-3 rounded bg-gray-950/60 border border-gray-800/60">
          <div className="flex justify-between text-xs">
            <span className="text-gray-400 font-medium">Detector Confidence</span>
            <span className="text-gray-200 font-mono font-semibold">{confidencePct}%</span>
          </div>
          <div className="w-full bg-gray-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-indigo-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${confidencePct}%` }}
            />
          </div>
          <p className="text-[11px] text-gray-500">Signal-to-noise ratio of activated rules</p>
        </div>

        {/* Forensic Coverage */}
        <div className="space-y-1.5 p-3 rounded bg-gray-950/60 border border-gray-800/60">
          <div className="flex justify-between text-xs">
            <span className="text-gray-400 font-medium">Forensic Coverage</span>
            <span className="text-gray-200 font-mono font-semibold">{coveragePct}%</span>
          </div>
          <div className="w-full bg-gray-800 h-2 rounded-full overflow-hidden">
            <div
              className="bg-cyan-500 h-full rounded-full transition-all duration-500"
              style={{ width: `${coveragePct}%` }}
            />
          </div>
          <p className="text-[11px] text-gray-500">Headers, hops, body, attachments, URLs</p>
        </div>
      </div>

      {/* Narrative Summary */}
      <div className="text-xs text-gray-300 leading-relaxed p-3 rounded bg-gray-950/40 border border-gray-800/50">
        <span className="font-semibold text-gray-200">Assessment: </span>
        {score.summary}
      </div>
    </div>
  );
}
