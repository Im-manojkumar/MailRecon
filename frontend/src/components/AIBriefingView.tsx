'use client';

import React, { useState } from 'react';
import { AIAnalysisResponse } from '@/lib/types';
import { Bot, Check, Copy, CheckCircle2, AlertTriangle, ShieldCheck, Target, Crosshair, ListChecks, Zap } from 'lucide-react';

interface Props {
  aiData: AIAnalysisResponse | null;
}

export default function AIBriefingView({ aiData }: Props) {
  const [copiedAction, setCopiedAction] = useState<number | null>(null);

  if (!aiData) {
    return (
      <div className="p-12 text-center text-gray-500 border border-dashed border-gray-800 rounded-lg">
        <Bot className="w-10 h-10 mx-auto mb-3 opacity-40 animate-pulse" />
        <p className="text-sm font-medium text-gray-400">AI forensic briefing pending or not available</p>
        <p className="text-xs text-gray-600 mt-1">
          Forensic LLM briefings are synthesized asynchronously from parsed evidence and detector signals.
        </p>
      </div>
    );
  }

  const handleCopyAction = (actionText: string, index: number) => {
    navigator.clipboard.writeText(actionText);
    setCopiedAction(index);
    setTimeout(() => setCopiedAction(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner with Provider & Grounding Badge */}
      <div className="flex flex-wrap items-center justify-between p-4 bg-gray-900/60 border border-gray-800 rounded-lg gap-4">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded bg-indigo-950/80 border border-indigo-700/60 text-indigo-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="text-sm font-semibold text-gray-200">
              Forensic LLM Intelligence Briefing
            </div>
            <div className="text-xs text-gray-500 font-mono">
              Provider Engine: <span className="text-indigo-400 uppercase">{aiData.provider}</span>
            </div>
          </div>
        </div>

        {/* Grounding Integrity Badge */}
        <div>
          {aiData.is_grounded ? (
            <div className="flex items-center space-x-2 px-3 py-1.5 bg-emerald-950/80 border border-emerald-700/80 rounded-full text-emerald-300 text-xs">
              <ShieldCheck className="w-4 h-4 text-emerald-400 flex-shrink-0" />
              <span className="font-medium">Verified Grounded Evidence (Zero Hallucination)</span>
            </div>
          ) : (
            <div className="flex items-center space-x-2 px-3 py-1.5 bg-amber-950/80 border border-amber-700/80 rounded-full text-amber-300 text-xs">
              <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
              <span className="font-medium">Unverified Grounding Citations</span>
            </div>
          )}
        </div>
      </div>

      {/* Executive Summary & Attack Vector Card */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 bg-gray-900/80 border border-gray-800 rounded-lg space-y-3">
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-2">
            <Zap className="w-4 h-4 text-yellow-400" />
            <span>Executive Forensic Summary</span>
          </h3>
          <p className="text-sm text-gray-200 leading-relaxed font-sans">
            {aiData.executive_summary}
          </p>
        </div>

        <div className="p-5 bg-gray-900/80 border border-gray-800 rounded-lg space-y-3">
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-2">
            <Target className="w-4 h-4 text-red-400" />
            <span>Attack Classification</span>
          </h3>
          <div className="text-sm font-semibold text-red-300 font-mono bg-red-950/40 p-2.5 rounded border border-red-900/60">
            {aiData.attack_vector}
          </div>
          <p className="text-xs text-gray-500">
            Assessed vector based on header provenance and payload markers.
          </p>
        </div>
      </div>

      {/* Threat Actor Tactics & Evidence Citations */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Tactics */}
        <div className="p-5 bg-gray-900/80 border border-gray-800 rounded-lg space-y-4">
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-2">
            <Crosshair className="w-4 h-4 text-orange-400" />
            <span>Observed Adversary Tactics</span>
          </h3>
          {aiData.threat_actor_tactics && aiData.threat_actor_tactics.length > 0 ? (
            <ul className="space-y-2 text-xs">
              {aiData.threat_actor_tactics.map((tactic, idx) => (
                <li key={idx} className="flex items-start space-x-2 text-gray-300">
                  <div className="w-1.5 h-1.5 rounded-full bg-orange-400 mt-1.5 flex-shrink-0" />
                  <span className="leading-relaxed">{tactic}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-gray-500">No specific adversary tactics recorded.</p>
          )}
        </div>

        {/* Evidence Citations */}
        <div className="p-5 bg-gray-900/80 border border-gray-800 rounded-lg space-y-4">
          <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Grounded Evidence Citations</span>
          </h3>
          {aiData.evidence_citations && aiData.evidence_citations.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {aiData.evidence_citations.map((cite, idx) => (
                <span
                  key={idx}
                  className="px-2.5 py-1 text-xs font-mono bg-gray-950 text-indigo-300 border border-gray-800 rounded-md"
                >
                  {cite}
                </span>
              ))}
            </div>
          ) : (
            <p className="text-xs text-gray-500">No explicit indicator citations extracted.</p>
          )}
        </div>
      </div>

      {/* Recommended SOC Containment Actions */}
      <div className="p-5 bg-gray-900/80 border border-gray-800 rounded-lg space-y-4">
        <h3 className="text-xs font-bold text-gray-400 uppercase tracking-wider flex items-center space-x-2">
          <ListChecks className="w-4 h-4 text-primary-400" />
          <span>Recommended Incident Containment Actions</span>
        </h3>
        {aiData.recommended_actions && aiData.recommended_actions.length > 0 ? (
          <div className="space-y-2.5">
            {aiData.recommended_actions.map((act, idx) => (
              <div
                key={idx}
                className="flex items-center justify-between p-3 bg-gray-950/70 border border-gray-800/80 rounded-lg hover:border-gray-700 transition-colors"
              >
                <div className="flex items-start space-x-3 text-xs text-gray-200">
                  <span className="font-mono text-indigo-400 font-bold">{idx + 1}.</span>
                  <span className="leading-relaxed">{act}</span>
                </div>
                <button
                  onClick={() => handleCopyAction(act, idx)}
                  className="p-1.5 text-gray-400 hover:text-white rounded hover:bg-gray-800 transition-colors flex-shrink-0 ml-3"
                  title="Copy action to clipboard"
                >
                  {copiedAction === idx ? (
                    <Check className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-gray-500">No automated actions recommended.</p>
        )}
      </div>
    </div>
  );
}
