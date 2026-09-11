'use client';

import React, { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import { PlaybookResponse, PlaybookItem } from '@/lib/types';
import {
  ShieldAlert,
  Terminal,
  CheckCircle2,
  Circle,
  Copy,
  Check,
  Download,
  FileCode2,
  Layers,
  Server,
  Lock,
  DollarSign,
  AlertOctagon,
  RefreshCw,
  ChevronDown,
  ChevronRight,
  Code,
} from 'lucide-react';

interface Props {
  caseId: string;
}

export default function IncidentResponseView({ caseId }: Props) {
  const [playbook, setPlaybook] = useState<PlaybookResponse | null>(null);
  const [loadingPlaybook, setLoadingPlaybook] = useState(true);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [selectedPillar, setSelectedPillar] = useState<string>('ALL');

  // Rule Export states
  const [activeExportFormat, setActiveExportFormat] = useState<'stix' | 'yara' | 'sigma' | 'snort'>('stix');
  const [exportContent, setExportContent] = useState<string>('');
  const [loadingExport, setLoadingExport] = useState(false);
  const [copiedExport, setCopiedExport] = useState(false);
  const [copiedScriptId, setCopiedScriptId] = useState<string | null>(null);
  const [expandedActionIds, setExpandedActionIds] = useState<Set<string>>(new Set());

  const fetchPlaybook = async () => {
    try {
      setLoadingPlaybook(true);
      const data = await api.cases.getPlaybook(caseId);
      setPlaybook(data);
      // Default expand critical items
      const criticals = new Set(
        data.items.filter((i) => i.priority === 'CRITICAL').map((i) => i.action_id)
      );
      setExpandedActionIds(criticals);
    } catch (err) {
      console.error('Failed to load playbook:', err);
    } finally {
      setLoadingPlaybook(false);
    }
  };

  const fetchExport = async (format: 'stix' | 'yara' | 'sigma' | 'snort') => {
    try {
      setLoadingExport(true);
      const content = await api.cases.getExportContent(caseId, format);
      setExportContent(content);
    } catch (err) {
      console.error('Failed to fetch export rule:', err);
      setExportContent(`// Error loading ${format.toUpperCase()} export`);
    } finally {
      setLoadingExport(false);
    }
  };

  useEffect(() => {
    fetchPlaybook();
    fetchExport(activeExportFormat);
  }, [caseId]);

  const handleFormatChange = (fmt: 'stix' | 'yara' | 'sigma' | 'snort') => {
    setActiveExportFormat(fmt);
    fetchExport(fmt);
  };

  const handleToggleAction = async (action: PlaybookItem) => {
    try {
      setTogglingId(action.action_id);
      const updated = await api.cases.togglePlaybookAction(caseId, action.action_id, !action.completed);
      setPlaybook(updated);
    } catch (err) {
      console.error('Failed to toggle action:', err);
    } finally {
      setTogglingId(null);
    }
  };

  const toggleExpand = (actionId: string) => {
    const next = new Set(expandedActionIds);
    if (next.has(actionId)) {
      next.delete(actionId);
    } else {
      next.add(actionId);
    }
    setExpandedActionIds(next);
  };

  const handleCopyScript = (id: string, scriptText: string) => {
    navigator.clipboard.writeText(scriptText);
    setCopiedScriptId(id);
    setTimeout(() => setCopiedScriptId(null), 2000);
  };

  const handleCopyExport = () => {
    navigator.clipboard.writeText(exportContent);
    setCopiedExport(true);
    setTimeout(() => setCopiedExport(false), 2000);
  };

  const handleDownloadExport = () => {
    const extensions = {
      stix: 'json',
      yara: 'yar',
      sigma: 'yml',
      snort: 'rules',
    };
    const blob = new Blob([exportContent], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `MailRecon-${caseId}-${activeExportFormat}.${extensions[activeExportFormat]}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const filteredItems = playbook?.items.filter((item) => {
    if (selectedPillar === 'ALL') return true;
    return item.pillar === selectedPillar;
  }) || [];

  const completionPct = playbook?.total_actions
    ? Math.round((playbook.completed_actions / playbook.total_actions) * 100)
    : 0;

  const getPillarIcon = (pillar: string) => {
    switch (pillar) {
      case 'EMAIL_GATEWAY':
        return <Server className="w-4 h-4 text-indigo-400" />;
      case 'ENDPOINT_EDR':
        return <Terminal className="w-4 h-4 text-emerald-400" />;
      case 'IDENTITY_IAM':
        return <Lock className="w-4 h-4 text-amber-400" />;
      case 'FINANCIAL_LEGAL':
        return <DollarSign className="w-4 h-4 text-red-400" />;
      default:
        return <Layers className="w-4 h-4 text-gray-400" />;
    }
  };

  const getPriorityBadge = (priority: string) => {
    switch (priority) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-700/80';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-400 border-amber-700/80';
      case 'MEDIUM':
        return 'bg-blue-950/80 text-blue-400 border-blue-700/80';
      default:
        return 'bg-gray-800 text-gray-400 border-gray-700';
    }
  };

  return (
    <div className="space-y-8">
      {/* SECTION 1: PLAYBOOK CHECKLIST */}
      <div className="space-y-4">
        {/* Playbook Header & Metrics */}
        <div className="flex flex-wrap items-center justify-between gap-4 p-4 bg-gray-900 border border-gray-800 rounded-lg">
          <div>
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-bold text-gray-100">
                Automated Incident Response Playbook
              </h2>
            </div>
            <p className="text-xs text-gray-400 mt-0.5">
              Pillar-separated remediation workflows with ready-to-execute PowerShell & CLI containment scripts.
            </p>
          </div>

          {playbook && (
            <div className="flex items-center space-x-4">
              <div className="flex flex-col items-end">
                <span className="text-xs font-semibold text-gray-300">
                  Containment Progress: {playbook.completed_actions} / {playbook.total_actions} ({completionPct}%)
                </span>
                <div className="w-36 h-2 bg-gray-800 rounded-full mt-1.5 overflow-hidden border border-gray-700">
                  <div
                    className={`h-full transition-all duration-300 ${
                      completionPct === 100 ? 'bg-emerald-500' : 'bg-indigo-500'
                    }`}
                    style={{ width: `${completionPct}%` }}
                  />
                </div>
              </div>

              {playbook.critical_actions > 0 && (
                <div className="px-2.5 py-1 bg-red-950/70 border border-red-800 text-red-300 rounded text-xs flex items-center gap-1.5">
                  <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
                  <span>{playbook.critical_actions} Critical</span>
                </div>
              )}

              <button
                onClick={fetchPlaybook}
                disabled={loadingPlaybook}
                className="p-1.5 text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded transition-colors"
                title="Refresh Playbook"
              >
                <RefreshCw className={`w-4 h-4 ${loadingPlaybook ? 'animate-spin' : ''}`} />
              </button>
            </div>
          )}
        </div>

        {/* Pillar Filter Tabs */}
        <div className="flex flex-wrap gap-2 pt-1 border-b border-gray-800 pb-3">
          {[
            { id: 'ALL', label: 'All Remediation Steps', icon: Layers },
            { id: 'EMAIL_GATEWAY', label: '1. Email Gateway (M365)', icon: Server },
            { id: 'ENDPOINT_EDR', label: '2. Endpoint & EDR', icon: Terminal },
            { id: 'IDENTITY_IAM', label: '3. Identity & IAM', icon: Lock },
            { id: 'FINANCIAL_LEGAL', label: '4. Financial & Wire Fraud', icon: DollarSign },
          ].map((tab) => {
            const Icon = tab.icon;
            const count = tab.id === 'ALL'
              ? playbook?.items.length
              : playbook?.items.filter((i) => i.pillar === tab.id).length;
            const isActive = selectedPillar === tab.id;

            return (
              <button
                key={tab.id}
                onClick={() => setSelectedPillar(tab.id)}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors border ${
                  isActive
                    ? 'bg-indigo-600/20 text-indigo-300 border-indigo-500/60'
                    : 'bg-gray-900/60 text-gray-400 border-gray-800 hover:text-gray-200 hover:bg-gray-800'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
                {count !== undefined && (
                  <span className="ml-1 px-1.5 py-0.2 bg-gray-800/80 text-[10px] rounded text-gray-300 font-mono">
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Playbook Item Cards */}
        {loadingPlaybook ? (
          <div className="p-8 text-center text-gray-500 text-sm">
            <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-indigo-400" />
            Loading response playbooks...
          </div>
        ) : filteredItems.length === 0 ? (
          <div className="p-6 text-center text-gray-500 text-xs bg-gray-900/40 rounded border border-gray-800">
            No playbook actions in this category.
          </div>
        ) : (
          <div className="space-y-3">
            {filteredItems.map((item) => {
              const isExpanded = expandedActionIds.has(item.action_id);
              const isToggling = togglingId === item.action_id;

              return (
                <div
                  key={item.action_id}
                  className={`border rounded-lg transition-all ${
                    item.completed
                      ? 'bg-gray-900/30 border-gray-800/60 opacity-75'
                      : item.priority === 'CRITICAL'
                      ? 'bg-gray-900/80 border-red-900/40'
                      : 'bg-gray-900/70 border-gray-800'
                  }`}
                >
                  {/* Item Main Row */}
                  <div className="p-3.5 flex items-start justify-between gap-3">
                    <div className="flex items-start space-x-3 flex-1 min-w-0">
                      {/* Checkbox */}
                      <button
                        onClick={() => handleToggleAction(item)}
                        disabled={isToggling}
                        className="mt-0.5 text-gray-400 hover:text-indigo-400 transition-colors flex-shrink-0"
                        title={item.completed ? 'Mark pending' : 'Mark completed'}
                      >
                        {item.completed ? (
                          <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                        ) : (
                          <Circle className="w-5 h-5 text-gray-500 hover:text-indigo-400" />
                        )}
                      </button>

                      {/* Content */}
                      <div className="space-y-1 flex-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <span
                            className={`text-sm font-semibold truncate ${
                              item.completed ? 'line-through text-gray-500' : 'text-gray-100'
                            }`}
                          >
                            {item.title}
                          </span>

                          <span
                            className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded uppercase border ${getPriorityBadge(
                              item.priority
                            )}`}
                          >
                            {item.priority}
                          </span>

                          <span className="flex items-center gap-1 text-[11px] text-gray-400 bg-gray-950 px-2 py-0.5 rounded border border-gray-800">
                            {getPillarIcon(item.pillar)}
                            <span>{item.pillar_label}</span>
                          </span>
                        </div>

                        <p className="text-xs text-gray-400 leading-relaxed">{item.description}</p>

                        <div className="flex items-center gap-2 pt-0.5 text-[11px] text-gray-500">
                          <span className="font-mono text-indigo-300/80">Target: {item.target_asset}</span>
                        </div>
                      </div>
                    </div>

                    {/* Expand/Collapse Button */}
                    {(item.automated_script || item.manual_steps.length > 0) && (
                      <button
                        onClick={() => toggleExpand(item.action_id)}
                        className="p-1 text-gray-400 hover:text-gray-200 hover:bg-gray-800 rounded transition-colors"
                        title={isExpanded ? 'Collapse' : 'Expand scripts & details'}
                      >
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </button>
                    )}
                  </div>

                  {/* Expanded Script & Manual Steps */}
                  {isExpanded && (
                    <div className="px-4 pb-4 pt-1 border-t border-gray-800/80 space-y-3 bg-gray-950/40 rounded-b-lg">
                      {/* Automated Script */}
                      {item.automated_script && (
                        <div className="space-y-1.5">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-mono text-gray-400 flex items-center gap-1.5">
                              <Code className="w-3.5 h-3.5 text-indigo-400" />
                              Containment Script ({item.script_language || 'PowerShell'}):
                            </span>
                            <button
                              onClick={() => handleCopyScript(item.action_id, item.automated_script!)}
                              className="flex items-center space-x-1 px-2 py-1 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded text-[11px] transition-colors"
                            >
                              {copiedScriptId === item.action_id ? (
                                <>
                                  <Check className="w-3 h-3 text-emerald-400" />
                                  <span className="text-emerald-400">Copied</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span>Copy Script</span>
                                </>
                              )}
                            </button>
                          </div>
                          <pre className="p-3 bg-black/90 border border-gray-800 rounded-md font-mono text-xs text-indigo-200/90 overflow-x-auto whitespace-pre-wrap selection:bg-indigo-900">
                            {item.automated_script}
                          </pre>
                        </div>
                      )}

                      {/* Manual Steps */}
                      {item.manual_steps.length > 0 && (
                        <div className="space-y-1.5 text-xs">
                          <span className="font-semibold text-gray-300">Operational Verification Checklist:</span>
                          <ul className="list-disc list-inside space-y-1 text-gray-400 pl-1">
                            {item.manual_steps.map((step, sIdx) => (
                              <li key={sIdx}>{step}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* SECTION 2: DETECTION & IOC RULE EXPORT HUB */}
      <div className="p-5 bg-gray-900 border border-gray-800 rounded-lg space-y-4">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-gray-800 pb-3">
          <div>
            <div className="flex items-center space-x-2">
              <FileCode2 className="w-5 h-5 text-purple-400" />
              <h3 className="text-sm font-bold text-gray-100 uppercase tracking-wider">
                Detection Engineering & IOC Export Hub
              </h3>
            </div>
            <p className="text-xs text-gray-400 mt-0.5">
              Instant multi-format indicators and rule generation for enterprise SIEM, EDR, IDS, and threat sharing.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center space-x-2">
            <button
              onClick={handleCopyExport}
              disabled={loadingExport || !exportContent}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 rounded text-xs transition-colors border border-gray-700"
            >
              {copiedExport ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedExport ? 'Copied' : 'Copy Content'}</span>
            </button>

            <button
              onClick={handleDownloadExport}
              disabled={loadingExport || !exportContent}
              className="flex items-center space-x-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs transition-colors shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download File</span>
            </button>
          </div>
        </div>

        {/* Export Format Selector Tabs */}
        <div className="flex flex-wrap gap-2">
          {[
            { id: 'stix', label: 'STIX 2.1 JSON', desc: 'OASIS CTI Sharing Standard' },
            { id: 'yara', label: 'YARA Rule (.yar)', desc: 'Email Header & Macro Hunting' },
            { id: 'sigma', label: 'Sigma Rule (.yml)', desc: 'Generic SIEM Detection' },
            { id: 'snort', label: 'Snort / Suricata (.rules)', desc: 'Network IDS Rules' },
          ].map((fmt) => (
            <button
              key={fmt.id}
              onClick={() => handleFormatChange(fmt.id as any)}
              className={`px-3 py-2 rounded-md text-left transition-all border ${
                activeExportFormat === fmt.id
                  ? 'bg-purple-950/40 text-purple-300 border-purple-600/80 shadow'
                  : 'bg-gray-950/60 text-gray-400 border-gray-800 hover:bg-gray-800 hover:text-gray-300'
              }`}
            >
              <div className="text-xs font-semibold">{fmt.label}</div>
              <div className="text-[10px] text-gray-500">{fmt.desc}</div>
            </button>
          ))}
        </div>

        {/* Rule Preview Editor Box */}
        <div className="relative rounded-md border border-gray-800 overflow-hidden bg-black/90">
          <div className="flex items-center justify-between px-3 py-1.5 bg-gray-950 border-b border-gray-800 text-[11px] font-mono text-gray-400">
            <span>
              Format: {activeExportFormat.toUpperCase()} | Case: {caseId.substring(0, 8)}...
            </span>
            {loadingExport && <span className="text-purple-400 animate-pulse">Generating ruleset...</span>}
          </div>

          <pre className="p-4 font-mono text-xs text-gray-200 overflow-x-auto max-h-[380px] overflow-y-auto whitespace-pre-wrap leading-relaxed select-text">
            {loadingExport ? (
              <span className="text-gray-500">Compiling threat artifacts into {activeExportFormat.toUpperCase()} format...</span>
            ) : (
              exportContent
            )}
          </pre>
        </div>
      </div>
    </div>
  );
}
