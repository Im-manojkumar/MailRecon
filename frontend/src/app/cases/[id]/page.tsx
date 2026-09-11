'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import ProtectedRoute from '@/components/ProtectedRoute';
import { api } from '@/lib/api';
import {
  CaseDetail,
  RiskScoreResponse,
  FindingResponse,
  ParsedEmailResponse,
  RouteAnalysisResponse,
  QrCodeResult,
  AIAnalysisResponse,
  IndicatorGraphResponse,
  ReportResponse,
  MacroAnalysisItem,
  ObfuscationAnalysisResponse,
  DomainIntelResponse,
  LiveDnsValidationResponse,
  OriginProfileResponse,
  ThreatClassificationResponse,
  FinancialForensicsResponse,
  CaseCampaignAffiliation,
} from '@/lib/types';
import StatusBadge from '@/components/StatusBadge';
import SeverityBadge from '@/components/SeverityBadge';
import RiskScoreCard from '@/components/RiskScoreCard';
import RouteHopTimeline from '@/components/RouteHopTimeline';
import RouteMap from '@/components/RouteMap';
import EmailViewer from '@/components/EmailViewer';
import AIBriefingView from '@/components/AIBriefingView';
import IndicatorGraphView from '@/components/IndicatorGraphView';
import FinancialForensicsCard from '@/components/FinancialForensicsCard';
import IncidentResponseView from '@/components/IncidentResponseView';
import {
  Shield,
  ShieldAlert,
  FileText,
  Clock,
  Download,
  AlertTriangle,
  Mail,
  Network,
  Compass,
  ListFilter,
  Bot,
  FileCode,
  CheckCircle,
  Copy,
  Check,
  ExternalLink,
  Globe,
  Radio,
  Server,
  ArrowRight,
} from 'lucide-react';

export default function CaseDetailPage({ params }: { params: { id: string } }) {
  const [activeTab, setActiveTab] = useState<string>('summary');
  const [caseData, setCaseData] = useState<CaseDetail | null>(null);
  const [score, setScore] = useState<RiskScoreResponse | null>(null);
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [parsed, setParsed] = useState<ParsedEmailResponse | null>(null);
  const [route, setRoute] = useState<RouteAnalysisResponse | null>(null);
  const [qrCodes, setQrCodes] = useState<QrCodeResult[]>([]);
  const [macros, setMacros] = useState<MacroAnalysisItem[]>([]);
  const [obfuscation, setObfuscation] = useState<ObfuscationAnalysisResponse | null>(null);
  const [aiData, setAiData] = useState<AIAnalysisResponse | null>(null);
  const [graph, setGraph] = useState<IndicatorGraphResponse | null>(null);
  const [reports, setReports] = useState<ReportResponse[]>([]);
  const [domainIntel, setDomainIntel] = useState<DomainIntelResponse | null>(null);
  const [dnsValidation, setDnsValidation] = useState<LiveDnsValidationResponse | null>(null);
  const [originProfile, setOriginProfile] = useState<OriginProfileResponse | null>(null);
  const [threatClass, setThreatClass] = useState<ThreatClassificationResponse | null>(null);
  const [financial, setFinancial] = useState<FinancialForensicsResponse | null>(null);
  const [campaignAffiliation, setCampaignAffiliation] = useState<CaseCampaignAffiliation | null>(null);
  const [generatingFormat, setGeneratingFormat] = useState<'html' | 'json' | null>(null);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    Promise.allSettled([
      api.cases.get(params.id),
      api.cases.getScore(params.id),
      api.cases.getFindings(params.id),
      api.cases.getParsed(params.id),
      api.cases.getRoute(params.id),
      api.cases.getQrCodes(params.id),
      api.cases.getAIAnalysis(params.id),
      api.cases.getGraph(params.id),
      api.cases.getReports(params.id),
      api.cases.getMacros(params.id),
      api.cases.getObfuscation(params.id),
      api.cases.getDomainIntel(params.id),
      api.cases.getDnsValidation(params.id),
      api.cases.getOriginProfile(params.id),
      api.cases.getThreatClassification(params.id),
      api.cases.getFinancialForensics(params.id),
      api.cases.getCampaign(params.id),
    ]).then(([caseRes, scoreRes, findingsRes, parsedRes, routeRes, qrRes, aiRes, graphRes, reportsRes, macRes, obfRes, domRes, dnsRes, origRes, threatRes, finRes, campRes]) => {
      if (caseRes.status === 'fulfilled') setCaseData(caseRes.value);
      if (scoreRes.status === 'fulfilled') setScore(scoreRes.value);
      if (findingsRes.status === 'fulfilled') {
        const fList = findingsRes.value.items || findingsRes.value.findings || [];
        const sevOrder: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        fList.sort((a, b) => (sevOrder[b.severity] || 0) - (sevOrder[a.severity] || 0));
        setFindings(fList);
      }
      if (parsedRes.status === 'fulfilled') setParsed(parsedRes.value);
      if (routeRes.status === 'fulfilled') setRoute(routeRes.value);
      if (qrRes.status === 'fulfilled') {
        const qrList = Array.isArray(qrRes.value) ? qrRes.value : (qrRes.value as any).qr_codes || [];
        setQrCodes(qrList);
      }
      if (aiRes.status === 'fulfilled') setAiData(aiRes.value);
      if (graphRes.status === 'fulfilled') setGraph(graphRes.value);
      if (reportsRes.status === 'fulfilled') setReports(reportsRes.value.items || reportsRes.value.reports || []);
      if (macRes.status === 'fulfilled') setMacros(macRes.value.items || []);
      if (obfRes.status === 'fulfilled') setObfuscation(obfRes.value);
      if (domRes.status === 'fulfilled') setDomainIntel(domRes.value);
      if (dnsRes.status === 'fulfilled') setDnsValidation(dnsRes.value);
      if (origRes.status === 'fulfilled') setOriginProfile(origRes.value);
      if (threatRes.status === 'fulfilled') setThreatClass(threatRes.value);
      if (finRes.status === 'fulfilled') setFinancial(finRes.value);
      if (campRes && campRes.status === 'fulfilled') setCampaignAffiliation(campRes.value);
      setLoading(false);
    });
  }, [params.id]);

  const handleDownloadOriginal = async () => {
    if (!caseData) return;
    try {
      setDownloading(true);
      const blob = await api.cases.downloadOriginal(caseData.id);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = caseData.filename || `${caseData.id}.eml`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      alert('Failed to download original .eml file. Integrity check may have failed.');
    } finally {
      setDownloading(false);
    }
  };

  if (loading) {
    return (
      <ProtectedRoute>
        <div className="flex flex-col items-center justify-center min-h-[400px] text-gray-400 space-y-3">
          <Shield className="w-10 h-10 text-indigo-500 animate-pulse" />
          <p className="font-mono text-sm">Loading forensic case evidence...</p>
        </div>
      </ProtectedRoute>
    );
  }

  if (!caseData) {
    return (
      <ProtectedRoute>
        <div className="p-8 text-center text-red-400 border border-red-900/60 bg-red-950/20 rounded-lg">
          Case not found or unauthorized access.
        </div>
      </ProtectedRoute>
    );
  }

  const tabs = [
    { id: 'summary', label: 'Summary', icon: Shield },
    { id: 'email', label: 'Email & Headers', icon: Mail },
    { id: 'route', label: 'Route & GeoIP', icon: Compass },
    { id: 'findings', label: `Findings (${findings.length})`, icon: ListFilter },
    { id: 'ai', label: 'AI Briefing', icon: Bot },
    { id: 'graph', label: 'Indicator Graph', icon: Network },
    { id: 'report', label: 'Forensic Report', icon: FileCode },
    { id: 'response', label: 'Incident Response & Export', icon: ShieldAlert },
  ];

  return (
    <ProtectedRoute>
      <div className="space-y-6 max-w-7xl mx-auto pb-12">
        {/* Case Header Banner */}
        <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-gray-800 pb-5 gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <h1 className="text-2xl font-black text-white font-mono tracking-tight">
                {caseData.filename || `Case ${caseData.id.substring(0, 8)}`}
              </h1>
              <StatusBadge status={caseData.status} />
            </div>
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-400 mt-2 font-mono">
              <span>CASE ID: <span className="text-gray-300">{caseData.id}</span></span>
              <span>•</span>
              <span>SHA-256: <span className="text-gray-300">{caseData.original_sha256 ? `${caseData.original_sha256.substring(0, 16)}...` : 'N/A'}</span></span>
              <span>•</span>
              <span>CREATED: <span className="text-gray-300">{new Date(caseData.created_at).toLocaleString()}</span></span>
            </div>

            {threatClass && (
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded-md uppercase border flex items-center gap-1.5 ${
                  threatClass.primary_category === 'CREDENTIAL_PHISHING'
                    ? 'bg-rose-950/90 text-rose-300 border-rose-700/80 shadow-sm shadow-rose-950'
                    : threatClass.primary_category === 'PAYMENT_DIVERSION'
                    ? 'bg-amber-950/90 text-amber-300 border-amber-700/80 shadow-sm shadow-amber-950'
                    : threatClass.primary_category === 'MALWARE_DELIVERY'
                    ? 'bg-red-950/90 text-red-300 border-red-700/80 shadow-sm shadow-red-950'
                    : threatClass.primary_category === 'CEO_IMPERSONATION'
                    ? 'bg-purple-950/90 text-purple-300 border-purple-700/80 shadow-sm shadow-purple-950'
                    : threatClass.primary_category === 'SPAM_RECONNAISSANCE'
                    ? 'bg-yellow-950/90 text-yellow-300 border-yellow-700/80'
                    : 'bg-emerald-950/90 text-emerald-300 border-emerald-700/80'
                }`}>
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>{threatClass.category_label} ({Math.round(threatClass.confidence * 100)}% Confidence)</span>
                </span>
                {threatClass.action_summary && (
                  <span className="text-xs text-gray-400 italic">
                    SOC Action: {threatClass.action_summary}
                  </span>
                )}
              </div>
            )}
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={handleDownloadOriginal}
              disabled={downloading}
              className="flex items-center space-x-2 px-3.5 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-semibold rounded-md border border-gray-700 transition-colors disabled:opacity-50"
            >
              <Download className="w-4 h-4 text-indigo-400" />
              <span>{downloading ? 'Downloading...' : 'Original .eml'}</span>
            </button>
          </div>
        </div>

        {/* Campaign Affiliation Alert Banner */}
        {campaignAffiliation?.is_part_of_campaign && (
          <div className="p-4 bg-gradient-to-r from-red-950/80 via-rose-950/40 to-gray-900 border border-rose-500/70 rounded-lg shadow-lg shadow-rose-950/20">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div className="flex items-start space-x-3.5">
                <div className="p-2 bg-rose-900/60 border border-rose-500/80 rounded-md text-rose-300 mt-0.5 shrink-0">
                  <Network className="w-5 h-5 text-rose-400 animate-pulse" />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-rose-300 bg-rose-900/60 px-2 py-0.5 rounded border border-rose-700">
                      Coordinated Threat Campaign Detected
                    </span>
                    <span className="text-xs text-rose-200/80 font-mono font-semibold">
                      {campaignAffiliation.total_correlated_cases} Cases Correlated
                    </span>
                  </div>
                  <h3 className="text-base font-bold text-white tracking-tight">
                    {campaignAffiliation.campaign_name}
                  </h3>
                  <p className="text-xs text-gray-300">
                    This email is part of a broader multi-case threat campaign sharing infrastructure, financial anchors, or attack patterns across <span className="font-semibold text-white">{campaignAffiliation.total_correlated_cases} investigations</span>.
                  </p>
                  {campaignAffiliation.shared_artifacts && campaignAffiliation.shared_artifacts.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5 pt-1">
                      <span className="text-[11px] text-gray-400 font-mono mr-1">Shared Anchors:</span>
                      {campaignAffiliation.shared_artifacts.map((art, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-gray-950/80 border border-rose-800/70 rounded text-[11px] font-mono text-rose-300">
                          <span className="text-gray-400 font-semibold">{art.kind}:</span> {art.value.length > 25 ? `${art.value.substring(0, 23)}...` : art.value}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0 self-start md:self-center">
                {campaignAffiliation.campaign_id && (
                  <Link
                    href={`/campaigns?id=${campaignAffiliation.campaign_id}`}
                    className="inline-flex items-center space-x-1.5 px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded-md shadow transition-colors"
                  >
                    <span>Inspect Global Campaign Graph</span>
                    <ExternalLink className="w-3.5 h-3.5" />
                  </Link>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="flex space-x-2 border-b border-gray-800 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-2 px-4 py-3 text-xs font-semibold uppercase tracking-wider border-b-2 whitespace-nowrap transition-colors ${
                  isActive
                    ? 'border-indigo-500 text-indigo-400 bg-indigo-950/20'
                    : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Active Tab Panel */}
        <div className="bg-surface border border-gray-800/80 rounded-lg p-6 min-h-[500px]">
          {/* TAB 1: SUMMARY */}
          {activeTab === 'summary' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                {/* Threat Score Card */}
                <div className="lg:col-span-2">
                  <RiskScoreCard score={score} />
                </div>

                {/* Case Metadata Card */}
                <div className="p-6 border border-gray-800 rounded-lg bg-gray-900/60 space-y-4">
                  <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                    Evidence Metadata
                  </h3>
                  <dl className="space-y-3 text-xs">
                    <div>
                      <dt className="text-gray-500 mb-0.5">Filename</dt>
                      <dd className="text-gray-200 font-mono break-all font-semibold">
                        {caseData.filename || 'Unknown'}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-gray-500 mb-0.5">SHA-256 Checksum</dt>
                      <dd className="text-gray-300 font-mono text-[11px] break-all bg-gray-950 p-2 rounded border border-gray-800">
                        {caseData.original_sha256}
                      </dd>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <dt className="text-gray-500 mb-0.5">File Size</dt>
                        <dd className="text-gray-200 font-mono">
                          {caseData.original_size ? `${(caseData.original_size / 1024).toFixed(1)} KB` : 'N/A'}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-gray-500 mb-0.5">Status</dt>
                        <dd><StatusBadge status={caseData.status} /></dd>
                      </div>
                    </div>
                    <div>
                      <dt className="text-gray-500 mb-0.5">Ingestion Timestamp</dt>
                      <dd className="text-gray-300 font-mono">
                        {new Date(caseData.created_at).toUTCString()}
                      </dd>
                    </div>
                  </dl>
                </div>
              </div>

              {/* Origin & Infrastructure Intelligence Profile */}
              <div className="p-6 border border-gray-800 rounded-lg bg-gray-900/50 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-3">
                  <div className="flex items-center space-x-2">
                    <Radio className="w-4 h-4 text-indigo-400" />
                    <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider">
                      Origin Traceability & Infrastructure Attribution
                    </h3>
                  </div>
                  {originProfile?.origin_confidence && (
                    <div className="flex items-center space-x-2">
                      <span className="text-[11px] text-gray-500">Attribution Confidence:</span>
                      <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${
                        originProfile.origin_confidence === 'high'
                          ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                          : originProfile.origin_confidence === 'medium'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-red-950 text-red-300 border border-red-800'
                      }`}>
                        {originProfile.origin_confidence}
                      </span>
                    </div>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
                  <div className="p-3 bg-gray-950/70 border border-gray-800 rounded-lg space-y-1">
                    <span className="text-gray-500 block">Originating Ingress IP</span>
                    <span className="text-gray-200 font-mono font-bold text-sm">
                      {originProfile?.originating_ip || 'No Public IP Found'}
                    </span>
                    <span className="text-[11px] text-gray-400 block truncate">
                      {originProfile?.city ? `${originProfile.city}, ` : ''}{originProfile?.country || 'Unknown Location'}
                    </span>
                  </div>

                  <div className="p-3 bg-gray-950/70 border border-gray-800 rounded-lg space-y-1">
                    <span className="text-gray-500 block">ISP & Autonomous System</span>
                    <span className="text-gray-200 font-mono font-semibold truncate block">
                      {originProfile?.asn || 'ASN: N/A'}
                    </span>
                    <span className="text-[11px] text-gray-400 block truncate" title={originProfile?.isp || originProfile?.org || ''}>
                      {originProfile?.isp || originProfile?.org || 'Standard Telecom'}
                    </span>
                  </div>

                  <div className="p-3 bg-gray-950/70 border border-gray-800 rounded-lg space-y-1">
                    <span className="text-gray-500 block">Infrastructure Archetype</span>
                    <span className="text-gray-200 font-semibold block">
                      {originProfile?.infra_label || 'Standard Internet Gateway'}
                    </span>
                    {originProfile?.is_anonymized && (
                      <span className="text-[10px] text-red-400 font-bold uppercase block">
                        ANONYMIZED ROUTING (TOR / VPN)
                      </span>
                    )}
                  </div>

                  <div className="p-3 bg-gray-950/70 border border-gray-800 rounded-lg space-y-1">
                    <span className="text-gray-500 block">Sender Domain Age & Registrar</span>
                    <div className="flex items-center space-x-1.5">
                      <span className="text-gray-200 font-bold font-mono">
                        {domainIntel?.domain_age_days != null ? `${domainIntel.domain_age_days} days` : 'Age N/A'}
                      </span>
                      {domainIntel?.is_newly_registered && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-300 border border-red-800 uppercase">
                          NEW DOMAIN
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] text-gray-400 block truncate" title={domainIntel?.registrar || ''}>
                      {domainIntel?.registrar || 'Registrar N/A'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Financial Fraud & Payment Diversion Forensics */}
              <FinancialForensicsCard financial={financial} />

              {/* Linked Campaign Evidence & Peer Cases */}
              {campaignAffiliation?.is_part_of_campaign && campaignAffiliation.affiliated_cases && campaignAffiliation.affiliated_cases.length > 1 && (
                <div className="p-6 border border-rose-900/60 rounded-lg bg-gray-900/60 space-y-4">
                  <div className="flex items-center justify-between border-b border-gray-800 pb-3">
                    <div className="flex items-center space-x-2">
                      <Network className="w-4 h-4 text-rose-400" />
                      <h3 className="text-xs font-bold text-gray-200 uppercase tracking-wider">
                        Linked Campaign Evidence & Peer Cases ({campaignAffiliation.affiliated_cases.length - 1} peers)
                      </h3>
                    </div>
                    {campaignAffiliation.campaign_id && (
                      <Link
                        href={`/campaigns?id=${campaignAffiliation.campaign_id}`}
                        className="text-xs text-rose-400 hover:text-rose-300 font-medium inline-flex items-center gap-1"
                      >
                        <span>Open Campaign View</span>
                        <ArrowRight className="w-3 h-3" />
                      </Link>
                    )}
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {campaignAffiliation.affiliated_cases
                      .filter((c) => c.case_id !== caseData.id)
                      .map((peer) => (
                        <Link
                          key={peer.case_id}
                          href={`/cases/${peer.case_id}`}
                          className="p-3 bg-gray-950/70 border border-gray-800 hover:border-rose-700/60 rounded-lg transition-colors group block space-y-1.5"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-xs font-bold text-gray-200 group-hover:text-rose-300 truncate max-w-[180px]">
                              {peer.filename || peer.case_id.substring(0, 8)}
                            </span>
                            <span className={`px-1.5 py-0.5 text-[10px] font-mono font-bold rounded ${
                              peer.score >= 70 ? 'bg-red-950 text-red-400 border border-red-800' :
                              peer.score >= 40 ? 'bg-amber-950 text-amber-400 border border-amber-800' :
                              'bg-emerald-950 text-emerald-400 border border-emerald-800'
                            }`}>
                              Risk: {Math.round(peer.score)}
                            </span>
                          </div>
                          <div className="text-[11px] text-gray-400 flex items-center justify-between">
                            <span className="truncate">{peer.from_email || 'Unknown Sender'}</span>
                            <span className="font-mono text-[10px] text-gray-500">{new Date(peer.created_at).toLocaleDateString()}</span>
                          </div>
                        </Link>
                      ))}
                  </div>
                </div>
              )}

              {/* Quick Findings Snapshot */}
              <div className="p-5 border border-gray-800 rounded-lg bg-gray-900/40 space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                    Detection Highlights ({findings.length} findings)
                  </h3>
                  <button
                    onClick={() => setActiveTab('findings')}
                    className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
                  >
                    View all in Findings tab →
                  </button>
                </div>

                {findings.length === 0 ? (
                  <p className="text-xs text-gray-500 py-2">No security findings recorded.</p>
                ) : (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {findings.slice(0, 4).map((f) => (
                      <div
                        key={f.id}
                        className="p-3 bg-gray-950/80 border border-gray-800/80 rounded-lg space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <SeverityBadge severity={f.severity} />
                          <span className="text-[11px] font-mono text-gray-500">{f.detector}</span>
                        </div>
                        <div className="text-xs font-semibold text-gray-200">{f.title}</div>
                        <div className="text-[11px] text-gray-400 line-clamp-2">{f.detail || f.description}</div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: EMAIL & HEADERS */}
          {activeTab === 'email' && (
            <EmailViewer
              parsed={parsed}
              qrCodes={qrCodes}
              macros={macros}
              obfuscation={obfuscation}
              dnsValidation={dnsValidation}
              caseId={caseData.id}
            />
          )}

          {/* TAB 3: ROUTE & GEOIP */}
          {activeTab === 'route' && (
            <div className="space-y-6">
              <RouteHopTimeline route={route} />
              <div className="space-y-3 pt-4 border-t border-gray-800">
                <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                  Geographical Transport Topology
                </h3>
                <RouteMap route={route} />
              </div>
            </div>
          )}

          {/* TAB 4: FINDINGS */}
          {activeTab === 'findings' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                  Forensic Threat Findings ({findings.length})
                </h3>
                <span className="text-xs text-gray-500">
                  Sorted by severity (Critical → Info)
                </span>
              </div>

              {findings.length === 0 ? (
                <div className="p-12 text-center text-gray-500 border border-dashed border-gray-800 rounded-lg">
                  <CheckCircle className="w-8 h-8 mx-auto mb-2 text-emerald-400 opacity-60" />
                  No threat indicators or security anomalies detected.
                </div>
              ) : (
                <div className="space-y-3">
                  {findings.map((f) => (
                    <div
                      key={f.id}
                      className="p-4 bg-gray-900/80 border border-gray-800 rounded-lg hover:border-gray-700 transition-colors space-y-2.5"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800/80 pb-2">
                        <div className="flex items-center space-x-3">
                          <SeverityBadge severity={f.severity} />
                          <span className="text-sm font-semibold text-gray-200">{f.title}</span>
                        </div>
                        <div className="flex items-center space-x-3 text-xs font-mono">
                          <span className="text-indigo-400 bg-indigo-950/60 px-2 py-0.5 rounded border border-indigo-900/60">
                            {f.detector}
                          </span>
                          <span className="text-gray-400">
                            Confidence: {Math.round((f.confidence || 0) * 100)}%
                          </span>
                        </div>
                      </div>

                      <p className="text-xs text-gray-300 leading-relaxed font-sans">
                        {f.detail || f.description}
                      </p>

                      {f.evidence_ref && (
                        <div className="text-[11px] font-mono text-gray-400 pt-1">
                          <span className="text-gray-500">Evidence Pointer: </span>
                          <span className="text-cyan-400 bg-gray-950 px-2 py-0.5 rounded border border-gray-800">
                            {f.evidence_ref}
                          </span>
                        </div>
                      )}

                      {/* Neural Trigger Tokens or Raw Evidence */}
                      {f.raw_evidence && Object.keys(f.raw_evidence).length > 0 && (
                        <details className="text-[11px] font-mono pt-1 text-gray-500">
                          <summary className="cursor-pointer hover:text-gray-300">
                            View Structured Raw Signal Evidence
                          </summary>
                          <pre className="mt-2 p-2.5 bg-gray-950 rounded border border-gray-800 text-gray-400 overflow-x-auto">
                            {JSON.stringify(f.raw_evidence, null, 2)}
                          </pre>
                        </details>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 5: AI BRIEFING */}
          {activeTab === 'ai' && <AIBriefingView aiData={aiData} />}

          {/* TAB 6: INDICATOR GRAPH */}
          {activeTab === 'graph' && <IndicatorGraphView graph={graph} />}

          {/* TAB 7: FORENSIC REPORT */}
          {activeTab === 'report' && (
            <div className="space-y-6">
              {/* Generation Actions Card */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between p-5 bg-gray-900/80 border border-gray-800 rounded-lg gap-4">
                <div>
                  <h3 className="text-sm font-semibold text-gray-200">
                    Forensic Intelligence Report Export
                  </h3>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Generate an immutable, SHA-256 signed forensic report suitable for incident documentation and compliance.
                  </p>
                </div>
                <div className="flex items-center space-x-3">
                  <button
                    onClick={async () => {
                      if (!caseData) return;
                      try {
                        setGeneratingFormat('html');
                        const rep = await api.cases.generateReport(caseData.id, 'html');
                        setReports((prev) => [rep, ...prev]);
                      } catch (err: any) {
                        alert('Failed to generate report: ' + (err.message || 'Unknown error'));
                      } finally {
                        setGeneratingFormat(null);
                      }
                    }}
                    disabled={generatingFormat !== null}
                    className="flex items-center space-x-1.5 px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-md transition-colors disabled:opacity-50"
                  >
                    <FileCode className="w-4 h-4" />
                    <span>{generatingFormat === 'html' ? 'Sealing HTML...' : 'Export HTML'}</span>
                  </button>

                  <button
                    onClick={async () => {
                      if (!caseData) return;
                      try {
                        setGeneratingFormat('json');
                        const rep = await api.cases.generateReport(caseData.id, 'json');
                        setReports((prev) => [rep, ...prev]);
                      } catch (err: any) {
                        alert('Failed to generate report: ' + (err.message || 'Unknown error'));
                      } finally {
                        setGeneratingFormat(null);
                      }
                    }}
                    disabled={generatingFormat !== null}
                    className="flex items-center space-x-1.5 px-3.5 py-2 bg-emerald-700 hover:bg-emerald-600 text-white text-xs font-semibold rounded-md transition-colors disabled:opacity-50"
                  >
                    <FileText className="w-4 h-4" />
                    <span>{generatingFormat === 'json' ? 'Sealing JSON...' : 'Export JSON'}</span>
                  </button>
                </div>
              </div>

              {/* Generated Reports List */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider">
                    Generated Forensic Reports ({reports.length})
                  </h4>
                  <span className="text-[11px] text-gray-500">
                    Protected by runtime SHA-256 tamper verification
                  </span>
                </div>

                {reports.length === 0 ? (
                  <div className="p-10 text-center text-gray-500 border border-dashed border-gray-800 rounded-lg space-y-2">
                    <FileCode className="w-8 h-8 mx-auto opacity-40" />
                    <p className="text-xs">
                      No reports generated yet. Click &quot;Export HTML&quot; or &quot;Export JSON&quot; above to create an immutable forensic report.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {reports.map((rep) => (
                      <div
                        key={rep.id}
                        className="p-4 bg-gray-900/70 border border-gray-800 rounded-lg space-y-3 hover:border-gray-700 transition-colors"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800/80 pb-2">
                          <div className="flex items-center space-x-2.5">
                            <span
                              className={`px-2 py-0.5 text-[11px] font-mono font-bold uppercase rounded border ${
                                rep.format === 'html'
                                  ? 'bg-indigo-950 text-indigo-300 border-indigo-700'
                                  : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                              }`}
                            >
                              {rep.format}
                            </span>
                            <span className="text-xs font-mono text-gray-300">
                              Report ID: {rep.id}
                            </span>
                          </div>

                          <span className="text-xs text-gray-500 font-mono">
                            {new Date(rep.created_at).toUTCString()}
                          </span>
                        </div>

                        {/* Integrity Checksum Banner */}
                        <div className="flex flex-wrap items-center justify-between bg-gray-950 p-2.5 rounded border border-gray-800 text-xs font-mono gap-2">
                          <div className="flex items-center space-x-2 text-gray-400">
                            <Shield className="w-3.5 h-3.5 text-indigo-400 flex-shrink-0" />
                            <span>SHA-256 Seal:</span>
                            <span className="text-cyan-300 break-all">{rep.integrity_sha256 || 'None'}</span>
                          </div>

                          {rep.integrity_sha256 && (
                            <button
                              onClick={() => {
                                navigator.clipboard.writeText(rep.integrity_sha256!);
                                setCopiedHash(rep.id);
                                setTimeout(() => setCopiedHash(null), 2000);
                              }}
                              className="p-1 hover:text-white text-gray-400 rounded hover:bg-gray-800 transition-colors"
                              title="Copy SHA-256 hash"
                            >
                              {copiedHash === rep.id ? (
                                <Check className="w-3.5 h-3.5 text-emerald-400" />
                              ) : (
                                <Copy className="w-3.5 h-3.5" />
                              )}
                            </button>
                          )}
                        </div>

                        {/* Action Buttons */}
                        <div className="flex items-center justify-end space-x-2 pt-1">
                          <button
                            onClick={async () => {
                              try {
                                const blob = await api.cases.downloadReport(caseData.id, rep.id);
                                const url = window.URL.createObjectURL(blob);
                                window.open(url, '_blank');
                              } catch (err) {
                                alert('Failed to open report.');
                              }
                            }}
                            className="flex items-center space-x-1.5 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium rounded border border-gray-700 transition-colors"
                          >
                            <ExternalLink className="w-3.5 h-3.5 text-indigo-400" />
                            <span>Preview</span>
                          </button>

                          <button
                            onClick={async () => {
                              try {
                                const blob = await api.cases.downloadReport(caseData.id, rep.id);
                                const url = window.URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url;
                                a.download = `case_${caseData.id}_report_${rep.id.substring(0, 8)}.${rep.format}`;
                                document.body.appendChild(a);
                                a.click();
                                window.URL.revokeObjectURL(url);
                                document.body.removeChild(a);
                              } catch (err) {
                                alert('Failed to download report. Tamper verification failed.');
                              }
                            }}
                            className="flex items-center space-x-1.5 px-3 py-1.5 bg-indigo-950/80 hover:bg-indigo-900/80 text-indigo-200 text-xs font-medium rounded border border-indigo-700/80 transition-colors"
                          >
                            <Download className="w-3.5 h-3.5 text-indigo-400" />
                            <span>Download Sealed File</span>
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 8: INCIDENT RESPONSE & EXPORT */}
          {activeTab === 'response' && (
            <IncidentResponseView caseId={caseData.id} />
          )}
        </div>
      </div>
    </ProtectedRoute>
  );
}
