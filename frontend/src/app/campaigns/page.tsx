'use client';

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import ProtectedRoute from '@/components/ProtectedRoute';
import { api } from '@/lib/api';
import { CampaignListItem, CampaignDetail } from '@/lib/types';
import {
  Network,
  ShieldAlert,
  Layers,
  ArrowRight,
  ExternalLink,
  Calendar,
  DollarSign,
  Globe,
  Radio,
  FileCode,
  CheckCircle2,
  RefreshCw,
  Search,
  Activity,
  Users,
  Target,
} from 'lucide-react';

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<CampaignListItem[]>([]);
  const [selectedCampaign, setSelectedCampaign] = useState<CampaignDetail | null>(null);
  const [loadingList, setLoadingList] = useState(true);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const fetchCampaigns = async () => {
    try {
      setLoadingList(true);
      const res = await api.campaigns.list();
      setCampaigns(res.items || []);
      if (res.items && res.items.length > 0) {
        loadDetail(res.items[0].campaign_id);
      }
    } catch (err) {
      console.error('Failed to load campaigns:', err);
    } finally {
      setLoadingList(false);
    }
  };

  const loadDetail = async (campaignId: string) => {
    try {
      setLoadingDetail(true);
      const detail = await api.campaigns.get(campaignId);
      setSelectedCampaign(detail);
    } catch (err) {
      console.error('Failed to load campaign detail:', err);
    } finally {
      setLoadingDetail(false);
    }
  };

  useEffect(() => {
    fetchCampaigns();
  }, []);

  const filteredCampaigns = campaigns.filter((c) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.name.toLowerCase().includes(q) ||
      c.threat_archetype.toLowerCase().includes(q) ||
      c.campaign_id.toLowerCase().includes(q) ||
      c.description.toLowerCase().includes(q)
    );
  });

  const getArchetypeBadge = (archetype: string) => {
    if (archetype.includes('Wire Fraud') || archetype.includes('Payment')) {
      return 'bg-amber-950/80 text-amber-300 border-amber-700/80';
    }
    if (archetype.includes('Credential') || archetype.includes('Phishing')) {
      return 'bg-rose-950/80 text-rose-300 border-rose-700/80';
    }
    if (archetype.includes('Malware') || archetype.includes('Dropper')) {
      return 'bg-red-950/80 text-red-300 border-red-700/80';
    }
    if (archetype.includes('Executive') || archetype.includes('Spoofing')) {
      return 'bg-purple-950/80 text-purple-300 border-purple-700/80';
    }
    return 'bg-indigo-950/80 text-indigo-300 border-indigo-700/80';
  };

  const getNodeColor = (type: string) => {
    switch (type) {
      case 'case':
        return 'bg-indigo-950 border-indigo-700 text-indigo-300';
      case 'iban':
      case 'financial':
      case 'crypto_wallet':
        return 'bg-amber-950 border-amber-700 text-amber-300';
      case 'domain':
        return 'bg-purple-950 border-purple-700 text-purple-300';
      case 'ip':
        return 'bg-cyan-950 border-cyan-700 text-cyan-300';
      case 'hash':
        return 'bg-rose-950 border-rose-700 text-rose-300';
      default:
        return 'bg-gray-800 border-gray-700 text-gray-300';
    }
  };

  return (
    <ProtectedRoute>
      <div className="space-y-6">
        {/* Page Header */}
        <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-gray-800 pb-5 gap-4">
          <div>
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-purple-950/80 border border-purple-700/80 rounded-lg text-purple-400">
                <Network className="w-6 h-6" />
              </div>
              <div>
                <h1 className="text-2xl font-black text-white tracking-tight flex items-center gap-2">
                  Threat Actor Campaign Intelligence & Graph
                </h1>
                <p className="text-xs text-gray-400 mt-0.5">
                  Automated cross-case correlation clustering disparate attacks sharing sender infrastructure, payment coordinates, and malware hashes.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={fetchCampaigns}
              disabled={loadingList}
              className="flex items-center space-x-1.5 px-3 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-semibold rounded-md border border-gray-700 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingList ? 'animate-spin' : ''}`} />
              <span>Re-cluster Database</span>
            </button>
          </div>
        </div>

        {/* Global Campaign Stats */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="p-4 bg-gray-900/80 border border-gray-800 rounded-lg space-y-1">
            <span className="text-xs font-medium text-gray-400 flex items-center gap-1.5">
              <Layers className="w-4 h-4 text-purple-400" /> Active Threat Campaigns
            </span>
            <span className="text-2xl font-black text-gray-100 font-mono">
              {campaigns.length}
            </span>
          </div>

          <div className="p-4 bg-gray-900/80 border border-gray-800 rounded-lg space-y-1">
            <span className="text-xs font-medium text-gray-400 flex items-center gap-1.5">
              <Users className="w-4 h-4 text-indigo-400" /> Correlated Cases
            </span>
            <span className="text-2xl font-black text-indigo-400 font-mono">
              {campaigns.reduce((acc, c) => acc + c.case_count, 0)}
            </span>
          </div>

          <div className="p-4 bg-gray-900/80 border border-gray-800 rounded-lg space-y-1">
            <span className="text-xs font-medium text-gray-400 flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-red-400" /> Critical Risk Campaigns
            </span>
            <span className="text-2xl font-black text-red-400 font-mono">
              {campaigns.filter((c) => c.risk_score >= 0.8).length}
            </span>
          </div>

          <div className="p-4 bg-gray-900/80 border border-gray-800 rounded-lg space-y-1">
            <span className="text-xs font-medium text-gray-400 flex items-center gap-1.5">
              <Activity className="w-4 h-4 text-emerald-400" /> Mean Attribution Confidence
            </span>
            <span className="text-2xl font-black text-emerald-400 font-mono">
              {campaigns.length > 0
                ? `${Math.round((campaigns.reduce((acc, c) => acc + c.confidence, 0) / campaigns.length) * 100)}%`
                : '100%'}
            </span>
          </div>
        </div>

        {/* Main Split Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left Column: Campaign Selector List (5 Cols) */}
          <div className="lg:col-span-5 space-y-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search campaigns, archetypes, or descriptions..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-gray-900 border border-gray-800 rounded-md text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-purple-500"
              />
            </div>

            {loadingList ? (
              <div className="p-12 text-center text-gray-500 text-sm">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-purple-400" />
                Clustering cross-case threat intelligence...
              </div>
            ) : filteredCampaigns.length === 0 ? (
              <div className="p-8 text-center text-gray-500 text-xs bg-gray-900/50 rounded border border-gray-800">
                No multi-case campaigns identified matching criteria.
              </div>
            ) : (
              <div className="space-y-3 max-h-[800px] overflow-y-auto pr-1">
                {filteredCampaigns.map((camp) => {
                  const isSelected = selectedCampaign?.campaign_id === camp.campaign_id;
                  return (
                    <div
                      key={camp.campaign_id}
                      onClick={() => loadDetail(camp.campaign_id)}
                      className={`p-4 rounded-lg border cursor-pointer transition-all ${
                        isSelected
                          ? 'bg-purple-950/30 border-purple-600/80 shadow-md shadow-purple-950/40'
                          : 'bg-gray-900/70 border-gray-800 hover:bg-gray-900 hover:border-gray-700'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div className="space-y-1 min-w-0">
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="font-mono text-[11px] text-purple-400 font-bold">
                              {camp.campaign_id}
                            </span>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getArchetypeBadge(
                                camp.threat_archetype
                              )}`}
                            >
                              {camp.threat_archetype}
                            </span>
                          </div>
                          <h3 className="text-xs font-bold text-gray-100 truncate" title={camp.name}>
                            {camp.name}
                          </h3>
                        </div>

                        <div className="flex flex-col items-end flex-shrink-0">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-red-950 text-red-300 border border-red-800">
                            Risk {Math.round(camp.risk_score * 100)}%
                          </span>
                          <span className="text-[10px] text-gray-500 font-mono mt-1">
                            {camp.case_count} Case(s)
                          </span>
                        </div>
                      </div>

                      <p className="text-[11px] text-gray-400 mt-2 line-clamp-2 leading-relaxed">
                        {camp.description}
                      </p>

                      <div className="mt-3 flex flex-wrap gap-1.5">
                        {camp.tactics.slice(0, 2).map((t, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-0.5 bg-gray-950 rounded text-[10px] text-gray-400 border border-gray-800"
                          >
                            {t}
                          </span>
                        ))}
                        {camp.tactics.length > 2 && (
                          <span className="text-[10px] text-gray-500 self-center">
                            +{camp.tactics.length - 2} more
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right Column: Selected Campaign Deep-Dive & Visual Correlation Graph (7 Cols) */}
          <div className="lg:col-span-7 space-y-4">
            {loadingDetail ? (
              <div className="p-16 text-center text-gray-500 text-sm bg-gray-900/60 rounded-lg border border-gray-800">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-purple-400" />
                Synthesizing campaign graph & interconnected IOCs...
              </div>
            ) : !selectedCampaign ? (
              <div className="p-16 text-center text-gray-500 text-sm bg-gray-900/60 rounded-lg border border-gray-800">
                Select a threat campaign from the list to view its forensic correlation graph.
              </div>
            ) : (
              <div className="space-y-4">
                {/* Campaign Detail Banner */}
                <div className="p-5 bg-gray-900 border border-gray-800 rounded-lg space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800 pb-3">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs text-purple-400 font-bold">
                          {selectedCampaign.campaign_id}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${getArchetypeBadge(
                            selectedCampaign.threat_archetype
                          )}`}
                        >
                          {selectedCampaign.threat_archetype}
                        </span>
                      </div>
                      <h2 className="text-base font-bold text-gray-100 mt-1">
                        {selectedCampaign.name}
                      </h2>
                    </div>

                    <div className="flex items-center space-x-3 text-xs font-mono">
                      <div className="text-right">
                        <span className="text-gray-500 block text-[10px]">ATTRIBUTION CONFIDENCE</span>
                        <span className="text-emerald-400 font-bold">
                          {Math.round(selectedCampaign.confidence * 100)}%
                        </span>
                      </div>
                    </div>
                  </div>

                  <p className="text-xs text-gray-300 leading-relaxed">
                    {selectedCampaign.description}
                  </p>

                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-2 text-xs">
                    <div className="p-2.5 bg-gray-950 rounded border border-gray-800">
                      <span className="text-gray-500 block text-[10px]">CORRELATED CASES</span>
                      <span className="text-gray-200 font-mono font-bold text-sm">
                        {selectedCampaign.case_count}
                      </span>
                    </div>
                    <div className="p-2.5 bg-gray-950 rounded border border-gray-800">
                      <span className="text-gray-500 block text-[10px]">FIRST OBSERVED</span>
                      <span className="text-gray-200 font-mono text-[11px] truncate block">
                        {new Date(selectedCampaign.first_seen).toLocaleDateString()}
                      </span>
                    </div>
                    <div className="p-2.5 bg-gray-950 rounded border border-gray-800">
                      <span className="text-gray-500 block text-[10px]">LAST OBSERVED</span>
                      <span className="text-gray-200 font-mono text-[11px] truncate block">
                        {new Date(selectedCampaign.last_seen).toLocaleDateString()}
                      </span>
                    </div>
                    <div className="p-2.5 bg-gray-950 rounded border border-gray-800">
                      <span className="text-gray-500 block text-[10px]">SHARED IOC ANCHORS</span>
                      <span className="text-purple-400 font-mono font-bold text-sm">
                        {selectedCampaign.shared_artifacts.length}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Shared Threat Anchors / Infrastructure Pills */}
                {selectedCampaign.shared_artifacts.length > 0 && (
                  <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg space-y-2">
                    <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Target className="w-3.5 h-3.5 text-purple-400" />
                      Shared Campaign Infrastructure & Pivots
                    </h4>
                    <div className="flex flex-wrap gap-2 pt-1">
                      {selectedCampaign.shared_artifacts.map((art, idx) => (
                        <div
                          key={idx}
                          className="flex items-center space-x-1.5 px-2.5 py-1 bg-gray-950 border border-gray-800 rounded text-xs font-mono"
                        >
                          <span className="text-[10px] uppercase font-bold text-purple-400">
                            {art.kind}:
                          </span>
                          <span className="text-gray-200 font-semibold">{art.value}</span>
                          <span className="px-1.5 py-0.2 bg-purple-950/80 text-purple-300 text-[10px] rounded border border-purple-800/80">
                            {art.occurrences}x
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Visual Interconnected Graph Panel */}
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                      <Network className="w-3.5 h-3.5 text-indigo-400" />
                      Multi-Case Infrastructure Topology
                    </h4>
                    <span className="text-[11px] font-mono text-gray-500">
                      {selectedCampaign.graph.nodes.length} Nodes | {selectedCampaign.graph.edges.length} Connections
                    </span>
                  </div>

                  {/* Interactive Nodes Visualization Matrix */}
                  <div className="p-4 bg-black/90 border border-gray-800 rounded-md min-h-[220px] space-y-3">
                    <div className="flex flex-wrap gap-2">
                      {selectedCampaign.graph.nodes.map((node) => (
                        <div
                          key={node.id}
                          className={`p-2.5 rounded-md border text-xs flex flex-col justify-between max-w-[240px] ${getNodeColor(
                            node.type
                          )}`}
                        >
                          <div className="flex items-center justify-between gap-2 mb-1">
                            <span className="text-[10px] uppercase font-mono font-bold tracking-wider opacity-75">
                              {node.sublabel || node.type}
                            </span>
                            {node.risk_level && (
                              <span className="text-[9px] uppercase font-mono px-1 rounded bg-black/40">
                                {node.risk_level}
                              </span>
                            )}
                          </div>
                          <span className="font-semibold text-xs truncate" title={node.label}>
                            {node.label}
                          </span>
                        </div>
                      ))}
                    </div>

                    <div className="pt-2 border-t border-gray-800/80 text-[11px] text-gray-500 flex flex-wrap items-center gap-4">
                      <span className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-indigo-500" /> Member Cases
                      </span>
                      <span className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-amber-500" /> Shared Financial Accounts
                      </span>
                      <span className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-purple-500" /> Sender Domains
                      </span>
                      <span className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-cyan-500" /> Ingress IPs
                      </span>
                      <span className="flex items-center gap-1">
                        <span className="w-2 h-2 rounded-full bg-rose-500" /> Malware Hashes
                      </span>
                    </div>
                  </div>
                </div>

                {/* Member Cases Table */}
                <div className="p-4 bg-gray-900 border border-gray-800 rounded-lg space-y-3">
                  <h4 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center gap-1.5">
                    <Layers className="w-3.5 h-3.5 text-emerald-400" />
                    Correlated Cases in Campaign ({selectedCampaign.cases.length})
                  </h4>

                  <div className="space-y-2">
                    {selectedCampaign.cases.map((cs) => (
                      <div
                        key={cs.case_id}
                        className="p-3 bg-gray-950 border border-gray-800 rounded-md flex flex-wrap items-center justify-between gap-3 text-xs"
                      >
                        <div className="space-y-0.5 min-w-0">
                          <div className="flex items-center space-x-2">
                            <span className="font-semibold text-gray-200">{cs.filename}</span>
                            <span className="text-gray-500 font-mono text-[11px]">
                              ({new Date(cs.created_at).toLocaleDateString()})
                            </span>
                          </div>
                          <div className="text-[11px] text-gray-400 font-mono truncate">
                            From: <span className="text-indigo-300">{cs.from_email}</span> → To: <span className="text-gray-300">{cs.recipient}</span>
                          </div>
                        </div>

                        <div className="flex items-center space-x-3">
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-red-950 text-red-300 border border-red-800">
                            Risk {Math.round(cs.score * 100)}%
                          </span>
                          <Link
                            href={`/cases/${cs.case_id}`}
                            className="flex items-center space-x-1 px-2.5 py-1 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs transition-colors"
                          >
                            <span>Open Case</span>
                            <ArrowRight className="w-3 h-3" />
                          </Link>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </ProtectedRoute>
  );
}
