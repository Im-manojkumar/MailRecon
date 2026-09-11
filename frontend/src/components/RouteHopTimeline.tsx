'use client';

import React from 'react';
import { RouteAnalysisResponse, RouteHopEnrichment } from '@/lib/types';
import { Clock, Globe, Shield, AlertTriangle, ArrowDown, Lock, Server } from 'lucide-react';

interface Props {
  route: RouteAnalysisResponse | null;
}

export default function RouteHopTimeline({ route }: Props) {
  if (!route || !route.hops || route.hops.length === 0) {
    return (
      <div className="p-8 text-center text-gray-500 border border-dashed border-gray-800 rounded-lg">
        <Server className="w-8 h-8 mx-auto mb-2 opacity-50" />
        No Received routing hops found in message headers.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Route Summary Bar */}
      <div className="flex flex-wrap items-center justify-between p-4 bg-gray-900/60 border border-gray-800 rounded-lg gap-4">
        <div className="flex items-center space-x-3">
          <Clock className="w-5 h-5 text-primary-400" />
          <div>
            <div className="text-xs text-gray-400">Total Transport Transit Time</div>
            <div className="text-sm font-semibold text-gray-200 font-mono">
              {route.total_transit_display || (route.total_transit_seconds != null ? `${route.total_transit_seconds.toFixed(1)}s` : 'Unknown')}
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <Server className="w-5 h-5 text-indigo-400" />
          <div>
            <div className="text-xs text-gray-400">MTA Hops Inspected</div>
            <div className="text-sm font-semibold text-gray-200 font-mono">{route.hops.length} relays</div>
          </div>
        </div>

        {route.origin_confidence && (
          <div className="flex items-center space-x-2">
            <span className="text-xs text-gray-400">Origin Trace Confidence:</span>
            <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold uppercase ${
              route.origin_confidence === 'high'
                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                : route.origin_confidence === 'medium'
                ? 'bg-amber-950 text-amber-300 border border-amber-800'
                : 'bg-red-950 text-red-300 border border-red-800'
            }`}>
              {route.origin_confidence}
            </span>
          </div>
        )}

        {route.anomalies && route.anomalies.length > 0 && (
          <div className="flex items-center space-x-2 px-3 py-1 bg-red-950/60 border border-red-800/80 rounded text-red-300 text-xs">
            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <span>{route.anomalies.length} transport anomaly detected</span>
          </div>
        )}
      </div>

      {/* Originating Ingress Node Spotlight */}
      {route.originating_node && (
        <div className="p-4 bg-gradient-to-r from-amber-950/40 via-gray-900 to-gray-900 border border-amber-800/60 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-ping" />
              <span className="text-xs font-bold text-amber-300 uppercase tracking-wider">
                Forensic Originating Ingress Node
              </span>
            </div>
            <span className="text-[11px] font-mono text-amber-400/80">
              Earliest Trustworthy Public Relay
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3 text-xs pt-1">
            <div className="bg-gray-950/80 p-2.5 rounded border border-gray-800">
              <span className="text-gray-500 block mb-0.5">Originating IP</span>
              <span className="text-gray-200 font-mono font-bold">{route.originating_node.ip || 'Unknown'}</span>
            </div>
            <div className="bg-gray-950/80 p-2.5 rounded border border-gray-800">
              <span className="text-gray-500 block mb-0.5">Location</span>
              <span className="text-gray-200 font-semibold">
                {route.originating_node.geoip?.city ? `${route.originating_node.geoip.city}, ` : ''}
                {route.originating_node.geoip?.country || 'Unknown'}
              </span>
            </div>
            <div className="bg-gray-950/80 p-2.5 rounded border border-gray-800">
              <span className="text-gray-500 block mb-0.5">ISP & ASN</span>
              <span className="text-gray-200 font-mono truncate block" title={route.originating_node.geoip?.isp || route.originating_node.geoip?.org || ''}>
                {route.originating_node.geoip?.asn || ''} {route.originating_node.geoip?.isp || route.originating_node.geoip?.org || 'Public ISP'}
              </span>
            </div>
            <div className="bg-gray-950/80 p-2.5 rounded border border-gray-800">
              <span className="text-gray-500 block mb-0.5">Infrastructure Archetype</span>
              <span className={`px-2 py-0.5 rounded text-[11px] font-bold uppercase inline-block ${
                route.originating_node.infra_tag?.risk_level === 'critical'
                  ? 'bg-red-950 text-red-300 border border-red-800'
                  : route.originating_node.infra_tag?.risk_level === 'high'
                  ? 'bg-orange-950 text-orange-300 border border-orange-800'
                  : route.originating_node.infra_tag?.risk_level === 'medium'
                  ? 'bg-purple-950 text-purple-300 border border-purple-800'
                  : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
              }`}>
                {route.originating_node.infra_tag?.label || 'Public Gateway'}
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Anomalies List */}
      {route.anomalies && route.anomalies.length > 0 && (
        <div className="p-4 bg-red-950/30 border border-red-900/50 rounded-lg space-y-2">
          <div className="text-xs font-bold text-red-400 uppercase tracking-wider flex items-center space-x-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Route Timing & Integrity Anomalies</span>
          </div>
          <ul className="text-xs text-red-300 space-y-1 list-disc list-inside">
            {route.anomalies.map((anom, idx) => (
              <li key={idx} className="leading-relaxed">{anom}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Chronological Hop Progression */}
      <div className="relative pl-6 space-y-8 before:absolute before:left-3 before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-indigo-500 before:via-blue-500 before:to-gray-700">
        {route.hops.map((hop, index) => {
          const hopNumber = hop.hop_number || hop.hop || (index + 1);
          const isOrigin = hop.is_originating || index === 0;
          const isFinal = index === route.hops.length - 1;
          const hasNegativeDelay = hop.delay_seconds != null && hop.delay_seconds < -15;
          const hasExcessiveDelay = hop.delay_seconds != null && hop.delay_seconds > 600;

          return (
            <div key={index} className="relative group">
              {/* Hop Marker Dot */}
              <div
                className={`absolute -left-[27px] top-1.5 w-4 h-4 rounded-full border-2 flex items-center justify-center ${
                  isOrigin
                    ? 'bg-amber-500 border-amber-300 text-black'
                    : isFinal
                    ? 'bg-emerald-500 border-emerald-300 text-black'
                    : 'bg-gray-900 border-indigo-400'
                }`}
              >
                <div className="w-1.5 h-1.5 rounded-full bg-white" />
              </div>

              {/* Hop Card */}
              <div className="p-4 bg-gray-900/80 border border-gray-800 rounded-lg hover:border-gray-700 transition-colors space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800/80 pb-2">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold text-indigo-400 uppercase">
                      Hop {hopNumber}
                    </span>
                    {isOrigin && (
                      <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-amber-950 text-amber-300 border border-amber-700 rounded">
                        ORIGIN INGESTION
                      </span>
                    )}
                    {isFinal && (
                      <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-700 rounded">
                        DESTINATION MX
                      </span>
                    )}
                    {hop.infra_tag && (
                      <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${
                        hop.infra_tag.risk_level === 'critical'
                          ? 'bg-red-950 text-red-300 border border-red-800'
                          : hop.infra_tag.risk_level === 'high'
                          ? 'bg-orange-950 text-orange-300 border border-orange-800'
                          : hop.infra_tag.risk_level === 'medium'
                          ? 'bg-purple-950 text-purple-300 border border-purple-800'
                          : 'bg-gray-800 text-gray-300 border border-gray-700'
                      }`}>
                        {hop.infra_tag.label}
                      </span>
                    )}
                  </div>

                  {hop.timestamp_iso && (
                    <div className="text-xs text-gray-400 font-mono">
                      {new Date(hop.timestamp_iso).toUTCString()}
                    </div>
                  )}
                </div>

                {/* Claimed vs Receiving Node */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-gray-500 block mb-0.5">Claimed Sender (from):</span>
                    <span className="text-gray-200 font-mono break-all">{hop.from_claimed || hop.from_host || 'Not specified'}</span>
                  </div>
                  <div>
                    <span className="text-gray-500 block mb-0.5">Receiving Node (by):</span>
                    <span className="text-gray-200 font-mono break-all">{hop.by_node || hop.by_host || 'Not specified'}</span>
                  </div>
                </div>

                {/* Infrastructure & GeoIP */}
                <div className="flex flex-wrap items-center gap-2 pt-1 text-xs">
                  {hop.ip && (
                    <span className="px-2 py-1 font-mono bg-gray-950 text-gray-300 border border-gray-800 rounded">
                      IP: {hop.ip}
                    </span>
                  )}

                  {hop.geoip && (
                    <>
                      {hop.geoip.is_private ? (
                        <span className="px-2 py-1 bg-gray-800 text-gray-300 rounded border border-gray-700">
                          RFC 1918 Private Network
                        </span>
                      ) : (
                        <>
                          {hop.geoip.country && (
                            <span className="px-2 py-1 bg-blue-950/80 text-blue-300 border border-blue-800 rounded flex items-center space-x-1">
                              <Globe className="w-3 h-3" />
                              <span>{hop.geoip.city ? `${hop.geoip.city}, ` : ''}{hop.geoip.country}</span>
                            </span>
                          )}
                          {hop.geoip.asn && (
                            <span className="px-2 py-1 bg-purple-950/80 text-purple-300 border border-purple-800 rounded">
                              {hop.geoip.asn} {hop.geoip.org || hop.geoip.isp ? `(${hop.geoip.org || hop.geoip.isp})` : ''}
                            </span>
                          )}
                        </>
                      )}
                    </>
                  )}

                  {/* TLS Security */}
                  {hop.tls_version ? (
                    <span className="px-2 py-1 bg-emerald-950/70 text-emerald-300 border border-emerald-800 rounded flex items-center space-x-1">
                      <Lock className="w-3 h-3 text-emerald-400" />
                      <span>{hop.tls_version}</span>
                    </span>
                  ) : (
                    <span className="px-2 py-1 bg-gray-800/80 text-gray-400 border border-gray-700 rounded flex items-center space-x-1">
                      <Lock className="w-3 h-3 text-gray-500" />
                      <span>Plaintext / No TLS</span>
                    </span>
                  )}
                </div>

                {/* Inter-hop Delay Metric */}
                {index > 0 && (hop.delay_display || hop.delay_seconds != null) && (
                  <div className="mt-2 pt-2 border-t border-gray-800/60 flex items-center space-x-2 text-xs">
                    <ArrowDown className="w-3.5 h-3.5 text-gray-500" />
                    <span className="text-gray-400">Transit delay from prior hop:</span>
                    <span
                      className={`font-mono font-semibold ${
                        hasNegativeDelay
                          ? 'text-red-400'
                          : hasExcessiveDelay
                          ? 'text-yellow-400'
                          : 'text-gray-200'
                      }`}
                    >
                      {hop.delay_display || `${hop.delay_seconds?.toFixed(1)}s`}
                    </span>
                    {hasNegativeDelay && (
                      <span className="text-red-400 font-semibold text-[11px]">
                        (Clock Skew / Forged Header Anomaly)
                      </span>
                    )}
                    {hasExcessiveDelay && (
                      <span className="text-yellow-400 text-[11px]">(Significant Queueing Delay)</span>
                    )}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
