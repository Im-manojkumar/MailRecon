'use client';

import React, { useState } from 'react';
import {
  ParsedEmailResponse,
  QrCodeResult,
  AttachmentInfo,
  ExtractedUrl,
  MacroAnalysisItem,
  ObfuscationAnalysisResponse,
  LiveDnsValidationResponse,
} from '@/lib/types';
import {
  Mail,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  FileText,
  Link2,
  Paperclip,
  QrCode,
  Eye,
  ExternalLink,
  Code2,
  Terminal,
  Cpu,
  Sparkles,
  ChevronDown,
  ChevronUp,
  Globe,
  Server,
  Lock,
} from 'lucide-react';

interface Props {
  parsed: ParsedEmailResponse | null;
  qrCodes?: QrCodeResult[];
  macros?: MacroAnalysisItem[];
  obfuscation?: ObfuscationAnalysisResponse | null;
  dnsValidation?: LiveDnsValidationResponse | null;
  caseId: string;
}

export default function EmailViewer({ parsed, qrCodes, macros, obfuscation, dnsValidation, caseId }: Props) {
  const [viewMode, setViewMode] = useState<'html' | 'text' | 'headers'>('html');
  const [showAllHeaders, setShowAllHeaders] = useState(false);
  const [deobfMode, setDeobfMode] = useState(false);
  const [expandedMacroSha, setExpandedMacroSha] = useState<string | null>(null);

  if (!parsed) {
    return (
      <div className="p-12 text-center text-gray-500 border border-dashed border-gray-800 rounded-lg">
        <Mail className="w-10 h-10 mx-auto mb-3 opacity-40 animate-pulse" />
        <p className="text-sm font-medium text-gray-400">Email parsing pending or not available</p>
      </div>
    );
  }

  const authResults = parsed.auth_results_json || {};
  const headers = parsed.headers_json || {};
  const urls: ExtractedUrl[] = parsed.urls_json || [];
  const attachments: AttachmentInfo[] = parsed.attachments_json || [];

  const getAuthBadge = (status: string | undefined, method: string) => {
    const s = (status || 'none').toLowerCase();
    if (s === 'pass') {
      return (
        <span className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 rounded">
          <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
          <span>{method.toUpperCase()}: PASS</span>
        </span>
      );
    }
    if (s === 'fail' || s === 'hardfail') {
      return (
        <span className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono font-semibold bg-red-950/80 text-red-300 border border-red-700/80 rounded">
          <XCircle className="w-3.5 h-3.5 text-red-400" />
          <span>{method.toUpperCase()}: FAIL</span>
        </span>
      );
    }
    if (s === 'softfail') {
      return (
        <span className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono font-semibold bg-amber-950/80 text-amber-300 border border-amber-700/80 rounded">
          <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          <span>{method.toUpperCase()}: SOFTFAIL</span>
        </span>
      );
    }
    return (
      <span className="flex items-center space-x-1 px-2.5 py-1 text-xs font-mono font-semibold bg-gray-800 text-gray-400 border border-gray-700 rounded">
        <span>{method.toUpperCase()}: {s.toUpperCase()}</span>
      </span>
    );
  };

  const hasEvasion = obfuscation?.has_evasion;
  const zeroWidthCount = (obfuscation?.body?.zero_width_count || 0) + (obfuscation?.subject?.zero_width_count || 0);
  const rloDetected = obfuscation?.body?.rlo_detected || obfuscation?.subject?.rlo_detected;
  const homoglyphCount = (obfuscation?.body?.homoglyphs_found?.length || 0) + (obfuscation?.subject?.homoglyphs_found?.length || 0);
  const mixedTokens = [
    ...(obfuscation?.body?.mixed_script_tokens || []),
    ...(obfuscation?.subject?.mixed_script_tokens || [])
  ];

  return (
    <div className="space-y-6">
      {/* 0. Adversarial Evasion & Obfuscation Alert Banner */}
      {hasEvasion && (
        <div className="p-4 bg-amber-950/40 border border-amber-800/80 rounded-lg space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center space-x-2.5">
              <Sparkles className="w-5 h-5 text-amber-400 animate-pulse" />
              <div>
                <h3 className="text-xs font-bold text-amber-200 uppercase tracking-wider">
                  Adversarial Evasion & Obfuscation Detected
                </h3>
                <p className="text-[11px] text-amber-300/80">
                  Adversaries inserted deceptive Unicode mechanisms to bypass traditional spam/keyword filters.
                </p>
              </div>
            </div>

            <button
              onClick={() => setDeobfMode(!deobfMode)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-md border transition-colors flex items-center space-x-1.5 ${
                deobfMode
                  ? 'bg-amber-600 text-white border-amber-500 shadow-md'
                  : 'bg-amber-950/80 text-amber-300 border-amber-700 hover:bg-amber-900/60'
              }`}
            >
              <Cpu className="w-3.5 h-3.5" />
              <span>{deobfMode ? 'De-obfuscation Active' : 'Normalize Content'}</span>
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono">
            {zeroWidthCount > 0 && (
              <span className="px-2 py-0.5 bg-amber-900/60 text-amber-200 border border-amber-700/60 rounded">
                Zero-Width Hidden Chars: {zeroWidthCount}
              </span>
            )}
            {rloDetected && (
              <span className="px-2 py-0.5 bg-red-900/80 text-red-200 border border-red-700/80 rounded">
                Right-to-Left Override (RLO) Found
              </span>
            )}
            {homoglyphCount > 0 && (
              <span className="px-2 py-0.5 bg-amber-900/60 text-amber-200 border border-amber-700/60 rounded">
                Cyrillic/Greek Homoglyphs: {homoglyphCount}
              </span>
            )}
            {mixedTokens.length > 0 && (
              <span className="px-2 py-0.5 bg-amber-900/60 text-amber-200 border border-amber-700/60 rounded">
                Mixed-Script Tokens: {mixedTokens.slice(0, 3).join(', ')}
              </span>
            )}
          </div>
        </div>
      )}

      {/* 1. RFC 8601 Authentication Header Claims */}
      <div className="p-4 bg-gray-900/80 border border-gray-800 rounded-lg space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4 text-indigo-400" />
            <span className="text-xs font-bold text-gray-300 uppercase tracking-wider">
              RFC 8601 Authentication Results
            </span>
          </div>
          <span className="text-[11px] text-gray-500 italic">
            Provenance: Header claim parsed at destination MX
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3 pt-1">
          {getAuthBadge(authResults.spf?.result, 'SPF')}
          {getAuthBadge(authResults.dkim?.result, 'DKIM')}
          {getAuthBadge(authResults.dmarc?.result, 'DMARC')}
        </div>
      </div>

      {/* 1b. Live DNS Protocol Validation & Identity Alignment */}
      {dnsValidation && dnsValidation.domain && (
        <div className="p-4 bg-gray-900/80 border border-gray-800 rounded-lg space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800/80 pb-2.5">
            <div className="flex items-center space-x-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold text-gray-200 uppercase tracking-wider">
                Live DNS Protocol Validation & Identity Alignment
              </span>
              <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-cyan-950/80 text-cyan-300 border border-cyan-800/60">
                Authoritative Resolver
              </span>
            </div>
            <div className="flex items-center space-x-2 text-xs font-mono">
              <span className="text-gray-400">Target Domain:</span>
              <span className="text-cyan-300 font-semibold">{dnsValidation.domain}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
            {/* SPF Live Card */}
            <div className="p-3 bg-gray-950/60 border border-gray-800/80 rounded-md space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-gray-300 flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-indigo-400" /> Live SPF Check
                </span>
                {dnsValidation.spf?.is_ip_authorized === true ? (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800 rounded">
                    AUTHORIZED IP
                  </span>
                ) : dnsValidation.spf?.is_ip_authorized === false ? (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-red-950/80 text-red-400 border border-red-800 rounded">
                    UNAUTHORIZED IP
                  </span>
                ) : (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-gray-800 text-gray-400 border border-gray-700 rounded">
                    {dnsValidation.spf?.raw_record ? 'RECORD FOUND' : 'NO RECORD'}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-gray-400 font-mono truncate" title={dnsValidation.spf?.raw_record || 'None'}>
                {dnsValidation.spf?.raw_record || 'No SPF TXT record published'}
              </p>
              {dnsValidation.spf?.default_policy && (
                <div className="text-[10px] text-gray-500 font-mono">
                  Default Policy: <span className="text-gray-300 font-bold">{dnsValidation.spf.default_policy}</span>
                </div>
              )}
            </div>

            {/* DMARC Policy Card */}
            <div className="p-3 bg-gray-950/60 border border-gray-800/80 rounded-md space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-gray-300 flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-purple-400" /> DMARC Policy
                </span>
                {dnsValidation.dmarc?.is_enforced ? (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800 rounded">
                    ENFORCED ({dnsValidation.dmarc.policy?.toUpperCase()})
                  </span>
                ) : dnsValidation.dmarc?.policy ? (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-amber-950/80 text-amber-400 border border-amber-800 rounded">
                    MONITOR ONLY (p={dnsValidation.dmarc.policy})
                  </span>
                ) : (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-red-950/80 text-red-400 border border-red-800 rounded">
                    NO DMARC RECORD
                  </span>
                )}
              </div>
              <p className="text-[11px] text-gray-400 font-mono truncate" title={dnsValidation.dmarc?.raw_record || 'None'}>
                {dnsValidation.dmarc?.raw_record || 'No _dmarc TXT record'}
              </p>
              <div className="text-[10px] text-gray-500 font-mono">
                Subdomain: <span className="text-gray-300">{dnsValidation.dmarc?.subdomain_policy || 'inherit'}</span> | Pct: <span className="text-gray-300">{dnsValidation.dmarc?.percentage ?? 100}%</span>
              </div>
            </div>

            {/* Alignment & Inbound MX */}
            <div className="p-3 bg-gray-950/60 border border-gray-800/80 rounded-md space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="font-semibold text-gray-300 flex items-center gap-1.5">
                  <Lock className="w-3.5 h-3.5 text-cyan-400" /> Identity Alignment
                </span>
                {dnsValidation.alignment?.dmarc_pass ? (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800 rounded">
                    ALIGNED (PASS)
                  </span>
                ) : (
                  <span className="px-1.5 py-0.5 text-[10px] font-mono bg-amber-950/80 text-amber-400 border border-amber-800 rounded">
                    ALIGNMENT FAIL
                  </span>
                )}
              </div>
              <div className="text-[10px] font-mono text-gray-400 space-y-0.5">
                <div>SPF Alignment: <span className="text-gray-200">{dnsValidation.alignment?.spf_alignment || 'none'}</span></div>
                <div>DKIM Alignment: <span className="text-gray-200">{dnsValidation.alignment?.dkim_alignment || 'none'}</span></div>
                <div>Inbound MX: {dnsValidation.mx?.is_send_only ? (
                  <span className="text-red-400 font-bold">SEND-ONLY / NO MX</span>
                ) : (
                  <span className="text-emerald-400 font-medium">{dnsValidation.mx?.servers?.length || 0} MX host(s)</span>
                )}</div>
              </div>
            </div>
          </div>

          {/* DNS Anomalies */}
          {dnsValidation.anomalies && dnsValidation.anomalies.length > 0 && (
            <div className="p-2.5 bg-red-950/20 border border-red-900/40 rounded text-xs space-y-1">
              <span className="text-red-400 font-semibold text-[11px] flex items-center gap-1">
                <AlertTriangle className="w-3.5 h-3.5 text-red-400" /> DNS / Protocol Anomalies Detected:
              </span>
              <ul className="list-disc list-inside text-gray-300 text-[11px] space-y-0.5 pl-1">
                {dnsValidation.anomalies.map((anom, idx) => (
                  <li key={idx}>{anom}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* 2. Key Envelope Headers */}
      <div className="p-4 bg-gray-900/60 border border-gray-800 rounded-lg space-y-2 text-xs">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 font-mono">
          <div>
            <span className="text-gray-500 font-sans">From: </span>
            <span className="text-gray-200">{headers.from || '(No From header)'}</span>
          </div>
          <div>
            <span className="text-gray-500 font-sans">To: </span>
            <span className="text-gray-200">{headers.to || '(No To header)'}</span>
          </div>
          <div>
            <span className="text-gray-500 font-sans">Subject: </span>
            {deobfMode && obfuscation?.subject?.has_evasion ? (
              <span className="text-cyan-300 font-semibold">
                {obfuscation.subject.normalized_preview || headers.subject}
                <span className="ml-2 px-1.5 py-0.5 text-[9px] font-mono uppercase bg-cyan-950 text-cyan-300 border border-cyan-800 rounded">
                  De-obfuscated
                </span>
              </span>
            ) : (
              <span className="text-gray-200 font-semibold">{headers.subject || '(No Subject)'}</span>
            )}
          </div>
          <div>
            <span className="text-gray-500 font-sans">Date: </span>
            <span className="text-gray-400">{headers.date || '(No Date header)'}</span>
          </div>
          {headers.reply_to && (
            <div className="md:col-span-2">
              <span className="text-amber-400 font-sans font-semibold">Reply-To: </span>
              <span className="text-amber-200">{headers.reply_to}</span>
            </div>
          )}
        </div>
      </div>

      {/* 3. Body & Header Viewer Tabs */}
      <div className="space-y-3">
        <div className="flex items-center justify-between border-b border-gray-800 pb-2">
          <div className="flex space-x-2">
            <button
              onClick={() => setViewMode('html')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                viewMode === 'html'
                  ? 'bg-primary-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-200'
              }`}
            >
              Sanitized HTML
            </button>
            <button
              onClick={() => setViewMode('text')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                viewMode === 'text'
                  ? 'bg-primary-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-200'
              }`}
            >
              Plain Text
            </button>
            <button
              onClick={() => setViewMode('headers')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                viewMode === 'headers'
                  ? 'bg-primary-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-200'
              }`}
            >
              All RFC Headers
            </button>
          </div>
        </div>

        {/* View Mode Content */}
        {viewMode === 'html' && (
          <div className="border border-gray-800 rounded-lg overflow-hidden bg-white text-gray-900">
            <div className="p-2.5 bg-gray-950 border-b border-gray-800 text-xs text-gray-400 flex items-center justify-between">
              <span className="flex items-center space-x-1.5">
                <Shield className="w-3.5 h-3.5 text-emerald-400" />
                <span>Bleach HTML Sanitization Active (Tracking images & scripts disarmed)</span>
              </span>
            </div>
            {parsed.body_html ? (
              <div
                className="p-6 max-h-[500px] overflow-y-auto prose prose-sm max-w-none font-sans"
                dangerouslySetInnerHTML={{ __html: parsed.body_html }}
              />
            ) : (
              <div className="p-8 text-center text-gray-500 text-xs font-sans">
                No HTML body part present in email.
              </div>
            )}
          </div>
        )}

        {viewMode === 'text' && (
          <div className="border border-gray-800 rounded-lg overflow-hidden bg-gray-950 p-4 max-h-[500px] overflow-y-auto space-y-2">
            {deobfMode && obfuscation?.body?.has_evasion && (
              <div className="pb-2 mb-2 border-b border-gray-800 flex items-center justify-between text-[11px] font-mono text-cyan-400">
                <span>⚡ Active View: Normalized De-obfuscated Text</span>
                <span className="text-gray-500">
                  {obfuscation.body.zero_width_count} zero-width / homoglyph chars neutralized
                </span>
              </div>
            )}
            <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap leading-relaxed">
              {deobfMode && obfuscation?.body?.has_evasion
                ? (obfuscation.body.normalized_preview || parsed.body_text)
                : (parsed.body_text || '(Empty text body)')}
            </pre>
          </div>
        )}

        {viewMode === 'headers' && (
          <div className="border border-gray-800 rounded-lg overflow-hidden bg-gray-950 p-4 max-h-[500px] overflow-y-auto">
            <pre className="text-xs text-gray-400 font-mono whitespace-pre-wrap leading-relaxed">
              {JSON.stringify(headers.all_headers || headers, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* 4. Extracted URLs Section */}
      {urls.length > 0 && (
        <div className="p-5 bg-gray-900/80 border border-gray-800 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center space-x-2">
              <Link2 className="w-4 h-4 text-cyan-400" />
              <span>Extracted & Defanged URLs ({urls.length})</span>
            </h3>
            <span className="text-[11px] text-gray-500">Defanged: hxxps:// and [.]</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-gray-800 text-gray-500">
                  <th className="pb-2 font-medium">Defanged Target URL</th>
                  <th className="pb-2 font-medium">Domain</th>
                  <th className="pb-2 font-medium">Display Text</th>
                  <th className="pb-2 font-medium">Flags</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 font-mono">
                {urls.map((u, idx) => (
                  <tr key={idx} className="hover:bg-gray-800/30">
                    <td className="py-2.5 pr-4 text-cyan-300 break-all">{u.defanged || u.url}</td>
                    <td className="py-2.5 pr-4 text-gray-300">{u.domain}</td>
                    <td className="py-2.5 pr-4 text-gray-400 font-sans">{u.anchor_text || '—'}</td>
                    <td className="py-2.5">
                      {u.is_ip && (
                        <span className="px-1.5 py-0.5 text-[10px] bg-red-950 text-red-300 border border-red-800 rounded">
                          RAW IP
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 5. Attachments Section */}
      {attachments.length > 0 && (
        <div className="p-5 bg-gray-900/80 border border-gray-800 rounded-lg space-y-3">
          <h3 className="text-xs font-bold text-gray-300 uppercase tracking-wider flex items-center space-x-2">
            <Paperclip className="w-4 h-4 text-amber-400" />
            <span>Extracted Attachments ({attachments.length})</span>
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {attachments.map((att, idx) => {
              const macroInfo = macros?.find(
                (m) => m.sha256 === att.sha256 || m.filename === att.filename
              );
              const isMaliciousMacro = macroInfo?.has_macros && macroInfo?.is_malicious;

              return (
                <div
                  key={idx}
                  className={`p-3.5 rounded-lg border space-y-2.5 ${
                    isMaliciousMacro
                      ? 'bg-red-950/40 border-red-700/90 shadow-lg shadow-red-950/30'
                      : att.is_macro
                      ? 'bg-amber-950/30 border-amber-800/80'
                      : 'bg-gray-950/60 border-gray-800'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-gray-200 font-mono break-all">
                      {att.filename}
                    </span>
                    {isMaliciousMacro ? (
                      <span className="px-1.5 py-0.5 text-[10px] font-bold uppercase bg-red-900 text-red-100 border border-red-700 rounded animate-pulse">
                        WEAPONIZED MACRO
                      </span>
                    ) : att.is_macro ? (
                      <span className="px-1.5 py-0.5 text-[10px] font-bold uppercase bg-amber-900 text-amber-200 border border-amber-700 rounded">
                        MACRO CONTAINER
                      </span>
                    ) : null}
                  </div>

                  <div className="text-[11px] text-gray-400 font-mono space-y-0.5">
                    <div>Type: {att.content_type}</div>
                    <div>Size: {(att.size / 1024).toFixed(1)} KB</div>
                    <div className="text-gray-500 break-all">SHA-256: {att.sha256}</div>
                  </div>

                  {/* Static VBA Macro Forensic Triage Details */}
                  {macroInfo && macroInfo.has_macros && (
                    <div className="pt-2 border-t border-gray-800/80 space-y-2">
                      <div className="text-[11px] font-bold text-gray-300 flex items-center space-x-1.5">
                        <Terminal className="w-3.5 h-3.5 text-amber-400" />
                        <span>Static VBA Macro Triage ({macroInfo.macro_count} Stream)</span>
                      </div>

                      {macroInfo.triggers && macroInfo.triggers.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-gray-400 font-mono">Triggers: </span>
                          <div className="flex flex-wrap gap-1">
                            {macroInfo.triggers.map((t) => (
                              <span
                                key={t}
                                className="px-1.5 py-0.5 text-[10px] font-mono bg-red-950 text-red-300 border border-red-800 rounded font-semibold"
                              >
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {macroInfo.suspicious_keywords && macroInfo.suspicious_keywords.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-gray-400 font-mono">Capabilities: </span>
                          <div className="flex flex-wrap gap-1">
                            {macroInfo.suspicious_keywords.slice(0, 4).map((kw, kIdx) => (
                              <span
                                key={kIdx}
                                className="px-1.5 py-0.5 text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800 rounded"
                              >
                                {kw.keyword}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {macroInfo.extracted_iocs && macroInfo.extracted_iocs.length > 0 && (
                        <div className="space-y-1">
                          <span className="text-[10px] text-gray-400 font-mono">Extracted IoCs: </span>
                          <div className="space-y-0.5">
                            {macroInfo.extracted_iocs.slice(0, 2).map((ioc, iIdx) => (
                              <div
                                key={iIdx}
                                className="text-[10px] font-mono text-cyan-300 break-all bg-gray-900/80 px-2 py-0.5 rounded border border-gray-800"
                              >
                                [{ioc.type}] {ioc.value}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {macroInfo.code_preview && (
                        <div className="pt-1">
                          <button
                            onClick={() =>
                              setExpandedMacroSha(
                                expandedMacroSha === att.sha256 ? null : att.sha256
                              )
                            }
                            className="flex items-center space-x-1 text-[10px] font-mono text-indigo-400 hover:text-indigo-300 transition-colors"
                          >
                            <span>
                              {expandedMacroSha === att.sha256
                                ? 'Hide Extracted VBA Code'
                                : 'Inspect Extracted VBA Code Preview'}
                            </span>
                            {expandedMacroSha === att.sha256 ? (
                              <ChevronUp className="w-3 h-3" />
                            ) : (
                              <ChevronDown className="w-3 h-3" />
                            )}
                          </button>

                          {expandedMacroSha === att.sha256 && (
                            <pre className="mt-1.5 p-2 bg-black/90 text-emerald-300 border border-gray-800 rounded text-[10px] font-mono overflow-x-auto max-h-40 leading-tight whitespace-pre-wrap">
                              {macroInfo.code_preview}
                            </pre>
                          )}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* 6. QR Code (Quishing) Section */}
      {qrCodes && qrCodes.length > 0 && (
        <div className="p-5 bg-purple-950/30 border border-purple-900/60 rounded-lg space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-purple-300 uppercase tracking-wider flex items-center space-x-2">
              <QrCode className="w-4 h-4 text-purple-400" />
              <span>Decoded QR Code Matrices (Quishing Defense)</span>
            </h3>
            <span className="text-[11px] text-purple-400 font-medium">Decompression Safe</span>
          </div>

          <div className="space-y-2">
            {qrCodes.map((qr, idx) => (
              <div
                key={idx}
                className="p-3 bg-gray-950/70 border border-purple-800/50 rounded-lg space-y-1 font-mono text-xs"
              >
                <div className="text-gray-400">Source: {qr.attachment_name}</div>
                <div className="text-purple-300 break-all font-semibold">
                  Defanged Target: {qr.defanged_text || qr.decoded_text}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
