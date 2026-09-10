'use client';

import React, { useState } from 'react';
import { ParsedEmailResponse, QrCodeResult, AttachmentInfo, ExtractedUrl } from '@/lib/types';
import { Mail, Shield, AlertTriangle, CheckCircle, XCircle, FileText, Link2, Paperclip, QrCode, Eye, ExternalLink, Code2 } from 'lucide-react';

interface Props {
  parsed: ParsedEmailResponse | null;
  qrCodes?: QrCodeResult[];
  caseId: string;
}

export default function EmailViewer({ parsed, qrCodes, caseId }: Props) {
  const [viewMode, setViewMode] = useState<'html' | 'text' | 'headers'>('html');
  const [showAllHeaders, setShowAllHeaders] = useState(false);

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

  return (
    <div className="space-y-6">
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
            <span className="text-gray-200 font-semibold">{headers.subject || '(No Subject)'}</span>
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
          <div className="border border-gray-800 rounded-lg overflow-hidden bg-gray-950 p-4 max-h-[500px] overflow-y-auto">
            <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap leading-relaxed">
              {parsed.body_text || '(Empty text body)'}
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
            {attachments.map((att, idx) => (
              <div
                key={idx}
                className={`p-3 rounded-lg border ${
                  att.is_macro
                    ? 'bg-red-950/30 border-red-800/80'
                    : 'bg-gray-950/60 border-gray-800'
                } space-y-2`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-semibold text-gray-200 font-mono break-all">
                    {att.filename}
                  </span>
                  {att.is_macro && (
                    <span className="px-1.5 py-0.5 text-[10px] font-bold uppercase bg-red-900 text-red-200 rounded">
                      MACRO ENABLED
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-gray-400 font-mono space-y-0.5">
                  <div>Type: {att.content_type}</div>
                  <div>Size: {(att.size / 1024).toFixed(1)} KB</div>
                  <div className="text-gray-500 break-all">SHA-256: {att.sha256}</div>
                </div>
              </div>
            ))}
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
