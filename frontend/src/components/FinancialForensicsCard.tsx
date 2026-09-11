'use client';

import React, { useState } from 'react';
import { FinancialForensicsResponse } from '@/lib/types';
import {
  DollarSign,
  CreditCard,
  AlertTriangle,
  Copy,
  Check,
  Building2,
  Coins,
  ShieldAlert,
  FileCheck,
} from 'lucide-react';

interface Props {
  financial: FinancialForensicsResponse | null;
}

export default function FinancialForensicsCard({ financial }: Props) {
  const [copiedText, setCopiedText] = useState<string | null>(null);

  if (!financial || (!financial.is_financial_threat && financial.bank_accounts.length === 0 && financial.routing_numbers.length === 0 && financial.crypto_wallets.length === 0 && !financial.vendor_mismatch)) {
    return null;
  }

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const isCritical = financial.risk_level === 'critical' || financial.threat_score >= 0.7;

  return (
    <div className={`p-4 rounded-lg border space-y-4 ${
      isCritical
        ? 'bg-red-950/30 border-red-800/80'
        : 'bg-amber-950/30 border-amber-800/80'
    }`}>
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-gray-800/80 pb-3">
        <div className="flex items-center space-x-2.5">
          <div className={`p-1.5 rounded ${isCritical ? 'bg-red-900/60 text-red-300' : 'bg-amber-900/60 text-amber-300'}`}>
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-gray-100 uppercase tracking-wider flex items-center gap-2">
              Payment Diversion & Financial Wire Fraud Forensics
            </h3>
            <p className="text-xs text-gray-400">
              High-risk financial manipulation patterns and banking artifacts intercepted in email text.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className={`px-2.5 py-1 text-xs font-mono font-bold rounded uppercase border ${
            isCritical
              ? 'bg-red-950/90 text-red-400 border-red-700/80'
              : 'bg-amber-950/90 text-amber-400 border-amber-700/80'
          }`}>
            Risk: {financial.risk_level.toUpperCase()} ({Math.round(financial.threat_score * 100)}%)
          </span>
        </div>
      </div>

      {/* Vendor Mismatch Warning Banner */}
      {financial.vendor_mismatch && (
        <div className="p-3 bg-red-950/60 border border-red-700/80 rounded-md flex items-start space-x-2.5 text-xs text-red-200">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <span className="font-bold text-red-100">Vendor Identity Impersonation Mismatch: </span>
            <span>{financial.vendor_mismatch}</span>
          </div>
        </div>
      )}

      {/* Financial Artifacts Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {/* IBANs / Bank Accounts */}
        {financial.bank_accounts.length > 0 && (
          <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-md space-y-2">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-300">
              <span className="flex items-center gap-1.5">
                <CreditCard className="w-3.5 h-3.5 text-indigo-400" /> Bank Accounts (IBAN)
              </span>
              <span className="text-[10px] font-mono text-gray-400">{financial.bank_accounts.length} found</span>
            </div>
            <div className="space-y-1.5">
              {financial.bank_accounts.map((iban, idx) => (
                <div key={idx} className="flex items-center justify-between p-1.5 bg-gray-950 rounded border border-gray-800/80 font-mono text-xs text-gray-200">
                  <span className="truncate" title={iban}>{iban}</span>
                  <button
                    onClick={() => handleCopy(iban)}
                    className="p-1 hover:text-indigo-400 text-gray-400 transition-colors"
                    title="Copy Account Number"
                  >
                    {copiedText === iban ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ABA Routing / SWIFT */}
        {(financial.routing_numbers.length > 0 || financial.swift_codes.length > 0) && (
          <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-md space-y-2">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-300">
              <span className="flex items-center gap-1.5">
                <Building2 className="w-3.5 h-3.5 text-purple-400" /> Wire Transit & SWIFT
              </span>
            </div>
            <div className="space-y-1.5 font-mono text-xs">
              {financial.routing_numbers.map((aba, idx) => (
                <div key={`aba-${idx}`} className="flex items-center justify-between p-1.5 bg-gray-950 rounded border border-gray-800/80 text-gray-200">
                  <span>ABA Routing: <strong className="text-indigo-300">{aba}</strong></span>
                  <button
                    onClick={() => handleCopy(aba)}
                    className="p-1 hover:text-indigo-400 text-gray-400 transition-colors"
                  >
                    {copiedText === aba ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              ))}
              {financial.swift_codes.map((swift, idx) => (
                <div key={`swift-${idx}`} className="flex items-center justify-between p-1.5 bg-gray-950 rounded border border-gray-800/80 text-gray-200">
                  <span>SWIFT/BIC: <strong className="text-purple-300">{swift}</strong></span>
                  <button
                    onClick={() => handleCopy(swift)}
                    className="p-1 hover:text-purple-400 text-gray-400 transition-colors"
                  >
                    {copiedText === swift ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Crypto Wallets */}
        {financial.crypto_wallets.length > 0 && (
          <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-md space-y-2">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-300">
              <span className="flex items-center gap-1.5">
                <Coins className="w-3.5 h-3.5 text-amber-400" /> Cryptocurrency Wallets
              </span>
              <span className="text-[10px] font-mono text-amber-400">{financial.crypto_wallets.length} wallet(s)</span>
            </div>
            <div className="space-y-1.5 font-mono text-xs">
              {financial.crypto_wallets.map((cw, idx) => (
                <div key={idx} className="flex items-center justify-between p-1.5 bg-gray-950 rounded border border-gray-800/80 text-gray-200">
                  <div className="truncate mr-2">
                    <span className="text-amber-400 text-[10px] block">{cw.type}</span>
                    <span className="truncate text-xs" title={cw.address}>{cw.address}</span>
                  </div>
                  <button
                    onClick={() => handleCopy(cw.address)}
                    className="p-1 hover:text-amber-400 text-gray-400 transition-colors"
                  >
                    {copiedText === cw.address ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Amounts & Invoices */}
        {(financial.amounts_mentioned.length > 0 || financial.invoice_numbers.length > 0) && (
          <div className="p-3 bg-gray-900/80 border border-gray-800 rounded-md space-y-2">
            <div className="flex items-center justify-between text-xs font-semibold text-gray-300">
              <span className="flex items-center gap-1.5">
                <DollarSign className="w-3.5 h-3.5 text-emerald-400" /> Financial Values & Invoices
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5 text-xs font-mono">
              {financial.amounts_mentioned.map((amt, idx) => (
                <span key={`amt-${idx}`} className="px-2 py-0.5 bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 rounded">
                  {amt}
                </span>
              ))}
              {financial.invoice_numbers.map((inv, idx) => (
                <span key={`inv-${idx}`} className="px-2 py-0.5 bg-gray-800 text-gray-300 border border-gray-700 rounded">
                  Ref: {inv}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Redirection / Diversion Indicators */}
      {financial.diversion_indicators.length > 0 && (
        <div className="p-3 bg-gray-950/60 border border-gray-800/80 rounded-md space-y-1.5 text-xs">
          <span className="font-semibold text-gray-300 flex items-center gap-1.5">
            <FileCheck className="w-3.5 h-3.5 text-amber-400" /> BEC Diversion Indicators Triggered:
          </span>
          <div className="flex flex-wrap gap-2 pt-1">
            {financial.diversion_indicators.map((ind, idx) => (
              <span
                key={idx}
                className="px-2 py-0.5 bg-amber-950/70 text-amber-300 border border-amber-800/60 rounded text-[11px] font-mono"
              >
                {ind}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
