import React from 'react';
import { Severity } from '@/lib/types';

interface Props {
  severity: Severity;
}

export default function SeverityBadge({ severity }: Props) {
  const colors = {
    [Severity.INFO]: 'bg-blue-900 text-blue-300 border-blue-700',
    [Severity.LOW]: 'bg-cyan-900 text-cyan-300 border-cyan-700',
    [Severity.MEDIUM]: 'bg-yellow-900 text-yellow-300 border-yellow-700',
    [Severity.HIGH]: 'bg-orange-900 text-orange-300 border-orange-700',
    [Severity.CRITICAL]: 'bg-red-900 text-red-300 border-red-700',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium uppercase border rounded ${colors[severity]}`}>
      {severity}
    </span>
  );
}
