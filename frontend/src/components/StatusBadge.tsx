import React from 'react';
import { CaseStatus } from '@/lib/types';

interface Props {
  status: CaseStatus;
}

export default function StatusBadge({ status }: Props) {
  const colors = {
    [CaseStatus.PENDING]: 'bg-yellow-900 text-yellow-300 border-yellow-700',
    [CaseStatus.PROCESSING]: 'bg-blue-900 text-blue-300 border-blue-700',
    [CaseStatus.COMPLETED]: 'bg-green-900 text-green-300 border-green-700',
    [CaseStatus.FAILED]: 'bg-red-900 text-red-300 border-red-700',
  };

  return (
    <span className={`px-2 py-1 text-xs font-medium uppercase border rounded ${colors[status]}`}>
      {status}
    </span>
  );
}
