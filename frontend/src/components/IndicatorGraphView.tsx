'use client';

import React from 'react';
import dynamic from 'next/dynamic';
import { IndicatorGraphResponse } from '@/lib/types';
import { Network } from 'lucide-react';

const DynamicIndicatorGraphInner = dynamic(() => import('./IndicatorGraphInner'), {
  ssr: false,
  loading: () => (
    <div className="flex flex-col items-center justify-center h-[520px] bg-gray-950/60 border border-gray-800 rounded-lg text-gray-500">
      <Network className="w-8 h-8 mb-2 animate-spin text-indigo-500 opacity-60" />
      <span className="text-xs font-mono">Initializing Cytoscape.js Threat Network...</span>
    </div>
  ),
});

interface Props {
  graph: IndicatorGraphResponse | null;
}

export default function IndicatorGraphView({ graph }: Props) {
  return <DynamicIndicatorGraphInner graph={graph} />;
}
