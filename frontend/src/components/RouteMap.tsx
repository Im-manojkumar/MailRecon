'use client';

import React from 'react';
import dynamic from 'next/dynamic';
import { RouteAnalysisResponse } from '@/lib/types';
import { Globe } from 'lucide-react';

const DynamicRouteMapInner = dynamic(() => import('./RouteMapInner'), {
  ssr: false,
  loading: () => (
    <div className="flex flex-col items-center justify-center h-[460px] bg-gray-950/60 border border-gray-800 rounded-lg text-gray-500">
      <Globe className="w-8 h-8 mb-2 animate-spin text-indigo-500 opacity-60" />
      <span className="text-xs font-mono">Initializing Geographical Transport Map...</span>
    </div>
  ),
});

interface Props {
  route: RouteAnalysisResponse | null;
}

export default function RouteMap({ route }: Props) {
  return <DynamicRouteMapInner route={route} />;
}
