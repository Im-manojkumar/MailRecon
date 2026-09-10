'use client';

import React, { useState, useRef, useEffect } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import cytoscape from 'cytoscape';
import { IndicatorGraphResponse, GraphNode, GraphEdge } from '@/lib/types';
import { Network, ZoomIn, ZoomOut, Maximize2, RotateCcw, Info, ShieldAlert, Layers } from 'lucide-react';

interface Props {
  graph: IndicatorGraphResponse | null;
}

export default function IndicatorGraphInner({ graph }: Props) {
  const [selectedNode, setSelectedNode] = useState<any | null>(null);
  const [layoutName, setLayoutName] = useState<string>('cose');
  const cyRef = useRef<cytoscape.Core | null>(null);

  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  if (nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[520px] bg-gray-950/60 border border-gray-800 rounded-lg text-gray-500">
        <Network className="w-10 h-10 mb-3 opacity-40 animate-pulse" />
        <p className="text-sm font-medium text-gray-400">No indicator graph nodes generated</p>
        <p className="text-xs text-gray-600 mt-1">
          Graph nodes are mapped dynamically from email identities, transport relays, URLs, and attachments.
        </p>
      </div>
    );
  }

  // Format elements for Cytoscape
  const elements = [
    ...nodes.map((n) => ({
      data: {
        id: n.id,
        label: n.label || n.value,
        kind: n.kind,
        value: n.value,
        risk_level: n.risk_level || 'neutral',
        ...(n.metadata || {}),
      },
    })),
    ...edges.map((e) => ({
      data: {
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label || e.relationship,
        relationship: e.relationship,
      },
    })),
  ];

  const stylesheet: any[] = [
    {
      selector: 'node',
      style: {
        'label': 'data(label)',
        'font-family': 'monospace',
        'font-size': '10px',
        'color': '#e2e8f0',
        'text-valign': 'bottom',
        'text-halign': 'center',
        'text-margin-y': 4,
        'text-outline-width': 2,
        'text-outline-color': '#090d16',
        'background-color': '#3b82f6',
        'border-width': 2,
        'border-color': '#1e40af',
        'width': 40,
        'height': 40,
      },
    },
    {
      selector: 'node[kind = "case"]',
      style: {
        'shape': 'diamond',
        'background-color': '#8b5cf6',
        'border-color': '#6d28d9',
        'width': 50,
        'height': 50,
      },
    },
    {
      selector: 'node[kind = "email"]',
      style: {
        'shape': 'ellipse',
      },
    },
    {
      selector: 'node[kind = "domain"]',
      style: {
        'shape': 'round-rectangle',
        'width': 50,
      },
    },
    {
      selector: 'node[kind = "ip"]',
      style: {
        'shape': 'triangle',
      },
    },
    {
      selector: 'node[kind = "url"]',
      style: {
        'shape': 'rectangle',
      },
    },
    {
      selector: 'node[kind = "hash"]',
      style: {
        'shape': 'hexagon',
      },
    },
    {
      selector: 'node[kind = "qr_url"]',
      style: {
        'shape': 'octagon',
        'background-color': '#d946ef',
        'border-color': '#a21caf',
      },
    },
    {
      selector: 'node[risk_level = "malicious"]',
      style: {
        'background-color': '#ef4444',
        'border-color': '#b91c1c',
        'border-width': 3,
      },
    },
    {
      selector: 'node[risk_level = "suspicious"]',
      style: {
        'background-color': '#f59e0b',
        'border-color': '#b45309',
        'border-width': 2.5,
      },
    },
    {
      selector: ':selected',
      style: {
        'border-width': 4,
        'border-color': '#38bdf8',
        'line-color': '#38bdf8',
        'target-arrow-color': '#38bdf8',
      },
    },
    {
      selector: 'edge',
      style: {
        'width': 1.5,
        'line-color': '#475569',
        'target-arrow-color': '#64748b',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-family': 'monospace',
        'font-size': '8px',
        'color': '#94a3b8',
        'text-rotation': 'autorotate',
        'text-background-color': '#090d16',
        'text-background-opacity': 0.8,
        'text-background-padding': '2px',
      },
    },
  ];

  const handleCyInit = (cy: cytoscape.Core) => {
    cyRef.current = cy;
    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      setSelectedNode(node.data());
    });
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });
  };

  const handleFit = () => {
    if (cyRef.current) {
      cyRef.current.fit(undefined, 30);
    }
  };

  const handleZoomIn = () => {
    if (cyRef.current) {
      cyRef.current.zoom(cyRef.current.zoom() * 1.25);
    }
  };

  const handleZoomOut = () => {
    if (cyRef.current) {
      cyRef.current.zoom(cyRef.current.zoom() * 0.8);
    }
  };

  return (
    <div className="space-y-4">
      {/* Control Toolbar */}
      <div className="flex flex-wrap items-center justify-between p-3 bg-gray-900/80 border border-gray-800 rounded-lg gap-3 text-xs">
        <div className="flex items-center space-x-2">
          <Layers className="w-4 h-4 text-indigo-400" />
          <span className="font-semibold text-gray-300">Layout Algorithm:</span>
          {['cose', 'concentric', 'breadthfirst', 'circle'].map((l) => (
            <button
              key={l}
              onClick={() => setLayoutName(l)}
              className={`px-2.5 py-1 rounded capitalize font-mono transition-colors ${
                layoutName === l
                  ? 'bg-primary-600 text-white'
                  : 'bg-gray-800 text-gray-400 hover:text-gray-200'
              }`}
            >
              {l}
            </button>
          ))}
        </div>

        <div className="flex items-center space-x-1">
          <button
            onClick={handleZoomIn}
            className="p-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded"
            title="Zoom In"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            onClick={handleZoomOut}
            className="p-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded"
            title="Zoom Out"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <button
            onClick={handleFit}
            className="p-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 rounded"
            title="Fit to Screen"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Canvas & Inspector Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
        <div className="lg:col-span-3 h-[520px] bg-[#090d16] border border-gray-800 rounded-lg overflow-hidden relative">
          <CytoscapeComponent
            elements={elements}
            stylesheet={stylesheet}
            style={{ width: '100%', height: '100%' }}
            layout={{ name: layoutName, animate: true, padding: 30 }}
            cy={handleCyInit}
          />
        </div>

        {/* Node Inspector Drawer */}
        <div className="p-4 bg-gray-900/90 border border-gray-800 rounded-lg space-y-4">
          <div className="flex items-center space-x-2 text-xs font-bold text-gray-300 uppercase tracking-wider border-b border-gray-800 pb-2">
            <Info className="w-4 h-4 text-indigo-400" />
            <span>Indicator Inspector</span>
          </div>

          {selectedNode ? (
            <div className="space-y-3 text-xs">
              <div>
                <span className="text-gray-500 block mb-0.5">Entity Value:</span>
                <span className="font-mono text-gray-200 break-all font-semibold bg-gray-950 p-2 rounded block border border-gray-800">
                  {selectedNode.value}
                </span>
              </div>

              <div>
                <span className="text-gray-500 block mb-0.5">Kind:</span>
                <span className="px-2 py-0.5 bg-gray-800 text-indigo-300 font-mono uppercase rounded text-[11px]">
                  {selectedNode.kind}
                </span>
              </div>

              <div>
                <span className="text-gray-500 block mb-0.5">Risk Rating:</span>
                <span
                  className={`px-2 py-0.5 rounded uppercase font-bold text-[11px] ${
                    selectedNode.risk_level === 'malicious'
                      ? 'bg-red-950 text-red-300 border border-red-800'
                      : selectedNode.risk_level === 'suspicious'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-blue-950 text-blue-300 border border-blue-800'
                  }`}
                >
                  {selectedNode.risk_level}
                </span>
              </div>

              <div>
                <span className="text-gray-500 block mb-0.5">Node ID:</span>
                <span className="font-mono text-gray-400 text-[10px] break-all">
                  {selectedNode.id}
                </span>
              </div>
            </div>
          ) : (
            <div className="text-gray-500 text-xs py-8 text-center space-y-2">
              <ShieldAlert className="w-6 h-6 mx-auto opacity-30" />
              <p>Click on any graph node to inspect its forensic properties and threat context.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
