'use client';

import React, { useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline } from 'react-leaflet';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { RouteAnalysisResponse } from '@/lib/types';
import { Globe, MapPin } from 'lucide-react';

interface Props {
  route: RouteAnalysisResponse | null;
}

export default function RouteMapInner({ route }: Props) {
  const hopsWithCoords = (route?.hops || []).filter(
    (h) => h.geoip?.latitude != null && h.geoip?.longitude != null
  );

  if (hopsWithCoords.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-[420px] bg-gray-950/60 border border-gray-800 rounded-lg text-gray-500">
        <Globe className="w-10 h-10 mb-3 opacity-40 animate-pulse" />
        <p className="text-sm font-medium text-gray-400">No public MTA hops with GeoIP coordinates found</p>
        <p className="text-xs text-gray-600 mt-1 max-w-sm text-center">
          Private IP ranges (RFC 1918) and unresolved hostnames cannot be mapped geographically.
        </p>
      </div>
    );
  }

  const positions: [number, number][] = hopsWithCoords.map((h) => [
    h.geoip!.latitude!,
    h.geoip!.longitude!,
  ]);

  const center: [number, number] = positions[0] || [20, 0];

  const createCustomIcon = (hopNum: number, isOrigin: boolean, isFinal: boolean) => {
    const bgColor = isOrigin ? '#f59e0b' : isFinal ? '#10b981' : '#6366f1';
    return L.divIcon({
      className: 'custom-mta-marker',
      html: `<div style="
        background-color: ${bgColor};
        color: black;
        border: 2px solid white;
        border-radius: 50%;
        width: 24px;
        height: 24px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: monospace;
        font-size: 11px;
        font-weight: bold;
        box-shadow: 0 0 10px rgba(0,0,0,0.5);
      ">${hopNum}</div>`,
      iconSize: [24, 24],
      iconAnchor: [12, 12],
    });
  };

  return (
    <div className="h-[460px] w-full rounded-lg overflow-hidden border border-gray-800 relative z-0">
      <MapContainer
        center={center}
        zoom={2}
        scrollWheelZoom={false}
        style={{ height: '100%', width: '100%', backgroundColor: '#090d16' }}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> &copy; <a href="https://carto.com/">CARTO</a>'
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          maxZoom={19}
        />

        {/* Flight-path Polyline */}
        <Polyline
          positions={positions}
          pathOptions={{
            color: '#818cf8',
            weight: 3,
            dashArray: '6, 8',
            opacity: 0.8,
          }}
        />

        {/* Hop Markers */}
        {hopsWithCoords.map((hop, idx) => {
          const isOrigin = idx === 0;
          const isFinal = idx === hopsWithCoords.length - 1;
          const lat = hop.geoip!.latitude!;
          const lon = hop.geoip!.longitude!;

          return (
            <Marker
              key={idx}
              position={[lat, lon]}
              icon={createCustomIcon(hop.hop, isOrigin, isFinal)}
            >
              <Popup className="custom-leaflet-popup">
                <div className="p-2 text-xs text-gray-900 font-sans space-y-1">
                  <div className="font-bold text-sm text-indigo-700 flex items-center space-x-1">
                    <MapPin className="w-3.5 h-3.5" />
                    <span>MTA Relay Hop {hop.hop}</span>
                  </div>
                  <div className="font-mono text-gray-700">IP: {hop.ip}</div>
                  <div>Location: {hop.geoip?.city ? `${hop.geoip.city}, ` : ''}{hop.geoip?.country}</div>
                  {hop.geoip?.asn && <div className="text-gray-600">ASN: {hop.geoip.asn} {hop.geoip.org ? `(${hop.geoip.org})` : ''}</div>}
                  {hop.delay_display && <div className="font-semibold text-gray-800">Delay: {hop.delay_display}</div>}
                </div>
              </Popup>
            </Marker>
          );
        })}
      </MapContainer>
    </div>
  );
}
