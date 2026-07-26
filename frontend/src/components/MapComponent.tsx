import React, { useEffect } from 'react';
import { CircleMarker, MapContainer, Popup, TileLayer, Tooltip, useMap } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import type { GeoLocation } from '../types';
import { formatCount } from '../format';

interface Props {
    locations: GeoLocation[];
}

const MIN_RADIUS = 6;
const MAX_RADIUS = 20;

/**
 * Marker radius scaled by packet count. The radius follows the square root of
 * the count, so marker *area* stays proportional to traffic and one very busy
 * destination does not swallow the map.
 */
function radiusFor(count: number, max: number): number {
    if (max <= 0) return MIN_RADIUS;
    const scale = Math.sqrt(count) / Math.sqrt(max);
    return MIN_RADIUS + scale * (MAX_RADIUS - MIN_RADIUS);
}

/**
 * Frames the map on the destinations instead of leaving the visitor at a
 * default world view they have to pan themselves.
 */
const FitToMarkers: React.FC<{ locations: GeoLocation[] }> = ({ locations }) => {
    const map = useMap();
    useEffect(() => {
        if (locations.length === 0) return;
        const bounds = L.latLngBounds(locations.map((l) => [l.latitude, l.longitude] as [number, number]));
        map.fitBounds(bounds, { padding: [40, 40], maxZoom: 6 });
    }, [locations, map]);
    return null;
};

export const MapComponent: React.FC<Props> = ({ locations }) => {
    if (locations.length === 0) {
        return (
            <div className="h-full min-h-64 grid place-items-center bg-slate-50 p-6 text-center">
                <p className="text-sm text-slate-500 max-w-xs">
                    No destinations to map. None of the addresses this host talked to resolved to a public location.
                </p>
            </div>
        );
    }

    const maxCount = Math.max(...locations.map((l) => l.count));

    return (
        <MapContainer
            center={[20, 0]}
            zoom={2}
            minZoom={2}
            scrollWheelZoom={false}
            worldCopyJump
            style={{ height: '100%', width: '100%' }}
            className="z-0"
        >
            <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            <FitToMarkers locations={locations} />
            {locations.map((loc) => (
                <CircleMarker
                    key={loc.ip}
                    center={[loc.latitude, loc.longitude]}
                    radius={radiusFor(loc.count, maxCount)}
                    pathOptions={{ color: '#4338ca', weight: 1.5, fillColor: '#6366f1', fillOpacity: 0.55 }}
                >
                    <Tooltip direction="top" offset={[0, -4]}>
                        {loc.city !== 'Unknown' ? `${loc.city}, ` : ''}
                        {loc.country} · {formatCount(loc.count)} packets
                    </Tooltip>
                    <Popup>
                        <strong>
                            {loc.city !== 'Unknown' ? `${loc.city}, ` : ''}
                            {loc.country}
                        </strong>
                        <br />
                        <span style={{ fontFamily: 'ui-monospace, monospace' }}>{loc.ip}</span>
                        <br />
                        {loc.count.toLocaleString()} packets sent here
                    </Popup>
                </CircleMarker>
            ))}
        </MapContainer>
    );
};
