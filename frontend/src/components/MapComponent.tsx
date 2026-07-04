import React from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';
import L from 'leaflet';
import type { GeoLocation } from '../types';

// Fix Leaflet icons
import icon from 'leaflet/dist/images/marker-icon.png';
import iconShadow from 'leaflet/dist/images/marker-shadow.png';

const DefaultIcon = L.icon({
    iconUrl: icon,
    shadowUrl: iconShadow,
    iconSize: [25, 41],
    iconAnchor: [12, 41]
});

L.Marker.prototype.options.icon = DefaultIcon;

interface Props {
    locations: GeoLocation[];
}

export const MapComponent: React.FC<Props> = ({ locations }) => {
    if (locations.length === 0) return <div className="p-4 text-center text-slate-500 h-full min-h-64 flex items-center justify-center bg-slate-50 rounded-lg">No geographic data available — no public destination IPs were resolved.</div>;

    return (
        <MapContainer center={[20, 0]} zoom={2} scrollWheelZoom={false} style={{ height: '100%', width: '100%' }} className="rounded-lg z-0">
            <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
            />
            {locations.map((loc, idx) => (
                <Marker key={idx} position={[loc.latitude, loc.longitude]}>
                    <Popup>
                        <strong>{loc.city}, {loc.country}</strong><br />
                        IP: {loc.ip}<br />
                        Packets: {loc.count}
                    </Popup>
                </Marker>
            ))}
        </MapContainer>
    );
};
