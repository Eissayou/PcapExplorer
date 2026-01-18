import React, { useMemo } from 'react';
import type { AnalyzeResponse } from '../types';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar } from 'recharts';
import { MapComponent } from './MapComponent';

interface Props {
    data: AnalyzeResponse;
}

const StatCard = ({ title, value, icon, color }: { title: string, value: string | number, icon: React.ReactNode, color: string }) => (
    <div className="bg-white overflow-hidden shadow rounded-lg border-l-4" style={{ borderColor: color }}>
        <div className="p-5">
            <div className="flex items-center">
                <div className="flex-shrink-0">
                    {icon}
                </div>
                <div className="ml-5 w-0 flex-1">
                    <dl>
                        <dt className="text-sm font-medium text-gray-500 truncate">{title}</dt>
                        <dd>
                            <div className="text-lg font-bold text-gray-900">{value}</div>
                        </dd>
                    </dl>
                </div>
            </div>
        </div>
    </div>
);

export const Dashboard: React.FC<Props> = ({ data }) => {
    const { graphObjects, locations, mapError } = data;

    // Transform data for charts
    const sentTimeData = useMemo(() => Object.entries(graphObjects.sentTime)
        .map(([time, count]) => ({ time: parseInt(time), count }))
        .sort((a, b) => a.time - b.time), [graphObjects.sentTime]);

    const receivedTimeData = useMemo(() => Object.entries(graphObjects.receivedTime)
        .map(([time, count]) => ({ time: parseInt(time), count }))
        .sort((a, b) => a.time - b.time), [graphObjects.receivedTime]);

    // Top IPs
    const sentIPData = useMemo(() => Object.entries(graphObjects.sentIP)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10), [graphObjects.sentIP]);

    const receivedIPData = useMemo(() => Object.entries(graphObjects.receivedIP)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10), [graphObjects.receivedIP]);

    const sentSizeData = useMemo(() => Object.entries(graphObjects.sentSize)
        .map(([time, size]) => ({ time: parseInt(time), size }))
        .sort((a, b) => a.time - b.time), [graphObjects.sentSize]);

    // Calculate Stats
    const totalSent = useMemo(() => Object.values(graphObjects.sentTime).reduce((a, b) => a + b, 0), [graphObjects.sentTime]);
    const totalReceived = useMemo(() => Object.values(graphObjects.receivedTime).reduce((a, b) => a + b, 0), [graphObjects.receivedTime]);
    const totalBytes = useMemo(() => Object.values(graphObjects.sentSize).reduce((a, b) => a + b, 0), [graphObjects.sentSize]);
    const topDestIP = sentIPData.length > 0 ? sentIPData[0].ip : "N/A";

    const formatBytes = (bytes: number) => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    return (
        <div className="space-y-8 max-w-7xl mx-auto pb-12">

            {/* Stats Summary */}
            <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
                <StatCard
                    title="Total Packets Sent"
                    value={totalSent.toLocaleString()}
                    color="#8884d8"
                    icon={<svg className="h-6 w-6 text-indigo-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" /></svg>}
                />
                <StatCard
                    title="Total Packets Received"
                    value={totalReceived.toLocaleString()}
                    color="#82ca9d"
                    icon={<svg className="h-6 w-6 text-green-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 14l-7 7m0 0l-7-7m7 7V3" /></svg>}
                />
                <StatCard
                    title="Total Data Transfer"
                    value={formatBytes(totalBytes)}
                    color="#ff7300"
                    icon={<svg className="h-6 w-6 text-orange-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4" /></svg>}
                />
                 <StatCard
                    title="Top Destination"
                    value={topDestIP}
                    color="#3b82f6"
                    icon={<svg className="h-6 w-6 text-blue-600" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z" /><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 11a3 3 0 11-6 0 3 3 0 016 0z" /></svg>}
                />
            </div>

            {/* Map Section */}
            <div className="bg-white rounded-xl shadow-md overflow-hidden border border-gray-100">
                <div className="p-6 border-b border-gray-100 bg-gray-50">
                     <h3 className="text-lg leading-6 font-medium text-gray-900">Geographic Distribution</h3>
                     <p className="mt-1 text-sm text-gray-500">Locations of IPs that traffic was sent to.</p>
                </div>
                <div className="p-6">
                    {mapError && <div className="bg-yellow-50 text-yellow-800 p-4 mb-4 rounded-md border border-yellow-200 text-sm flex items-start"><svg className="h-5 w-5 text-yellow-400 mr-2" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" /></svg>{mapError}</div>}
                    <div className="border rounded-lg overflow-hidden h-96 shadow-inner">
                        <MapComponent locations={locations} />
                    </div>
                </div>
            </div>

            {/* Charts Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                {/* Sent Packets Over Time */}
                <div className="bg-white p-6 rounded-xl shadow-md border border-gray-100">
                    <h3 className="text-lg font-bold mb-6 text-gray-800 border-b pb-2">Sent Packets Over Time</h3>
                    <div className="h-72">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={sentTimeData}>
                                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5e7eb" />
                                <XAxis dataKey="time" label={{ value: 'Seconds', position: 'insideBottom', offset: -5 }} tick={{fill: '#6b7280'}} axisLine={{stroke: '#9ca3af'}} />
                                <YAxis tick={{fill: '#6b7280'}} axisLine={{stroke: '#9ca3af'}} />
                                <Tooltip contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'}} />
                                <Legend wrapperStyle={{paddingTop: '10px'}} />
                                <Line type="monotone" dataKey="count" stroke="#8884d8" name="Packets" dot={false} strokeWidth={3} activeDot={{r: 6}} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Received Packets Over Time */}
                <div className="bg-white p-6 rounded-xl shadow-md border border-gray-100">
                    <h3 className="text-lg font-bold mb-6 text-gray-800 border-b pb-2">Received Packets Over Time</h3>
                    <div className="h-72">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={receivedTimeData}>
                                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5e7eb" />
                                <XAxis dataKey="time" label={{ value: 'Seconds', position: 'insideBottom', offset: -5 }} tick={{fill: '#6b7280'}} axisLine={{stroke: '#9ca3af'}} />
                                <YAxis tick={{fill: '#6b7280'}} axisLine={{stroke: '#9ca3af'}} />
                                <Tooltip contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'}} />
                                <Legend wrapperStyle={{paddingTop: '10px'}} />
                                <Line type="monotone" dataKey="count" stroke="#82ca9d" name="Packets" dot={false} strokeWidth={3} activeDot={{r: 6}} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Top Sent IPs */}
                <div className="bg-white p-6 rounded-xl shadow-md border border-gray-100">
                    <h3 className="text-lg font-bold mb-6 text-gray-800 border-b pb-2">Top Destination IPs</h3>
                    <div className="h-72">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={sentIPData} layout="vertical" margin={{ left: 20 }}>
                                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#e5e7eb" />
                                <XAxis type="number" tick={{fill: '#6b7280'}} axisLine={{stroke: '#9ca3af'}} />
                                <YAxis dataKey="ip" type="category" width={110} tick={{fontSize: 12, fill: '#374151'}} axisLine={{stroke: '#9ca3af'}} />
                                <Tooltip cursor={{fill: 'transparent'}} contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'}} />
                                <Legend wrapperStyle={{paddingTop: '10px'}} />
                                <Bar dataKey="count" fill="#8884d8" name="Packets" radius={[0, 4, 4, 0]} barSize={20} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                {/* Top Received IPs */}
                <div className="bg-white p-6 rounded-xl shadow-md border border-gray-100">
                    <h3 className="text-lg font-bold mb-6 text-gray-800 border-b pb-2">Top Source IPs</h3>
                    <div className="h-72">
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={receivedIPData} layout="vertical" margin={{ left: 20 }}>
                                <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke="#e5e7eb" />
                                <XAxis type="number" tick={{fill: '#6b7280'}} axisLine={{stroke: '#9ca3af'}} />
                                <YAxis dataKey="ip" type="category" width={110} tick={{fontSize: 12, fill: '#374151'}} axisLine={{stroke: '#9ca3af'}} />
                                <Tooltip cursor={{fill: 'transparent'}} contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'}} />
                                <Legend wrapperStyle={{paddingTop: '10px'}} />
                                <Bar dataKey="count" fill="#82ca9d" name="Packets" radius={[0, 4, 4, 0]} barSize={20} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                 {/* Sent Size Over Time */}
                 <div className="bg-white p-6 rounded-xl shadow-md lg:col-span-2 border border-gray-100">
                    <h3 className="text-lg font-bold mb-6 text-gray-800 border-b pb-2">Data Transfer Size Over Time (Sent)</h3>
                    <div className="h-72">
                        <ResponsiveContainer width="100%" height="100%">
                            <LineChart data={sentSizeData}>
                                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#e5e7eb" />
                                <XAxis dataKey="time" label={{ value: 'Seconds', position: 'insideBottom', offset: -5 }} tick={{fill: '#6b7280'}} axisLine={{stroke: '#9ca3af'}} />
                                <YAxis tick={{fill: '#6b7280'}} axisLine={{stroke: '#9ca3af'}} />
                                <Tooltip contentStyle={{borderRadius: '8px', border: 'none', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)'}} />
                                <Legend wrapperStyle={{paddingTop: '10px'}} />
                                <Line type="monotone" dataKey="size" stroke="#ff7300" name="Bytes" dot={false} strokeWidth={3} activeDot={{r: 6}} />
                            </LineChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>
        </div>
    );
};
