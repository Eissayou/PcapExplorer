import React, { useMemo } from 'react';
import type { AnalyzeResponse } from '../types';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { MapComponent } from './MapComponent';
import { formatBytes, formatCount, formatElapsed, isPrivateIp } from '../format';
import { ArrowDownIcon, ArrowUpIcon, DatabaseIcon, InboxIcon, NetworkIcon, PeersIcon } from './Icons';

interface Props {
    data: AnalyzeResponse;
    /** Re-runs the analysis against another host in the same capture. */
    onChangeHost: (ip: string) => void;
    /** Name of the capture being shown, for context in the header. */
    fileName?: string;
}

const SENT = '#4f46e5'; // indigo-600
const RECEIVED = '#059669'; // emerald-600
const SENT_BYTES = '#f59e0b'; // amber-500
const RECEIVED_BYTES = '#0ea5e9'; // sky-500

/** How many points a timeline chart draws before it starts bucketing. */
const MAX_TIMELINE_POINTS = 600;

const AXIS = { fill: '#64748b', fontSize: 12 } as const;
const GRID = '#e2e8f0';

const tooltipStyle = {
    borderRadius: '10px',
    border: '1px solid #e2e8f0',
    boxShadow: '0 8px 20px -6px rgb(15 23 42 / 0.18)',
    fontSize: '13px',
} as const;

type TimePoint = { t: number; sent: number; received: number };

/**
 * Turns two sparse {second: value} maps into one dense, evenly spaced series.
 *
 * Seconds with no traffic are missing from the API response but they still mean
 * something on a chart, so they get filled in as zeros rather than skipped.
 * Long captures are bucketed to keep the point count, and the SVG, bounded.
 */
function buildTimeline(sent: Record<string, number>, received: Record<string, number>): TimePoint[] {
    const seconds = [...Object.keys(sent), ...Object.keys(received)].map(Number).filter(Number.isFinite);
    if (seconds.length === 0) return [];

    const last = Math.max(...seconds);
    const bucketSize = Math.max(1, Math.ceil((last + 1) / MAX_TIMELINE_POINTS));
    const points: TimePoint[] = Array.from({ length: Math.floor(last / bucketSize) + 1 }, (_, i) => ({
        t: i * bucketSize,
        sent: 0,
        received: 0,
    }));

    const fill = (source: Record<string, number>, key: 'sent' | 'received') => {
        for (const [second, value] of Object.entries(source)) {
            const point = points[Math.floor(Number(second) / bucketSize)];
            if (point) point[key] += value;
        }
    };
    fill(sent, 'sent');
    fill(received, 'received');
    return points;
}

/** Top-N entries of an {ip: count} map, ordered by count. */
function topEntries(counts: Record<string, number>, limit: number) {
    return Object.entries(counts)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, limit);
}

const sum = (m: Record<string, number>) => Object.values(m).reduce((a, b) => a + b, 0);

const StatCard = ({ title, value, sub, icon, color }: { title: string; value: string; sub?: string; icon: React.ReactNode; color: string }) => (
    <div className="bg-white shadow-sm hover:shadow-md transition-shadow rounded-xl border border-slate-200/80">
        <div className="p-4 sm:p-5 flex items-center gap-4">
            <div className="grid place-items-center h-11 w-11 rounded-xl shrink-0" style={{ backgroundColor: `${color}1a`, color }}>
                {icon}
            </div>
            <div className="min-w-0">
                <dt className="text-xs font-medium text-slate-500 uppercase tracking-wide truncate">{title}</dt>
                <dd className="text-xl font-bold text-slate-900 truncate">{value}</dd>
                {sub && <p className="text-xs text-slate-400 truncate">{sub}</p>}
            </div>
        </div>
    </div>
);

const ChartCard = ({ title, description, children }: { title: string; description: string; children: React.ReactNode }) => (
    <div className="bg-white p-5 sm:p-6 rounded-xl shadow-sm border border-slate-200/80">
        <h3 className="text-base font-bold text-slate-800">{title}</h3>
        <p className="mt-0.5 mb-4 text-sm text-slate-500">{description}</p>
        <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">{children}</ResponsiveContainer>
        </div>
    </div>
);

/**
 * Sent and received plotted against elapsed time. Both timelines on this page
 * are the same chart with a different unit, so they share one component.
 */
const TimelineChart = ({
    title,
    description,
    data,
    colors,
    format,
    unit,
}: {
    title: string;
    description: string;
    data: TimePoint[];
    colors: [string, string];
    format: (n: number) => string;
    unit: string;
}) => (
    <ChartCard title={title} description={description}>
        <AreaChart data={data} margin={{ top: 5, right: 8, bottom: 18, left: 0 }}>
            <defs>
                {colors.map((color, i) => (
                    <linearGradient key={color} id={`fill-${title.replace(/\W/g, '')}-${i}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={color} stopOpacity={0.35} />
                        <stop offset="100%" stopColor={color} stopOpacity={0.02} />
                    </linearGradient>
                ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" vertical={false} stroke={GRID} />
            <XAxis
                dataKey="t"
                type="number"
                domain={['dataMin', 'dataMax']}
                tickFormatter={formatElapsed}
                tick={AXIS}
                stroke="#cbd5e1"
                label={{ value: 'Time since first packet', position: 'insideBottom', offset: -12, fill: '#94a3b8', fontSize: 12 }}
            />
            <YAxis tickFormatter={format} tick={AXIS} stroke="#cbd5e1" width={unit === 'packets' ? 48 : 64} />
            <Tooltip
                contentStyle={tooltipStyle}
                labelFormatter={(t) => `At ${formatElapsed(Number(t))}`}
                formatter={(v, name) => [`${format(Number(v ?? 0))}${unit === 'packets' ? ' packets' : ''}`, name]}
            />
            <Legend wrapperStyle={{ paddingTop: 8 }} />
            {(['sent', 'received'] as const).map((key, i) => (
                <Area
                    key={key}
                    type="monotone"
                    dataKey={key}
                    name={key === 'sent' ? 'Sent' : 'Received'}
                    stroke={colors[i]}
                    strokeWidth={2}
                    fill={`url(#fill-${title.replace(/\W/g, '')}-${i})`}
                />
            ))}
        </AreaChart>
    </ChartCard>
);

/** Ranked peers in one direction. Both "top talkers" charts share this. */
const PeersChart = ({
    title,
    description,
    data,
    color,
    direction,
}: {
    title: string;
    description: string;
    data: { ip: string; count: number }[];
    color: string;
    direction: 'Sent' | 'Received';
}) => (
    <ChartCard title={title} description={description}>
        <BarChart data={data} layout="vertical" margin={{ left: 4, right: 16 }}>
            <CartesianGrid strokeDasharray="3 3" horizontal={false} stroke={GRID} />
            <XAxis type="number" tickFormatter={formatCount} tick={AXIS} stroke="#cbd5e1" />
            <YAxis dataKey="ip" type="category" width={128} tick={{ fontSize: 11, fill: '#475569' }} stroke="#cbd5e1" />
            <Tooltip
                cursor={{ fill: '#f1f5f9' }}
                contentStyle={tooltipStyle}
                formatter={(v) => [`${Number(v ?? 0).toLocaleString()} packets`, direction]}
            />
            <Bar dataKey="count" name={`Packets ${direction.toLowerCase()}`} fill={color} radius={[0, 4, 4, 0]} barSize={16} />
        </BarChart>
    </ChartCard>
);

export const Dashboard: React.FC<Props> = ({ data, onChangeHost, fileName }) => {
    const { graphObjects, locations, mapError, targetIp, autoDetected, hosts } = data;

    const packetTimeline = useMemo(
        () => buildTimeline(graphObjects.sentTime, graphObjects.receivedTime),
        [graphObjects.sentTime, graphObjects.receivedTime],
    );
    const byteTimeline = useMemo(
        () => buildTimeline(graphObjects.sentSize, graphObjects.receivedSize),
        [graphObjects.sentSize, graphObjects.receivedSize],
    );

    const sentIPData = useMemo(() => topEntries(graphObjects.sentIP, 10), [graphObjects.sentIP]);
    const receivedIPData = useMemo(() => topEntries(graphObjects.receivedIP, 10), [graphObjects.receivedIP]);

    const totals = useMemo(
        () => ({
            sent: sum(graphObjects.sentTime),
            received: sum(graphObjects.receivedTime),
            bytesSent: sum(graphObjects.sentSize),
            bytesReceived: sum(graphObjects.receivedSize),
        }),
        [graphObjects],
    );

    const peers = useMemo(() => {
        const all = [...Object.keys(graphObjects.sentIP), ...Object.keys(graphObjects.receivedIP)];
        const unique = [...new Set(all)];
        return { total: unique.length, private: unique.filter(isPrivateIp).length };
    }, [graphObjects.sentIP, graphObjects.receivedIP]);

    const countryCount = useMemo(() => new Set(locations.map((l) => l.country)).size, [locations]);

    const hasTraffic = totals.sent > 0 || totals.received > 0;
    const otherHosts = hosts.filter((h) => h.ip !== targetIp);

    return (
        <div className="space-y-6 max-w-7xl mx-auto pb-12">
            {/* Results header and host switcher */}
            <div className="bg-white rounded-xl border border-slate-200/80 shadow-sm p-5 flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                <div className="min-w-0">
                    <h2 className="text-lg font-bold text-slate-900 flex flex-wrap items-center gap-x-2 gap-y-1">
                        Traffic for
                        <code className="px-2 py-0.5 rounded-md bg-slate-100 text-indigo-700 font-semibold">{targetIp}</code>
                        {autoDetected && (
                            <span className="inline-flex items-center rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 ring-1 ring-emerald-200">
                                auto-detected
                            </span>
                        )}
                    </h2>
                    <p className="mt-1 text-sm text-slate-500">
                        {autoDetected ? 'The busiest host in ' : 'From '}
                        {fileName ? <span className="font-medium text-slate-600">{fileName}</span> : 'your capture'}
                        {'. Sent and received are both relative to this host.'}
                    </p>
                </div>

                {otherHosts.length > 0 && (
                    <div className="shrink-0">
                        <label htmlFor="host-switch" className="block text-xs font-semibold text-slate-600 mb-1.5">
                            Analyze a different host
                        </label>
                        <select
                            id="host-switch"
                            value=""
                            onChange={(e) => e.target.value && onChangeHost(e.target.value)}
                            className="w-full lg:w-72 rounded-lg border border-slate-300 bg-white py-2 pl-3 pr-8 text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                        >
                            <option value="">Pick a host in this capture</option>
                            {otherHosts.map((h) => (
                                <option key={h.ip} value={h.ip}>
                                    {h.ip} ({formatCount(h.packets)} packets)
                                </option>
                            ))}
                        </select>
                    </div>
                )}
            </div>

            {!hasTraffic && (
                <div className="bg-amber-50 border border-amber-200 text-amber-900 rounded-xl p-5 text-sm">
                    <p className="font-semibold">No TCP traffic matched {targetIp}.</p>
                    <p className="mt-1">
                        Check the address, or pick another host from the list above. PCAP Explorer only reads TCP, so a capture made up of
                        UDP, ICMP or ARP traffic comes back empty.
                    </p>
                </div>
            )}

            {/* Summary tiles */}
            <dl className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-3 2xl:grid-cols-6">
                <StatCard title="Packets sent" value={totals.sent.toLocaleString()} color={SENT} icon={<ArrowUpIcon className="h-5 w-5" />} />
                <StatCard
                    title="Packets received"
                    value={totals.received.toLocaleString()}
                    color={RECEIVED}
                    icon={<ArrowDownIcon className="h-5 w-5" />}
                />
                <StatCard title="Data sent" value={formatBytes(totals.bytesSent)} color={SENT_BYTES} icon={<DatabaseIcon className="h-5 w-5" />} />
                <StatCard
                    title="Data received"
                    value={formatBytes(totals.bytesReceived)}
                    color={RECEIVED_BYTES}
                    icon={<InboxIcon className="h-5 w-5" />}
                />
                <StatCard
                    title="Peers"
                    value={peers.total.toLocaleString()}
                    sub={peers.private > 0 ? `${peers.private} on the local network` : undefined}
                    color="#8b5cf6"
                    icon={<PeersIcon className="h-5 w-5" />}
                />
                <StatCard
                    title="Countries"
                    value={countryCount.toLocaleString()}
                    sub={locations.length > 0 ? `${locations.length} located IPs` : 'no public destinations'}
                    color="#ec4899"
                    icon={<NetworkIcon className="h-5 w-5" />}
                />
            </dl>

            {/* Map */}
            <section className="bg-white rounded-xl shadow-sm border border-slate-200/80 overflow-hidden" aria-labelledby="map-heading">
                <div className="px-5 sm:px-6 py-4 border-b border-slate-200/80">
                    <h3 id="map-heading" className="text-base font-bold text-slate-800">
                        Where the packets went
                    </h3>
                    <p className="mt-0.5 text-sm text-slate-500">
                        Destinations {targetIp} sent TCP packets to, located with MaxMind GeoLite2. Bigger markers mean more packets.
                    </p>
                </div>
                {mapError && (
                    <div className="mx-5 sm:mx-6 mt-4 bg-amber-50 text-amber-900 p-3 rounded-lg border border-amber-200 text-sm">{mapError}</div>
                )}
                <div className="p-5 sm:p-6 grid gap-5 lg:grid-cols-3">
                    <div className="lg:col-span-2 border border-slate-200 rounded-lg overflow-hidden h-80 sm:h-96">
                        <MapComponent locations={locations} />
                    </div>
                    <div className="lg:max-h-96 lg:overflow-y-auto">
                        {locations.length > 0 ? (
                            <ol className="space-y-1.5">
                                {locations.map((loc) => (
                                    <li
                                        key={loc.ip}
                                        className="flex items-baseline justify-between gap-3 rounded-lg px-3 py-2 bg-slate-50 border border-slate-100"
                                    >
                                        <div className="min-w-0">
                                            <p className="text-sm font-medium text-slate-800 truncate">
                                                {loc.city !== 'Unknown' ? `${loc.city}, ` : ''}
                                                {loc.country}
                                            </p>
                                            <p className="text-xs text-slate-500 font-mono truncate">{loc.ip}</p>
                                        </div>
                                        <span className="text-sm font-semibold text-slate-600 shrink-0">{formatCount(loc.count)}</span>
                                    </li>
                                ))}
                            </ol>
                        ) : (
                            <p className="text-sm text-slate-500">
                                Nothing to put on the map. Private addresses (10.x, 192.168.x, fd00::/8) have no public location, so a
                                LAN-only capture leaves this empty.
                            </p>
                        )}
                    </div>
                </div>
            </section>

            {/* Charts */}
            <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">
                <div className="xl:col-span-2">
                    <TimelineChart
                        title="Packets over time"
                        description="TCP packets per second, in each direction."
                        data={packetTimeline}
                        colors={[SENT, RECEIVED]}
                        format={formatCount}
                        unit="packets"
                    />
                </div>
                <div className="xl:col-span-2">
                    <TimelineChart
                        title="Throughput over time"
                        description="Bytes on the wire per second, headers included."
                        data={byteTimeline}
                        colors={[SENT_BYTES, RECEIVED_BYTES]}
                        format={formatBytes}
                        unit="bytes"
                    />
                </div>

                <PeersChart
                    title="Top destinations"
                    description={`Hosts ${targetIp} sent the most packets to.`}
                    data={sentIPData}
                    color={SENT}
                    direction="Sent"
                />
                <PeersChart
                    title="Top sources"
                    description={`Hosts that sent ${targetIp} the most packets.`}
                    data={receivedIPData}
                    color={RECEIVED}
                    direction="Received"
                />
            </div>
        </div>
    );
};
