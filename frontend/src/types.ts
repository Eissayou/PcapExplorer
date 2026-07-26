export interface GraphData {
    sentTime: Record<string, number>; // JSON keys are strings
    receivedTime: Record<string, number>;
    sentIP: Record<string, number>;
    receivedIP: Record<string, number>;
    sentSize: Record<string, number>;
    receivedSize: Record<string, number>;
}

export interface GeoLocation {
    ip: string;
    city: string;
    country: string;
    latitude: number;
    longitude: number;
    count: number;
}

/** An endpoint seen in the capture, with how many TCP packets it appears in. */
export interface HostCount {
    ip: string;
    packets: number;
}

export interface AnalyzeResponse {
    /** The host the results are relative to, echoed back or auto-detected. */
    targetIp: string;
    /** True when the server picked the target rather than the user. */
    autoDetected: boolean;
    /** Busiest endpoints, offered as alternative targets. */
    hosts: HostCount[];
    graphObjects: GraphData;
    locations: GeoLocation[];
    mapError?: string;
}
