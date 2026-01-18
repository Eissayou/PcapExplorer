export interface GraphData {
    sentTime: Record<string, number>; // JSON keys are strings
    receivedTime: Record<string, number>;
    sentIP: Record<string, number>;
    receivedIP: Record<string, number>;
    sentSize: Record<string, number>;
}

export interface GeoLocation {
    ip: string;
    city: string;
    country: string;
    latitude: number;
    longitude: number;
    count: number;
}

export interface AnalyzeResponse {
    graphObjects: GraphData;
    locations: GeoLocation[];
    mapError?: string;
}
