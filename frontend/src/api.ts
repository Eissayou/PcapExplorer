import axios from 'axios';
import type { AnalyzeResponse } from './types';

/** Path of the demo capture shipped with the app (see cmd/gen_pcap). */
export const SAMPLE_CAPTURE_URL = '/sample-capture.pcap';
export const SAMPLE_CAPTURE_NAME = 'sample-capture.pcap';

/**
 * Post a capture to the backend for analysis.
 *
 * `ip` is optional: leaving it out asks the server to analyze the busiest host
 * in the file, which is almost always the machine the capture was taken on.
 */
export async function analyzeCapture(file: File, ip?: string): Promise<AnalyzeResponse> {
    const formData = new FormData();
    formData.append('file', file);
    if (ip) formData.append('ip', ip);

    try {
        const res = await axios.post<AnalyzeResponse>('/api/analyze', formData);
        return res.data;
    } catch (err) {
        throw new Error(describeError(err));
    }
}

/** Download the bundled sample capture and hand it back as a File. */
export async function fetchSampleCapture(): Promise<File> {
    const res = await fetch(SAMPLE_CAPTURE_URL);
    if (!res.ok) {
        throw new Error(`Could not load the sample capture (HTTP ${res.status}).`);
    }
    const blob = await res.blob();
    return new File([blob], SAMPLE_CAPTURE_NAME, { type: 'application/vnd.tcpdump.pcap' });
}

/**
 * Turn whatever the network layer threw into a sentence worth showing a person.
 * The Go handler replies with plain-text errors, so those are passed through
 * when present.
 */
function describeError(err: unknown): string {
    if (!axios.isAxiosError(err)) {
        return err instanceof Error ? err.message : 'Something went wrong. Please try again.';
    }
    const body = err.response?.data;
    if (typeof body === 'string' && body.trim()) {
        return body.trim();
    }
    if (err.code === 'ERR_NETWORK') {
        return 'Could not reach the analyzer. Check your connection and try again.';
    }
    return err.message || 'Upload failed. Please try again.';
}
