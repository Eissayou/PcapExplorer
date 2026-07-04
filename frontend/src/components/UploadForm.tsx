import React, { useState, useCallback } from 'react';
import axios from 'axios';
import type { AnalyzeResponse } from '../types';

interface Props {
    onResult: (data: AnalyzeResponse, ip: string) => void;
    setLoading: (loading: boolean) => void;
    setError: (error: string | null) => void;
}

const MAX_FILE_BYTES = 100 * 1024 * 1024; // 100MB, matches the server limit
const VALID_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

/** Validate an IPv4 or IPv6 address without a network round-trip. */
function isValidIp(value: string): boolean {
    const ip = value.trim();
    if (!ip) return false;
    // IPv6 (incl. embedded IPv4) — lean on the URL parser's host validation.
    if (ip.includes(':')) {
        try {
            return new URL(`http://[${ip}]`).hostname.length > 0;
        } catch {
            return false;
        }
    }
    // IPv4 — exactly four octets in 0-255.
    const parts = ip.split('.');
    return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    const units = ['KB', 'MB', 'GB'];
    let i = -1;
    let n = bytes;
    do {
        n /= 1024;
        i++;
    } while (n >= 1024 && i < units.length - 1);
    return `${n.toFixed(1)} ${units[i]}`;
}

export const UploadForm: React.FC<Props> = ({ onResult, setLoading, setError }) => {
    const [ip, setIp] = useState('');
    const [file, setFile] = useState<File | null>(null);
    const [isDragging, setIsDragging] = useState(false);
    const [fileError, setFileError] = useState<string | null>(null);

    const ipTouched = ip.trim().length > 0;
    const ipValid = isValidIp(ip);

    const acceptFile = useCallback((f: File) => {
        const lower = f.name.toLowerCase();
        if (!VALID_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
            setFileError('Unsupported file type. Use .pcap or .pcapng.');
            return;
        }
        if (f.size > MAX_FILE_BYTES) {
            setFileError(`File is ${formatBytes(f.size)} — the limit is 100MB.`);
            return;
        }
        setFileError(null);
        setFile(f);
    }, []);

    const handleDrag = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        if (e.type === 'dragenter' || e.type === 'dragover') {
            setIsDragging(true);
        } else if (e.type === 'dragleave') {
            setIsDragging(false);
        }
    }, []);

    const handleDrop = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(false);
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
            acceptFile(e.dataTransfer.files[0]);
        }
    }, [acceptFile]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!ipValid) {
            setError('Please enter a valid IPv4 or IPv6 address.');
            return;
        }
        if (!file) {
            setError('Please select a PCAP file to analyze.');
            return;
        }

        setLoading(true);
        setError(null);

        const formData = new FormData();
        formData.append('ip', ip.trim());
        formData.append('file', file);

        try {
            const res = await axios.post<AnalyzeResponse>('/api/analyze', formData);
            onResult(res.data, ip.trim());
        } catch (err) {
            let message = 'Upload failed. Please try again.';
            if (axios.isAxiosError(err)) {
                message = typeof err.response?.data === 'string' && err.response.data
                    ? err.response.data
                    : err.message;
            }
            setError(message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="bg-white p-6 sm:p-8 rounded-2xl shadow-xl shadow-slate-200/60 mb-8 max-w-4xl mx-auto border border-slate-100">
            <h2 className="text-xl font-bold mb-6 text-slate-800 flex items-center">
                <span className="bg-indigo-100 text-indigo-600 p-2 rounded-lg mr-3">
                    <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                </span>
                Start analysis
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 md:gap-8">
                <div>
                    <label htmlFor="ip" className="block text-sm font-semibold text-slate-700 mb-2">Target IP address</label>
                    <div className="relative">
                        <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                            <svg xmlns="http://www.w3.org/2000/svg" className="h-5 w-5 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
                            </svg>
                        </div>
                        <input
                            id="ip"
                            type="text"
                            value={ip}
                            onChange={(e) => setIp(e.target.value)}
                            placeholder="e.g. 192.168.1.5"
                            autoComplete="off"
                            spellCheck={false}
                            aria-invalid={ipTouched && !ipValid}
                            className={`block w-full pl-10 pr-10 py-3 border rounded-lg bg-white placeholder-slate-400 focus:outline-none focus:ring-2 sm:text-sm transition ${
                                ipTouched && !ipValid
                                    ? 'border-red-300 focus:ring-red-500 focus:border-red-500'
                                    : 'border-slate-300 focus:ring-indigo-500 focus:border-indigo-500'
                            }`}
                        />
                        {ipTouched && (
                            <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                                {ipValid ? (
                                    <svg className="h-5 w-5 text-green-500" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" /></svg>
                                ) : (
                                    <svg className="h-5 w-5 text-red-400" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" /></svg>
                                )}
                            </div>
                        )}
                    </div>
                    <p className={`mt-2 text-xs ${ipTouched && !ipValid ? 'text-red-600' : 'text-slate-500'}`}>
                        {ipTouched && !ipValid ? 'Enter a valid IPv4 or IPv6 address.' : 'The host whose traffic you want to analyze.'}
                    </p>
                </div>

                <div>
                    <label className="block text-sm font-semibold text-slate-700 mb-2">PCAP file</label>
                    {file ? (
                        <div className="flex items-center justify-between gap-3 px-4 py-3 rounded-lg border border-indigo-200 bg-indigo-50/60">
                            <div className="flex items-center gap-3 min-w-0">
                                <svg className="h-8 w-8 text-indigo-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.6}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
                                </svg>
                                <div className="min-w-0">
                                    <p className="text-sm font-medium text-slate-800 truncate">{file.name}</p>
                                    <p className="text-xs text-slate-500">{formatBytes(file.size)}</p>
                                </div>
                            </div>
                            <button
                                type="button"
                                onClick={() => { setFile(null); setFileError(null); }}
                                className="shrink-0 rounded-md p-1 text-slate-400 hover:text-slate-600 hover:bg-slate-200/60 transition"
                                aria-label="Remove file"
                            >
                                <svg className="h-5 w-5" viewBox="0 0 20 20" fill="currentColor"><path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" /></svg>
                            </button>
                        </div>
                    ) : (
                        <div
                            className={`flex justify-center px-6 py-6 border-2 border-dashed rounded-lg transition-colors ${isDragging ? 'border-indigo-500 bg-indigo-50' : 'border-slate-300 hover:border-indigo-400 hover:bg-slate-50'}`}
                            onDragEnter={handleDrag}
                            onDragLeave={handleDrag}
                            onDragOver={handleDrag}
                            onDrop={handleDrop}
                        >
                            <div className="space-y-1 text-center">
                                <svg className="mx-auto h-10 w-10 text-slate-400" stroke="currentColor" fill="none" viewBox="0 0 48 48" aria-hidden="true">
                                    <path d="M28 8H12a4 4 0 00-4 4v20m32-12v8m0 0v8a4 4 0 01-4 4H12a4 4 0 01-4-4v-4m32-4l-3.172-3.172a4 4 0 00-5.656 0L28 28M8 32l9.172-9.172a4 4 0 015.656 0L28 28m0 0l4 4m4-24h8m-4-4v8m-12 4h.02" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                </svg>
                                <div className="flex text-sm text-slate-600 justify-center">
                                    <label htmlFor="file-upload" className="relative cursor-pointer rounded-md font-medium text-indigo-600 hover:text-indigo-500 focus-within:outline-none focus-within:ring-2 focus-within:ring-indigo-500">
                                        <span>Upload a file</span>
                                        <input id="file-upload" name="file-upload" type="file" className="sr-only" accept=".pcap,.pcapng,.cap" onChange={(e) => e.target.files && e.target.files[0] && acceptFile(e.target.files[0])} />
                                    </label>
                                    <p className="pl-1">or drag and drop</p>
                                </div>
                                <p className="text-xs text-slate-500">PCAP or PCAPNG up to 100MB</p>
                            </div>
                        </div>
                    )}
                    {fileError && <p className="mt-2 text-xs text-red-600">{fileError}</p>}
                </div>
            </div>

            <div className="mt-8">
                <button
                    type="submit"
                    className="group relative w-full flex justify-center items-center gap-2 py-3 px-4 rounded-lg text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition shadow-md hover:shadow-lg"
                    disabled={!ipValid || !file}
                >
                    <svg className="h-5 w-5" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                        <path fillRule="evenodd" d="M11.3 1.046A1 1 0 0112 2v5h4a1 1 0 01.82 1.573l-7 10A1 1 0 018 18v-5H4a1 1 0 01-.82-1.573l7-10a1 1 0 011.12-.38z" clipRule="evenodd" />
                    </svg>
                    Analyze traffic
                </button>
            </div>
        </form>
    );
};
