import React, { useCallback, useRef, useState } from 'react';
import { SAMPLE_CAPTURE_URL } from '../api';
import { formatBytes, isValidIp } from '../format';
import { BoltIcon, CheckIcon, FileIcon, GlobeIcon, PlayIcon, UploadIcon, XCircleIcon } from './Icons';

interface Props {
    /** Runs the analysis. An empty ip asks the server to auto-detect the host. */
    onAnalyze: (file: File, ip: string) => void;
    /** Loads the bundled demo capture and analyzes it in one step. */
    onTrySample: () => void;
}

const MAX_FILE_BYTES = 100 * 1024 * 1024; // 100MB, matches the server limit
const VALID_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

export const UploadForm: React.FC<Props> = ({ onAnalyze, onTrySample }) => {
    const [ip, setIp] = useState('');
    const [file, setFile] = useState<File | null>(null);
    const [isDragging, setIsDragging] = useState(false);
    const [fileError, setFileError] = useState<string | null>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    const ipTouched = ip.trim().length > 0;
    const ipValid = isValidIp(ip);
    const canSubmit = file !== null && (!ipTouched || ipValid);

    const acceptFile = useCallback((f: File) => {
        const lower = f.name.toLowerCase();
        if (!VALID_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
            setFileError('That file type is not supported. Use .pcap, .pcapng or .cap.');
            return;
        }
        if (f.size > MAX_FILE_BYTES) {
            setFileError(`That file is ${formatBytes(f.size)}, and the limit is 100 MB.`);
            return;
        }
        setFileError(null);
        setFile(f);
    }, []);

    const handleDrag = useCallback((e: React.DragEvent) => {
        e.preventDefault();
        e.stopPropagation();
        setIsDragging(e.type === 'dragenter' || e.type === 'dragover');
    }, []);

    const handleDrop = useCallback(
        (e: React.DragEvent) => {
            e.preventDefault();
            e.stopPropagation();
            setIsDragging(false);
            const dropped = e.dataTransfer.files?.[0];
            if (dropped) acceptFile(dropped);
        },
        [acceptFile],
    );

    const handleSubmit = (e: React.FormEvent) => {
        e.preventDefault();
        if (file && canSubmit) onAnalyze(file, ipTouched ? ip.trim() : '');
    };

    return (
        <form
            onSubmit={handleSubmit}
            className="bg-white p-6 sm:p-8 rounded-2xl shadow-xl shadow-slate-200/60 max-w-3xl mx-auto border border-slate-200/80"
        >
            <h2 className="sr-only">Upload a capture</h2>

            {file ? (
                <div className="flex items-center justify-between gap-3 px-4 py-4 rounded-xl border border-indigo-200 bg-indigo-50/60">
                    <div className="flex items-center gap-3 min-w-0">
                        <FileIcon className="h-9 w-9 text-indigo-500 shrink-0" />
                        <div className="min-w-0">
                            <p className="text-sm font-semibold text-slate-800 truncate">{file.name}</p>
                            <p className="text-xs text-slate-500">{formatBytes(file.size)}, ready to analyze</p>
                        </div>
                    </div>
                    <button
                        type="button"
                        onClick={() => {
                            setFile(null);
                            setFileError(null);
                            if (inputRef.current) inputRef.current.value = '';
                        }}
                        className="shrink-0 rounded-lg px-2.5 py-1.5 text-sm font-medium text-slate-500 hover:text-slate-800 hover:bg-slate-200/70 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 transition"
                    >
                        Remove
                    </button>
                </div>
            ) : (
                <div
                    role="button"
                    tabIndex={0}
                    aria-describedby="dropzone-hint"
                    onClick={() => inputRef.current?.click()}
                    onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault();
                            inputRef.current?.click();
                        }
                    }}
                    onDragEnter={handleDrag}
                    onDragLeave={handleDrag}
                    onDragOver={handleDrag}
                    onDrop={handleDrop}
                    className={`flex flex-col items-center justify-center gap-2 px-6 py-10 border-2 border-dashed rounded-xl cursor-pointer transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 ${
                        isDragging ? 'border-indigo-500 bg-indigo-50' : 'border-slate-300 hover:border-indigo-400 hover:bg-slate-50'
                    }`}
                >
                    <UploadIcon className="h-11 w-11 text-slate-400" />
                    <p className="text-sm text-slate-700">
                        <span className="font-semibold text-indigo-600">Choose a capture</span> or drag it here
                    </p>
                    <p id="dropzone-hint" className="text-xs text-slate-500">
                        .pcap, .pcapng or .cap, up to 100 MB
                    </p>
                </div>
            )}

            <input
                ref={inputRef}
                id="file-upload"
                type="file"
                className="hidden"
                accept=".pcap,.pcapng,.cap"
                onChange={(e) => {
                    const picked = e.target.files?.[0];
                    if (picked) acceptFile(picked);
                }}
            />

            {fileError && (
                <p role="alert" className="mt-3 text-sm text-red-600">
                    {fileError}
                </p>
            )}

            <div className="mt-6">
                <label htmlFor="ip" className="flex items-baseline justify-between text-sm font-semibold text-slate-700 mb-2">
                    <span>Host to analyze</span>
                    <span className="text-xs font-normal text-slate-400">optional</span>
                </label>
                <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <GlobeIcon className="h-5 w-5 text-slate-400" />
                    </div>
                    <input
                        id="ip"
                        type="text"
                        value={ip}
                        onChange={(e) => setIp(e.target.value)}
                        placeholder="Leave blank to auto-detect the busiest host"
                        autoComplete="off"
                        spellCheck={false}
                        aria-invalid={ipTouched && !ipValid}
                        aria-describedby="ip-hint"
                        className={`block w-full pl-10 pr-10 py-3 border rounded-lg bg-white placeholder-slate-400 focus:outline-none focus:ring-2 sm:text-sm transition ${
                            ipTouched && !ipValid
                                ? 'border-red-300 focus:ring-red-500 focus:border-red-500'
                                : 'border-slate-300 focus:ring-indigo-500 focus:border-indigo-500'
                        }`}
                    />
                    {ipTouched && (
                        <div className="absolute inset-y-0 right-0 pr-3 flex items-center">
                            {ipValid ? <CheckIcon className="h-5 w-5 text-emerald-500" /> : <XCircleIcon className="h-5 w-5 text-red-400" />}
                        </div>
                    )}
                </div>
                <p id="ip-hint" className={`mt-2 text-xs ${ipTouched && !ipValid ? 'text-red-600' : 'text-slate-500'}`}>
                    {ipTouched && !ipValid
                        ? 'That is not a valid IPv4 or IPv6 address.'
                        : 'Traffic is split into sent and received relative to this host. You can change it after the first run.'}
                </p>
            </div>

            <button
                type="submit"
                className="mt-6 w-full flex justify-center items-center gap-2 py-3 px-4 rounded-lg text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition shadow-md hover:shadow-lg"
                disabled={!canSubmit}
            >
                <BoltIcon className="h-5 w-5" />
                Analyze traffic
            </button>

            <div className="mt-6 pt-5 border-t border-slate-200/80 text-center">
                <p className="text-sm text-slate-600">No capture handy?</p>
                <button
                    type="button"
                    onClick={onTrySample}
                    className="mt-2 inline-flex items-center gap-2 rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-2 text-sm font-semibold text-indigo-700 hover:bg-indigo-100 hover:border-indigo-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-500 transition"
                >
                    <PlayIcon className="h-4 w-4" />
                    Try the sample capture
                </button>
                <p className="mt-2 text-xs text-slate-500">
                    Three minutes of one workstation&rsquo;s TCP traffic, spread across 15 cities.{' '}
                    <a href={SAMPLE_CAPTURE_URL} download className="text-indigo-600 hover:text-indigo-700 underline underline-offset-2">
                        Download it
                    </a>{' '}
                    if you want to open the same file in Wireshark.
                </p>
            </div>
        </form>
    );
};
