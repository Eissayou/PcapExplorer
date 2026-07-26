import { useCallback, useEffect, useRef, useState } from 'react';
import { UploadForm } from './components/UploadForm';
import { Dashboard } from './components/Dashboard';
import { LandingContent } from './components/LandingContent';
import { AlertIcon, NetworkIcon, RefreshIcon } from './components/Icons';
import { analyzeCapture, fetchSampleCapture } from './api';
import { AUTHOR } from './content';
import type { AnalyzeResponse } from './types';

function App() {
    const [data, setData] = useState<AnalyzeResponse | null>(null);
    const [loading, setLoading] = useState<string | null>(null);
    const [error, setError] = useState<string | null>(null);

    // The capture is kept so the host switcher can re-run the analysis without
    // asking the visitor to pick the same file a second time.
    const [file, setFile] = useState<File | null>(null);
    const resultsRef = useRef<HTMLDivElement>(null);

    /**
     * Single path for every analysis on the page: the form, the sample button
     * and the host switcher all end up here. `load` optionally fetches the
     * capture first, which is what the sample button needs.
     */
    const run = useCallback(async (label: string, load: () => Promise<{ capture: File; ip: string }>) => {
        setLoading(label);
        setError(null);
        try {
            const { capture, ip } = await load();
            const result = await analyzeCapture(capture, ip);
            setFile(capture);
            setData(result);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Analysis failed. Please try again.');
        } finally {
            setLoading(null);
        }
    }, []);

    const analyze = useCallback(
        (capture: File, ip: string) => void run('Analyzing traffic', async () => ({ capture, ip })),
        [run],
    );

    const trySample = useCallback(
        () => void run('Loading the sample capture', async () => ({ capture: await fetchSampleCapture(), ip: '' })),
        [run],
    );

    const changeHost = useCallback(
        (ip: string) => {
            if (file) void run(`Analyzing ${ip}`, async () => ({ capture: file, ip }));
        },
        [file, run],
    );

    const reset = () => {
        setData(null);
        setError(null);
        setFile(null);
    };

    // Bring fresh results into view. Without this, switching hosts leaves the
    // visitor looking at whatever they had scrolled to.
    useEffect(() => {
        if (data) resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, [data]);

    const showLanding = !data && !loading;

    return (
        <div className="min-h-screen flex flex-col bg-gradient-to-b from-slate-50 to-slate-100 text-slate-800 font-sans">
            <a
                href="#main"
                className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:m-3 focus:rounded-lg focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-indigo-700 focus:shadow-lg"
            >
                Skip to content
            </a>

            <header className="sticky top-0 z-20 bg-gradient-to-r from-indigo-600 via-indigo-600 to-violet-600 shadow-lg">
                <div className="max-w-7xl mx-auto py-3.5 px-4 sm:px-6 lg:px-8 flex justify-between items-center gap-4">
                    <div className="flex items-center gap-3">
                        <span className="grid place-items-center h-10 w-10 rounded-xl bg-white/15 ring-1 ring-white/25 backdrop-blur">
                            <NetworkIcon className="h-6 w-6 text-white" />
                        </span>
                        <div className="leading-tight">
                            <span className="block text-lg font-bold text-white tracking-tight">PCAP Explorer</span>
                            <span className="hidden sm:block text-[11px] text-indigo-100/90">
                                by{' '}
                                <a
                                    href={AUTHOR.site}
                                    target="_blank"
                                    rel="author noopener"
                                    className="underline decoration-indigo-300/60 underline-offset-2 hover:text-white"
                                >
                                    Jason Eissayou
                                </a>
                            </span>
                        </div>
                    </div>
                    {data && (
                        <button
                            onClick={reset}
                            className="inline-flex items-center gap-1.5 rounded-lg bg-white/10 hover:bg-white/20 px-3 py-1.5 text-sm font-medium text-white ring-1 ring-white/25 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-white"
                        >
                            <RefreshIcon className="h-4 w-4" />
                            New analysis
                        </button>
                    )}
                </div>
            </header>

            <main id="main" className="flex-1">
                <div className="max-w-7xl mx-auto py-10 sm:py-12 px-4 sm:px-6 lg:px-8">
                    {showLanding && (
                        <>
                            <div className="mb-10 text-center max-w-3xl mx-auto">
                                <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold tracking-tight text-slate-900">
                                    See where your network traffic actually goes
                                </h1>
                                <p className="mt-4 text-lg text-slate-600">
                                    PCAP Explorer is a free packet capture analyzer. Drop in a{' '}
                                    <code className="px-1.5 py-0.5 rounded bg-slate-200/70 text-slate-700 text-base">.pcap</code> or{' '}
                                    <code className="px-1.5 py-0.5 rounded bg-slate-200/70 text-slate-700 text-base">.pcapng</code> file and
                                    get a traffic timeline, the top talkers, and a world map of every destination. Nothing to install.
                                </p>
                            </div>
                            <UploadForm onAnalyze={analyze} onTrySample={trySample} />
                        </>
                    )}

                    {loading && (
                        <div className="text-center py-24" role="status" aria-live="polite">
                            <div className="inline-block animate-spin rounded-full h-12 w-12 border-4 border-indigo-200 border-t-indigo-600" />
                            <p className="mt-4 text-slate-700 font-medium">{loading}&hellip;</p>
                            <p className="text-sm text-slate-400">Parsing packets on the server.</p>
                        </div>
                    )}

                    {error && !loading && (
                        <div role="alert" className="bg-red-50 border-l-4 border-red-500 p-4 my-6 rounded-r-lg shadow-sm max-w-3xl mx-auto">
                            <div className="flex items-start gap-3">
                                <AlertIcon className="h-5 w-5 text-red-500 mt-0.5 shrink-0" />
                                <div>
                                    <h2 className="text-sm font-semibold text-red-800">Analysis failed</h2>
                                    <p className="mt-1 text-sm text-red-700">{error}</p>
                                </div>
                            </div>
                        </div>
                    )}

                    <div ref={resultsRef}>
                        {data && !loading && <Dashboard data={data} onChangeHost={changeHost} fileName={file?.name} />}
                    </div>

                    {showLanding && <LandingContent />}
                </div>
            </main>

            <footer className="border-t border-slate-200 bg-white/60 py-8">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-sm text-slate-500 space-y-2">
                    <p>
                        Built by{' '}
                        <a href={AUTHOR.site} className="font-semibold text-indigo-600 hover:text-indigo-700" target="_blank" rel="author noopener">
                            Jason Eissayou
                        </a>{' '}
                        &middot;{' '}
                        <a href={AUTHOR.caseStudy} className="hover:text-slate-700" target="_blank" rel="noopener">
                            Case study
                        </a>{' '}
                        &middot;{' '}
                        <a href={AUTHOR.projects} className="hover:text-slate-700" target="_blank" rel="noopener">
                            More projects
                        </a>{' '}
                        &middot;{' '}
                        <a href={AUTHOR.repo} className="hover:text-slate-700" target="_blank" rel="noopener">
                            Source on GitHub
                        </a>
                    </p>
                    <p className="text-xs text-slate-400">
                        Geolocation by MaxMind GeoLite2. Map tiles &copy;{' '}
                        <a href="https://www.openstreetmap.org/copyright" className="hover:text-slate-600" target="_blank" rel="noopener">
                            OpenStreetMap
                        </a>{' '}
                        contributors.
                    </p>
                </div>
            </footer>
        </div>
    );
}

export default App;
