import { useState } from 'react';
import { UploadForm } from './components/UploadForm';
import { Dashboard } from './components/Dashboard';
import type { AnalyzeResponse } from './types';

function App() {
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [targetIp, setTargetIp] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleResult = (result: AnalyzeResponse, ip: string) => {
    setTargetIp(ip);
    setData(result);
  };

  const reset = () => {
    setData(null);
    setError(null);
    setTargetIp('');
  };

  return (
    <div className="min-h-screen flex flex-col bg-gradient-to-b from-slate-50 to-slate-100 text-slate-800 font-sans">
      <header className="sticky top-0 z-20 bg-gradient-to-r from-indigo-600 via-indigo-600 to-violet-600 shadow-lg">
        <div className="max-w-7xl mx-auto py-4 px-4 sm:px-6 lg:px-8 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <span className="grid place-items-center h-10 w-10 rounded-xl bg-white/15 ring-1 ring-white/25 backdrop-blur">
              <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </span>
            <div className="leading-tight">
              <h1 className="text-xl font-bold text-white tracking-tight">PCAP Explorer</h1>
              <p className="text-[11px] text-indigo-100/90 hidden sm:block">Visualize where your packets go</p>
            </div>
          </div>
          {data && (
            <button
              onClick={reset}
              className="inline-flex items-center gap-1.5 rounded-lg bg-white/10 hover:bg-white/20 px-3 py-1.5 text-sm font-medium text-white ring-1 ring-white/25 transition"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              New analysis
            </button>
          )}
        </div>
      </header>

      <main className="flex-1">
        <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
          {!data && !loading && (
            <div className="mb-8 text-center max-w-2xl mx-auto">
              <h2 className="text-2xl sm:text-3xl font-bold text-slate-900">Analyze your network capture</h2>
              <p className="mt-2 text-slate-500">
                Upload a <code className="px-1.5 py-0.5 rounded bg-slate-200/70 text-slate-700 text-sm">.pcap</code> or
                <code className="px-1.5 py-0.5 rounded bg-slate-200/70 text-slate-700 text-sm ml-1">.pcapng</code> file to
                chart traffic over time, surface top talkers, and map where packets are headed.
              </p>
            </div>
          )}

          {!data && !loading && (
            <UploadForm onResult={handleResult} setLoading={setLoading} setError={setError} />
          )}

          {loading && (
            <div className="text-center py-24">
              <div className="inline-block animate-spin rounded-full h-12 w-12 border-4 border-indigo-200 border-t-indigo-600"></div>
              <p className="mt-4 text-slate-600 font-medium">Analyzing traffic&hellip;</p>
              <p className="text-sm text-slate-400">Parsing packets on the server (Go).</p>
            </div>
          )}

          {error && !loading && (
            <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-6 rounded-r-lg shadow-sm max-w-4xl mx-auto">
              <div className="flex items-start gap-3">
                <svg className="h-5 w-5 text-red-500 mt-0.5 shrink-0" viewBox="0 0 20 20" fill="currentColor">
                  <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                </svg>
                <div>
                  <h3 className="text-sm font-semibold text-red-800">Analysis failed</h3>
                  <p className="mt-1 text-sm text-red-700">{error}</p>
                </div>
              </div>
            </div>
          )}

          {data && !loading && <Dashboard data={data} targetIp={targetIp} />}
        </div>
      </main>

      <footer className="border-t border-slate-200 py-6">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center text-sm text-slate-500 space-y-1">
          <p>
            Made by{' '}
            <a href="https://www.eissayou.com" className="font-semibold text-indigo-600 hover:text-indigo-700" target="_blank" rel="author noopener">
              Jason Eissayou
            </a>{' '}
            &middot;{' '}
            <a href="https://www.eissayou.com/projects/pcap-tracker.html" className="hover:text-slate-700" target="_blank" rel="noopener">
              Case study
            </a>{' '}
            &middot;{' '}
            <a href="https://github.com/Eissayou/PcapExplorer" className="hover:text-slate-700" target="_blank" rel="noopener">
              Source on GitHub
            </a>
          </p>
          <p className="text-xs text-slate-400">
            A project by Jason Eissayou —{' '}
            <a href="https://www.eissayou.com" className="hover:text-slate-600" target="_blank" rel="noopener">
              www.eissayou.com
            </a>
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
