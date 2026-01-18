import { useState } from 'react';
import { UploadForm } from './components/UploadForm';
import { Dashboard } from './components/Dashboard';
import type { AnalyzeResponse } from './types';

function App() {
  const [data, setData] = useState<AnalyzeResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="min-h-screen bg-gray-50 font-sans">
      <header className="bg-indigo-700 shadow-lg">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8 flex justify-between items-center">
          <h1 className="text-2xl font-bold text-white tracking-wide">PCAP Traffic Analyzer</h1>
          <a href="#" onClick={() => setData(null)} className="text-indigo-200 hover:text-white text-sm">Reset</a>
        </div>
      </header>
      <main>
        <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
          {!data && !loading && (
              <div className="mb-8 text-center text-gray-600">
                  <p>Upload a .pcap file to analyze network traffic patterns and visualize geolocation of IPs.</p>
              </div>
          )}

          {!data && (
            <UploadForm
                onAnalyze={setData}
                setLoading={setLoading}
                setError={setError}
            />
          )}

          {loading && (
            <div className="text-center py-24">
               <div className="inline-block animate-spin rounded-full h-12 w-12 border-4 border-indigo-200 border-t-indigo-600"></div>
               <p className="mt-4 text-gray-600 font-medium">Analyzing traffic data...</p>
               <p className="text-sm text-gray-400">This happens on the server (Go).</p>
            </div>
          )}

          {error && (
            <div className="bg-red-50 border-l-4 border-red-500 p-4 mb-6 rounded shadow-sm max-w-4xl mx-auto">
              <div className="flex">
                <div className="ml-3">
                  <h3 className="text-sm font-medium text-red-800">Error</h3>
                  <div className="mt-2 text-sm text-red-700">
                    <p>{error}</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {data && !loading && (
             <Dashboard data={data} />
          )}
        </div>
      </main>
    </div>
  );
}

export default App;
