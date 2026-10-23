import { useState, useEffect, lazy, Suspense } from 'react';
import { Navbar } from './components/Navbar';
import { LandingHero } from './components/LandingHero';
import { ScanWorkspace } from './components/ScanWorkspace';
import { ScanResultView } from './components/ScanResultView';
import type { ScanResponse, HealthStatus, ScanType } from './types';
import { checkHealth } from './services/api';
import { Shield, Sparkles } from 'lucide-react';

// Code-split heavy views for optimal performance & loading efficiency
const Dashboard = lazy(() => import('./components/Dashboard').then((m) => ({ default: m.Dashboard })));
const ScanHistory = lazy(() => import('./components/ScanHistory').then((m) => ({ default: m.ScanHistory })));
const MethodologyModal = lazy(() => import('./components/MethodologyModal').then((m) => ({ default: m.MethodologyModal })));

export function App() {
  const [activeTab, setActiveTab] = useState<'workspace' | 'dashboard' | 'history' | 'methodology'>('workspace');
  const [currentResult, setCurrentResult] = useState<ScanResponse | null>(null);
  const [scanTypePreference, setScanTypePreference] = useState<ScanType>('text');
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    checkHealth()
      .then(setHealth)
      .catch((err) => console.warn('Backend offline or health check failed:', err));
  }, []);

  const handleStartScan = (type?: ScanType) => {
    if (type) setScanTypePreference(type);
    setCurrentResult(null);
    setActiveTab('workspace');
  };

  const handleScanComplete = (result: ScanResponse) => {
    setCurrentResult(result);
  };

  const handleSelectFromHistory = (scan: ScanResponse) => {
    setCurrentResult(scan);
    setActiveTab('workspace');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-between selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'workspace') setCurrentResult(null);
        }}
        health={health}
      />

      {/* Main Content Area */}
      <main id="main-content" tabIndex={-1} className="flex-1 pb-16 outline-none">
        {activeTab === 'workspace' && (
          <>
            {!currentResult && <LandingHero onStartScan={handleStartScan} />}
            {currentResult ? (
              <ScanResultView
                result={currentResult}
                onNewScan={() => setCurrentResult(null)}
              />
            ) : (
              <ScanWorkspace
                initialScanType={scanTypePreference}
                onScanComplete={handleScanComplete}
              />
            )}
          </>
        )}

        <Suspense
          fallback={
            <div className="flex items-center justify-center p-20 text-slate-400 gap-2">
              <Sparkles className="h-5 w-5 text-cyan-400 animate-spin" />
              <span className="text-sm">Loading security module...</span>
            </div>
          }
        >
          {activeTab === 'dashboard' && (
            <Dashboard
              onSelectScan={handleSelectFromHistory}
              onGoToScanner={() => {
                setCurrentResult(null);
                setActiveTab('workspace');
              }}
            />
          )}

          {activeTab === 'history' && (
            <ScanHistory
              onSelectScan={handleSelectFromHistory}
              onGoToScanner={() => {
                setCurrentResult(null);
                setActiveTab('workspace');
              }}
            />
          )}

          {activeTab === 'methodology' && <MethodologyModal />}
        </Suspense>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-8 px-4 sm:px-6 lg:px-8 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-cyan-500" />
            <span className="font-semibold text-slate-300">ScamShield</span>
            <span>• Engineered for PromptWar Hackathon</span>
          </div>
          <div className="text-center sm:text-right space-y-1">
            <p>
              Theme: <span className="text-slate-400">Build Beyond AI: Engineer Secure, Intelligent & Autonomous Applications</span>
            </p>
            <p className="text-[11px] text-slate-600">
              ScamShield provides informational security analysis and risk estimation; not a guarantee of absolute safety.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
