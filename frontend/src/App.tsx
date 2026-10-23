import { useState, useEffect } from 'react';
import { Navbar } from './components/Navbar';
import { LandingHero } from './components/LandingHero';
import { ScanWorkspace } from './components/ScanWorkspace';
import { ScanResultView } from './components/ScanResultView';
import { Dashboard } from './components/Dashboard';
import { ScanHistory } from './components/ScanHistory';
import { MethodologyModal } from './components/MethodologyModal';
import type { HealthStatus, ScanResponse, ScanType } from './types';
import { checkHealth } from './services/api';
import { Shield, Lock, Cpu, Sparkles } from 'lucide-react';

export function App() {
  const [activeTab, setActiveTab] = useState<'workspace' | 'dashboard' | 'history' | 'methodology'>('workspace');
  const [currentResult, setCurrentResult] = useState<ScanResponse | null>(null);
  const [selectedScanType, setSelectedScanType] = useState<ScanType>('text');
  const [health, setHealth] = useState<HealthStatus | null>(null);

  useEffect(() => {
    checkHealth()
      .then((data) => setHealth(data))
      .catch((err) => console.warn('Health check unreachable:', err));
  }, []);

  const handleStartScanFromHero = (type?: ScanType) => {
    if (type) {
      setSelectedScanType(type);
    }
    setCurrentResult(null);
    setActiveTab('workspace');
  };

  const handleScanComplete = (result: ScanResponse) => {
    setCurrentResult(result);
  };

  const handleSelectHistoryScan = (scan: ScanResponse) => {
    setCurrentResult(scan);
    setActiveTab('workspace');
  };

  const handleNewScan = () => {
    setCurrentResult(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          setActiveTab(tab);
          if (tab !== 'workspace') {
            setCurrentResult(null);
          }
        }}
        health={health}
      />

      {/* Main Content Area */}
      <main className="flex-1">
        {activeTab === 'workspace' && (
          <>
            {!currentResult && (
              <>
                <LandingHero onStartScan={handleStartScanFromHero} />
                <div className="py-8">
                  <ScanWorkspace
                    key={selectedScanType}
                    initialScanType={selectedScanType}
                    onScanComplete={handleScanComplete}
                  />
                </div>
              </>
            )}

            {currentResult && (
              <ScanResultView
                result={currentResult}
                onNewScan={handleNewScan}
              />
            )}
          </>
        )}

        {activeTab === 'dashboard' && (
          <Dashboard
            onSelectScan={handleSelectHistoryScan}
            onGoToScanner={() => {
              setCurrentResult(null);
              setActiveTab('workspace');
            }}
          />
        )}

        {activeTab === 'history' && (
          <ScanHistory
            onSelectScan={handleSelectHistoryScan}
            onGoToScanner={() => {
              setCurrentResult(null);
              setActiveTab('workspace');
            }}
          />
        )}

        {activeTab === 'methodology' && <MethodologyModal />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/80 py-8 px-4 sm:px-6 lg:px-8 text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <div className="h-6 w-6 rounded-md bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center">
              <Shield className="h-3.5 w-3.5 text-white" />
            </div>
            <span className="font-semibold text-slate-200">ScamShield</span>
            <span className="text-slate-600">|</span>
            <span>PromptWar Hackathon 2026</span>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-4 text-slate-400">
            <span className="flex items-center gap-1">
              <Sparkles className="h-3 w-3 text-cyan-400" />
              Powered by Google Gemini AI
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <Lock className="h-3 w-3 text-emerald-400" />
              Zero Sensitive Data Retention
            </span>
            <span>•</span>
            <span className="flex items-center gap-1">
              <Cpu className="h-3 w-3 text-indigo-400" />
              SSRF & Anti-Injection Guardrails
            </span>
          </div>

          <p className="text-slate-400 text-center sm:text-right">
            Pre-emptive AI Cybersecurity Engine
          </p>
        </div>
      </footer>
    </div>
  );
}

export default App;
