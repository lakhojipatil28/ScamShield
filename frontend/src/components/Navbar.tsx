import { Shield, Activity, Clock, BookOpen, Sparkles, AlertCircle } from 'lucide-react';
import type { HealthStatus } from '../types';

interface NavbarProps {
  activeTab: 'workspace' | 'dashboard' | 'history' | 'methodology';
  setActiveTab: (tab: 'workspace' | 'dashboard' | 'history' | 'methodology') => void;
  health: HealthStatus | null;
}

export const Navbar = ({ activeTab, setActiveTab, health }: NavbarProps) => {
  const isAiOnline = health?.gemini_ai?.configured;

  return (
    <header className="sticky top-0 z-50 border-b border-slate-800 bg-slate-950/85 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Brand */}
          <div
            className="flex items-center gap-3 cursor-pointer"
            onClick={() => setActiveTab('workspace')}
          >
            <div className="h-10 w-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/20">
              <Shield className="h-6 w-6 text-white" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xl font-bold tracking-tight text-white">ScamShield</span>
                <span className="text-xs px-2 py-0.5 rounded-full font-medium bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  PromptWar
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">AI Cyber Threat Intelligence</p>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 sm:gap-2">
            <button
              onClick={() => setActiveTab('workspace')}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === 'workspace'
                  ? 'bg-slate-800 text-cyan-400 shadow-sm border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Shield className="h-4 w-4" />
              <span>Scanner</span>
            </button>

            <button
              onClick={() => setActiveTab('dashboard')}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === 'dashboard'
                  ? 'bg-slate-800 text-cyan-400 shadow-sm border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Activity className="h-4 w-4" />
              <span className="hidden md:inline">Dashboard</span>
            </button>

            <button
              onClick={() => setActiveTab('history')}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === 'history'
                  ? 'bg-slate-800 text-cyan-400 shadow-sm border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Clock className="h-4 w-4" />
              <span className="hidden md:inline">History</span>
            </button>

            <button
              onClick={() => setActiveTab('methodology')}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
                activeTab === 'methodology'
                  ? 'bg-slate-800 text-cyan-400 shadow-sm border border-slate-700'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <BookOpen className="h-4 w-4" />
              <span className="hidden lg:inline">Methodology</span>
            </button>
          </nav>

          {/* Engine Status Indicator */}
          <div className="flex items-center gap-3">
            {isAiOnline ? (
              <div className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 shadow-sm">
                <Sparkles className="h-3.5 w-3.5 text-emerald-400 animate-pulse" />
                <span className="hidden sm:inline">Gemini 3.8 Flash Online</span>
                <span className="sm:hidden">Gemini AI</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium bg-amber-950/80 text-amber-400 border border-amber-800/60 shadow-sm" title="Operating with Deterministic Rule Engine (GEMINI_API_KEY unconfigured)">
                <AlertCircle className="h-3.5 w-3.5 text-amber-400" />
                <span className="hidden sm:inline">Deterministic Mode</span>
                <span className="sm:hidden">Rule Engine</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};
