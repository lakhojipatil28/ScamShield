import React, { useState, useEffect } from 'react';
import {
  Clock,
  Search,
  Filter,
  Trash2,
  ExternalLink,
  RefreshCw,
} from 'lucide-react';
import type { ScanResponse, RiskLevel, ScanType } from '../types';
import { listScans, deleteScan } from '../services/api';

interface ScanHistoryProps {
  onSelectScan: (scan: ScanResponse) => void;
  onGoToScanner: () => void;
}

export const ScanHistory: React.FC<ScanHistoryProps> = ({ onSelectScan, onGoToScanner }) => {
  const [scans, setScans] = useState<ScanResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedRisk, setSelectedRisk] = useState<string>('ALL');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [refreshTrigger, setRefreshTrigger] = useState(0);

  useEffect(() => {
    let isCurrent = true;
    const run = async () => {
      try {
        const riskParam = selectedRisk !== 'ALL' ? (selectedRisk as RiskLevel) : undefined;
        const typeParam = selectedType !== 'ALL' ? (selectedType as ScanType) : undefined;
        const data = await listScans(100, 0, riskParam, typeParam);
        if (isCurrent) {
          setScans(data);
          setIsLoading(false);
        }
      } catch (err: unknown) {
        if (isCurrent) {
          console.error('Failed to fetch history:', err);
          setIsLoading(false);
        }
      }
    };
    run();
    return () => {
      isCurrent = false;
    };
  }, [selectedRisk, selectedType, refreshTrigger]);

  const handleDelete = async (scanId: string) => {
    if (!window.confirm('Are you sure you want to permanently delete this scan record?')) {
      return;
    }
    setDeletingId(scanId);
    try {
      await deleteScan(scanId);
      setScans((prev) => prev.filter((s) => s.scan_id !== scanId));
    } catch (err: unknown) {
      console.error('Failed to delete scan record:', err);
      alert('Failed to delete scan record');
    } finally {
      setDeletingId(null);
    }
  };

  // Client-side text search filter
  const filteredScans = scans.filter((s) => {
    if (!searchTerm.trim()) return true;
    const term = searchTerm.toLowerCase();
    return (
      s.target_analyzed.toLowerCase().includes(term) ||
      s.assessment.threat_type.toLowerCase().includes(term) ||
      s.assessment.summary.toLowerCase().includes(term) ||
      s.scan_id.toLowerCase().includes(term)
    );
  });

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-extrabold text-white tracking-tight">Audit & Scan History</h2>
          <p className="text-sm text-slate-400">
            View, inspect, and manage previously analyzed security scans.
          </p>
        </div>
        <button
          onClick={() => {
            setIsLoading(true);
            setRefreshTrigger((prev) => prev + 1);
          }}
          disabled={isLoading}
          aria-label="Refresh scan history"
          className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-800 bg-slate-900 text-xs font-medium text-slate-300 hover:bg-slate-800 focus-visible:ring-2 focus-visible:ring-cyan-500 transition-colors cursor-pointer"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-2xl border border-slate-800 bg-slate-900/60 flex flex-col md:flex-row gap-3 items-center justify-between">
        {/* Search Input */}
        <div className="relative w-full md:w-80">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
            <Search className="h-4 w-4" />
          </div>
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search keywords, threat, or ID..."
            aria-label="Search scan history"
            className="w-full pl-9 pr-3 py-2 rounded-xl border border-slate-700 bg-slate-950/80 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus-visible:ring-2 focus-visible:ring-cyan-500"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2 w-full md:w-auto">
          <label htmlFor="risk-filter" className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="h-3.5 w-3.5" />
            <span>Risk:</span>
          </label>
          <select
            id="risk-filter"
            value={selectedRisk}
            onChange={(e) => {
              setIsLoading(true);
              setSelectedRisk(e.target.value);
            }}
            aria-label="Filter by risk level"
            className="rounded-xl border border-slate-700 bg-slate-950/80 px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Risk Levels</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MODERATE">Moderate</option>
            <option value="LOW">Low</option>
          </select>

          <label htmlFor="type-filter" className="flex items-center gap-1.5 text-xs text-slate-400 ml-2">
            <span>Type:</span>
          </label>
          <select
            id="type-filter"
            value={selectedType}
            onChange={(e) => {
              setIsLoading(true);
              setSelectedType(e.target.value);
            }}
            aria-label="Filter by scan type"
            className="rounded-xl border border-slate-700 bg-slate-950/80 px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Scan Types</option>
            <option value="text">Message / SMS</option>
            <option value="email">Email / Job</option>
            <option value="url">URL</option>
            <option value="screenshot">Screenshot</option>
          </select>
        </div>
      </div>

      {/* Scans List / Table */}
      {filteredScans.length === 0 ? (
        <div className="p-12 text-center rounded-2xl border border-dashed border-slate-800 bg-slate-900/30 text-slate-400 space-y-3">
          <Clock className="h-8 w-8 mx-auto text-slate-500" />
          <h3 className="text-base font-semibold text-slate-300">No Scan Records Found</h3>
          <p className="text-xs text-slate-500 max-w-md mx-auto">
            {searchTerm || selectedRisk !== 'ALL' || selectedType !== 'ALL'
              ? 'No scans matched your search criteria. Try resetting the filters.'
              : 'You have not conducted any security scans yet.'}
          </p>
          <button
            onClick={onGoToScanner}
            className="mt-2 px-4 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white focus-visible:ring-2 focus-visible:ring-cyan-500 transition-colors cursor-pointer"
          >
            Start a New Scan
          </button>
        </div>
      ) : (
        <div className="space-y-3" role="feed" aria-label="Scan history list">
          {filteredScans.map((s) => (
            <article
              key={s.scan_id}
              className="p-4 rounded-2xl border border-slate-800 bg-slate-900/70 hover:bg-slate-800/60 transition-all flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
            >
              {/* Left Column: Badges & Preview */}
              <div className="space-y-2 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                      s.assessment.risk_level === 'CRITICAL'
                        ? 'bg-red-950 text-red-300 border border-red-800'
                        : s.assessment.risk_level === 'HIGH'
                        ? 'bg-orange-950 text-orange-300 border border-orange-800'
                        : s.assessment.risk_level === 'MODERATE'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                        : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                    }`}
                  >
                    {s.assessment.risk_level} • {s.assessment.risk_score}/100
                  </span>
                  <span className="text-xs font-semibold text-slate-200">
                    {s.assessment.threat_type.replace(/_/g, ' ')}
                  </span>
                  <span className="text-[11px] uppercase px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800">
                    {s.scan_type}
                  </span>
                  {s.assessment.is_partial && (
                    <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800">
                      Rule Engine Only
                    </span>
                  )}
                </div>

                <p className="text-xs text-slate-300 font-mono line-clamp-1 bg-slate-950/50 p-2 rounded-lg border border-slate-800/60">
                  {s.target_analyzed}
                </p>

                <p className="text-xs text-slate-400 line-clamp-1">{s.assessment.summary}</p>

                <div className="flex items-center gap-3 text-[11px] text-slate-500">
                  <span>
                    {new Date(s.created_at).toLocaleDateString()} at{' '}
                    {new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </span>
                  <span>•</span>
                  <span>Latency: {s.metrics.duration_ms} ms</span>
                  <span>•</span>
                  <span className="font-mono">{s.scan_id}</span>
                </div>
              </div>

              {/* Right Column: Actions */}
              <div className="flex items-center gap-2 self-end md:self-center">
                <button
                  onClick={() => onSelectScan(s)}
                  aria-label={`View report for scan ${s.scan_id}`}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl border border-cyan-800/80 bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 text-xs font-medium focus-visible:ring-2 focus-visible:ring-cyan-500 transition-colors cursor-pointer"
                >
                  <ExternalLink className="h-3.5 w-3.5" />
                  <span>View Report</span>
                </button>
                <button
                  onClick={() => handleDelete(s.scan_id)}
                  disabled={deletingId === s.scan_id}
                  aria-label={`Delete record ${s.scan_id}`}
                  className="p-2 rounded-xl border border-slate-800 bg-slate-950 text-slate-500 hover:text-red-400 hover:border-red-900/60 focus-visible:ring-2 focus-visible:ring-red-500 transition-colors cursor-pointer"
                  title="Delete record"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
};
