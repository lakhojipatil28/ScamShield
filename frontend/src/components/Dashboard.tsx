import { useEffect, useState } from 'react';
import {
  Activity,
  ShieldAlert,
  Clock,
  CheckCircle2,
  PieChart as PieIcon,
  BarChart2,
  ArrowRight,
  RefreshCw,
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import type { MetricsSummary, ScanResponse } from '../types';
import { getMetrics, listScans } from '../services/api';

interface DashboardProps {
  onSelectScan: (scan: ScanResponse) => void;
  onGoToScanner: () => void;
}

const RISK_COLORS = {
  LOW: '#10b981',      // Emerald
  MODERATE: '#f59e0b', // Amber
  HIGH: '#f97316',     // Orange
  CRITICAL: '#ef4444', // Red
};

export const Dashboard = ({ onSelectScan, onGoToScanner }: DashboardProps) => {
  const [metrics, setMetrics] = useState<MetricsSummary | null>(null);
  const [recentScans, setRecentScans] = useState<ScanResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [m, scans] = await Promise.all([getMetrics(), listScans(10)]);
      setMetrics(m);
      setRecentScans(scans);
    } catch (e) {
      console.error('Failed to load dashboard data:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const riskPieData = metrics
    ? Object.entries(metrics.risk_distribution).map(([name, value]) => ({
        name,
        value,
      }))
    : [];

  const threatBarData = metrics
    ? Object.entries(metrics.threat_type_distribution).map(([name, value]) => ({
        name: name.replace(/_/g, ' ').substring(0, 14),
        count: value,
      }))
    : [];

  const highRiskTotal = metrics
    ? (metrics.risk_distribution['HIGH'] || 0) + (metrics.risk_distribution['CRITICAL'] || 0)
    : 0;

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-extrabold text-white tracking-tight">Security Telemetry Dashboard</h2>
          <p className="text-sm text-slate-400">
            Real-time operational metrics, detection accuracy, and persistent audit telemetry.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-2 rounded-xl border border-slate-800 bg-slate-900 text-xs font-medium text-slate-300 hover:bg-slate-800 transition-colors cursor-pointer"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
          <button
            onClick={onGoToScanner}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white shadow-sm transition-colors cursor-pointer"
          >
            <span>New Scan</span>
            <ArrowRight className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/70 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Total Scans Conducted</span>
            <Activity className="h-4 w-4 text-cyan-400" />
          </div>
          <p className="text-3xl font-extrabold text-white">{metrics?.total_scans ?? 0}</p>
          <p className="text-xs text-slate-500">Across SMS, Email, URL & OCR</p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/70 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">High & Critical Threats</span>
            <ShieldAlert className="h-4 w-4 text-red-400" />
          </div>
          <p className="text-3xl font-extrabold text-red-400">{highRiskTotal}</p>
          <p className="text-xs text-slate-500">
            {metrics?.total_scans
              ? `${Math.round((highRiskTotal / metrics.total_scans) * 100)}% of submitted scans`
              : 'No scans recorded'}
          </p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/70 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Avg Scan Latency</span>
            <Clock className="h-4 w-4 text-indigo-400" />
          </div>
          <p className="text-3xl font-extrabold text-white">
            {metrics?.latency_metrics.avg_ms ? `${metrics.latency_metrics.avg_ms} ms` : '0 ms'}
          </p>
          <p className="text-xs text-slate-500">
            Deterministic: {metrics?.latency_metrics.avg_deterministic_ms ?? 0} ms
          </p>
        </div>

        <div className="p-5 rounded-2xl border border-slate-800 bg-slate-900/70 space-y-2">
          <div className="flex items-center justify-between text-slate-400">
            <span className="text-xs font-semibold uppercase tracking-wider">Scan Success Rate</span>
            <CheckCircle2 className="h-4 w-4 text-emerald-400" />
          </div>
          <p className="text-3xl font-extrabold text-emerald-400">
            {metrics?.success_rate_percent ?? 100}%
          </p>
          <p className="text-xs text-slate-500">Zero unhandled execution failures</p>
        </div>
      </div>

      {/* Visual Analytics Row: Risk Distribution Donut & Threat Categories Bar */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Risk Distribution Donut */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <PieIcon className="h-5 w-5 text-cyan-400" />
              <h3 className="text-base font-bold text-white">Risk Band Distribution</h3>
            </div>
            <span className="text-xs text-slate-500">Observed Scans</span>
          </div>

          {metrics?.total_scans === 0 ? (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-sm border border-dashed border-slate-800 rounded-xl">
              <p>No scans recorded yet.</p>
              <button
                onClick={onGoToScanner}
                className="mt-2 text-xs text-cyan-400 hover:underline cursor-pointer"
              >
                Run your first security scan
              </button>
            </div>
          ) : (
            <div className="h-64 flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={riskPieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={85}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {riskPieData.map((entry, index) => (
                      <Cell
                        key={`cell-${index}`}
                        fill={RISK_COLORS[entry.name as keyof typeof RISK_COLORS] || '#64748b'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      color: '#f8fafc',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-2 ml-4">
                {riskPieData.map((d) => (
                  <div key={d.name} className="flex items-center gap-2 text-xs">
                    <div
                      className="w-3 h-3 rounded-full"
                      style={{
                        backgroundColor:
                          RISK_COLORS[d.name as keyof typeof RISK_COLORS] || '#64748b',
                      }}
                    />
                    <span className="text-slate-300 font-medium">{d.name}:</span>
                    <span className="text-slate-400">{d.value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Threat Categories Bar Chart */}
        <div className="p-6 rounded-2xl border border-slate-800 bg-slate-900/60 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <BarChart2 className="h-5 w-5 text-indigo-400" />
              <h3 className="text-base font-bold text-white">Threats by Classification</h3>
            </div>
            <span className="text-xs text-slate-500">Categories</span>
          </div>

          {threatBarData.length === 0 ? (
            <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-sm border border-dashed border-slate-800 rounded-xl">
              <p>No threat categories detected yet.</p>
            </div>
          ) : (
            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={threatBarData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
                  <XAxis dataKey="name" stroke="#64748b" fontSize={11} angle={-25} textAnchor="end" />
                  <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      color: '#f8fafc',
                    }}
                  />
                  <Bar dataKey="count" fill="#6366f1" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* Recent Scans Table */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-base font-bold text-white">Recent Security Audits</h3>
          <span className="text-xs text-slate-500">Latest 10 records</span>
        </div>

        {recentScans.length === 0 ? (
          <div className="p-8 text-center border border-dashed border-slate-800 rounded-xl text-slate-500 text-sm">
            No scans recorded in history. Run a scan above to see results here.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                <tr>
                  <th className="p-3">Risk Level</th>
                  <th className="p-3">Score</th>
                  <th className="p-3">Type</th>
                  <th className="p-3">Threat Category</th>
                  <th className="p-3">Inspected Snippet</th>
                  <th className="p-3">Date</th>
                  <th className="p-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/80">
                {recentScans.map((s) => (
                  <tr key={s.scan_id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="p-3 font-semibold">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          s.assessment.risk_level === 'CRITICAL'
                            ? 'bg-red-950 text-red-300 border border-red-800'
                            : s.assessment.risk_level === 'HIGH'
                            ? 'bg-orange-950 text-orange-300 border border-orange-800'
                            : s.assessment.risk_level === 'MODERATE'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        }`}
                      >
                        {s.assessment.risk_level}
                      </span>
                    </td>
                    <td className="p-3 font-mono font-bold text-slate-200">
                      {s.assessment.risk_score}
                    </td>
                    <td className="p-3 uppercase text-slate-400">{s.scan_type}</td>
                    <td className="p-3 text-slate-300 font-medium">
                      {s.assessment.threat_type.replace(/_/g, ' ')}
                    </td>
                    <td className="p-3 text-slate-400 max-w-xs truncate font-mono">
                      {s.target_analyzed}
                    </td>
                    <td className="p-3 text-slate-500 whitespace-nowrap">
                      {new Date(s.created_at).toLocaleDateString()} {new Date(s.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </td>
                    <td className="p-3 text-right">
                      <button
                        onClick={() => onSelectScan(s)}
                        className="text-cyan-400 hover:text-cyan-300 font-medium cursor-pointer"
                      >
                        Open Report
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
