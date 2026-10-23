import { useState } from 'react';
import {
  ShieldAlert,
  Info,
  CheckCircle,
  Copy,
  Download,
  RotateCcw,
  Clock,
  Layers,
  Check,
  FileText,
  HelpCircle,
} from 'lucide-react';
import type { ScanResponse, RiskLevel } from '../types';

interface ScanResultViewProps {
  result: ScanResponse;
  onNewScan: () => void;
}

export const ScanResultView = ({ result, onNewScan }: ScanResultViewProps) => {
  const [copied, setCopied] = useState(false);
  const { assessment, indicators, evidence, recommendations, metrics, scan_type, target_analyzed, extracted_text } =
    result;

  const getRiskColor = (level: RiskLevel) => {
    switch (level) {
      case 'CRITICAL':
        return {
          bg: 'bg-red-950/80',
          border: 'border-red-800',
          text: 'text-red-400',
          accent: 'from-red-500 to-rose-600',
          badge: 'bg-red-900/60 text-red-200 border-red-700',
          gauge: 'text-red-500',
        };
      case 'HIGH':
        return {
          bg: 'bg-orange-950/80',
          border: 'border-orange-800',
          text: 'text-orange-400',
          accent: 'from-orange-500 to-amber-600',
          badge: 'bg-orange-900/60 text-orange-200 border-orange-700',
          gauge: 'text-orange-500',
        };
      case 'MODERATE':
        return {
          bg: 'bg-amber-950/80',
          border: 'border-amber-800',
          text: 'text-amber-400',
          accent: 'from-amber-500 to-yellow-600',
          badge: 'bg-amber-900/60 text-amber-200 border-amber-700',
          gauge: 'text-amber-500',
        };
      case 'LOW':
      default:
        return {
          bg: 'bg-emerald-950/80',
          border: 'border-emerald-800',
          text: 'text-emerald-400',
          accent: 'from-emerald-500 to-teal-600',
          badge: 'bg-emerald-900/60 text-emerald-200 border-emerald-700',
          gauge: 'text-emerald-500',
        };
    }
  };

  const colors = getRiskColor(assessment.risk_level);

  const copyReportToClipboard = () => {
    const reportText = `=== SCAMSHIELD SECURITY THREAT REPORT ===
Scan ID: ${result.scan_id}
Date: ${result.created_at}
Scan Type: ${scan_type.toUpperCase()}
Target Analyzed: ${target_analyzed}

[RISK ASSESSMENT]
Risk Level: ${assessment.risk_level}
Composite Risk Score: ${assessment.risk_score} / 100
Primary Threat Category: ${assessment.threat_type}
Confidence: ${Math.round(assessment.confidence_score * 100)}%
Analysis Mode: ${assessment.is_partial ? 'Deterministic Rule Engine Only' : 'Reconciled Gemini AI + Deterministic'}

Summary:
${assessment.summary}

[KEY WARNING SIGNS]
${indicators.map((ind, i) => `${i + 1}. [${ind.severity}] ${ind.name} (${ind.evidence_type})\n   ${ind.description}${ind.supporting_quote ? `\n   Evidence Quote: "${ind.supporting_quote}"` : ''}`).join('\n\n')}

[ACTIONABLE RECOMMENDATIONS]
${recommendations.map((rec, i) => `${i + 1}. [Priority ${rec.priority}] ${rec.action}\n   Why: ${rec.explanation}`).join('\n\n')}

[EVIDENCE RECONCILIATION]
${evidence.map((ev) => `- Source: ${ev.source} [${ev.evidence_type}]: ${ev.detail} (Verified: ${ev.verified})`).join('\n')}

[UNCERTAINTY & CAVEATS]
${assessment.uncertainty_notes.map((note) => `- ${note}`).join('\n')}

[METRICS]
End-to-End Latency: ${metrics.duration_ms} ms
Deterministic Check Time: ${metrics.deterministic_duration_ms} ms
AI Latency: ${metrics.ai_duration_ms} ms
=========================================`;

    navigator.clipboard.writeText(reportText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadJsonReport = () => {
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `scamshield_report_${result.scan_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="max-w-5xl mx-auto px-4 py-8 space-y-6">
      {/* Top Banner if Partial / Offline Mode */}
      {assessment.is_partial && (
        <div className="p-4 rounded-xl bg-amber-950/70 border border-amber-800 text-amber-300 flex items-start gap-3">
          <Info className="h-5 w-5 text-amber-400 shrink-0 mt-0.5" />
          <div className="text-sm">
            <span className="font-semibold">Deterministic Security Engine Report: </span>
            Google Gemini AI was offline or unconfigured; report is generated from high-precision
            deterministic pattern rules without fabricating AI output.
          </div>
        </div>
      )}

      {/* Main Risk Header Card */}
      <div className={`rounded-2xl border ${colors.border} ${colors.bg} p-6 sm:p-8 shadow-2xl relative overflow-hidden backdrop-blur-md`}>
        <div className="flex flex-col md:flex-row items-center md:items-start justify-between gap-6">
          {/* Left: Classification & Summary */}
          <div className="space-y-4 flex-1 text-center md:text-left">
            <div className="flex flex-wrap items-center justify-center md:justify-start gap-2">
              <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${colors.badge}`}>
                {assessment.risk_level} RISK
              </span>
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-slate-900/80 text-slate-300 border border-slate-700">
                Threat: {assessment.threat_type.replace(/_/g, ' ')}
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-medium bg-slate-900/60 text-slate-400 border border-slate-800">
                Type: {scan_type.toUpperCase()}
              </span>
            </div>

            <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
              {assessment.summary}
            </h2>

            <div className="text-xs text-slate-400 bg-slate-950/50 p-3 rounded-xl border border-slate-800/80 font-mono break-all">
              <span className="text-slate-500">Target Inspected: </span>
              {target_analyzed}
            </div>
          </div>

          {/* Right: Score Gauge Widget */}
          <div className="flex flex-col items-center justify-center p-6 rounded-2xl bg-slate-950/80 border border-slate-800 shadow-inner min-w-[200px]">
            <span className="text-xs font-semibold uppercase tracking-widest text-slate-400 mb-1">
              Risk Score
            </span>
            <div className="relative flex items-center justify-center">
              <span className={`text-5xl font-black tracking-tight ${colors.gauge}`}>
                {assessment.risk_score}
              </span>
              <span className="text-sm font-bold text-slate-500 ml-1">/100</span>
            </div>
            <div className="w-28 bg-slate-800 h-2 rounded-full overflow-hidden mt-3">
              <div
                className={`h-full bg-gradient-to-r ${colors.accent}`}
                style={{ width: `${Math.max(5, assessment.risk_score)}%` }}
              />
            </div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400 mt-3">
              <HelpCircle className="h-3.5 w-3.5" />
              <span>Confidence: {Math.round(assessment.confidence_score * 100)}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Extracted Text View (For Screenshots) */}
      {extracted_text && (
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-center gap-2 mb-2 text-sm font-semibold text-slate-200">
            <FileText className="h-4 w-4 text-cyan-400" />
            <span>Extracted Screenshot Transcription (OCR)</span>
          </div>
          <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 font-mono text-xs text-slate-300 max-h-48 overflow-y-auto whitespace-pre-wrap">
            {extracted_text}
          </div>
        </div>
      )}

      {/* Two Column Layout: Warning Signs & Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Warning Signs / Indicators */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-red-400" />
              <h3 className="text-base font-bold text-white">Detected Warning Signs</h3>
            </div>
            <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-slate-800 text-slate-300">
              {indicators.length} found
            </span>
          </div>

          {indicators.length === 0 ? (
            <div className="p-6 rounded-xl border border-dashed border-slate-800 text-center text-slate-500 text-sm">
              No overt malicious indicators detected in this submission.
            </div>
          ) : (
            <div className="space-y-3">
              {indicators.map((ind, i) => (
                <div key={i} className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <span className="text-sm font-semibold text-slate-100">{ind.name}</span>
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                        ind.severity === 'CRITICAL'
                          ? 'bg-red-950 text-red-300 border border-red-800'
                          : ind.severity === 'HIGH'
                          ? 'bg-orange-950 text-orange-300 border border-orange-800'
                          : ind.severity === 'MEDIUM'
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-slate-800 text-slate-300'
                      }`}
                    >
                      {ind.severity}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed">{ind.description}</p>
                  {ind.supporting_quote && (
                    <div className="text-[11px] font-mono text-cyan-300 bg-cyan-950/40 p-2 rounded-lg border border-cyan-900/50">
                      <span className="text-slate-500">Evidence Quote: </span>"{ind.supporting_quote}"
                    </div>
                  )}
                  <div className="text-[10px] text-slate-500 flex items-center gap-1">
                    <span>Source: {ind.evidence_type}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Actionable Recommendations */}
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
          <div className="flex items-center gap-2">
            <CheckCircle className="h-5 w-5 text-emerald-400" />
            <h3 className="text-base font-bold text-white">Recommended Next Steps</h3>
          </div>

          <div className="space-y-3">
            {recommendations.map((rec, i) => (
              <div
                key={i}
                className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 flex items-start gap-3"
              >
                <div
                  className={`h-6 w-6 rounded-full flex items-center justify-center shrink-0 mt-0.5 text-xs font-bold ${
                    rec.priority === 1
                      ? 'bg-red-950 text-red-400 border border-red-800'
                      : rec.priority === 2
                      ? 'bg-amber-950 text-amber-400 border border-amber-800'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {rec.priority}
                </div>
                <div className="space-y-1">
                  <p className="text-sm font-semibold text-slate-100">{rec.action}</p>
                  <p className="text-xs text-slate-400">{rec.explanation}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Evidence Sources & Corroboration Breakdown */}
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 space-y-4">
        <div className="flex items-center gap-2">
          <Layers className="h-5 w-5 text-indigo-400" />
          <h3 className="text-base font-bold text-white">
            Evidence Verification & Model Grounding
          </h3>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-3">
          {evidence.map((ev, i) => (
            <div key={i} className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5 text-xs">
              <div className="flex items-center justify-between text-slate-400">
                <span className="font-semibold text-slate-200">{ev.source}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700">
                  {ev.evidence_type}
                </span>
              </div>
              <p className="text-slate-300 leading-snug">{ev.detail}</p>
              <div className="text-[10px] text-slate-500">
                {ev.verified ? '✓ Verified Fact' : '○ Inferred Interpretation'}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Uncertainty & Limitations Notes */}
      {assessment.uncertainty_notes.length > 0 && (
        <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-400 space-y-1.5">
          <p className="font-semibold text-slate-300 flex items-center gap-1.5">
            <Info className="h-3.5 w-3.5 text-cyan-400" /> Uncertainty Disclosures & Limitations:
          </p>
          <ul className="list-disc list-inside space-y-1 pl-1">
            {assessment.uncertainty_notes.map((note, i) => (
              <li key={i}>{note}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Operational Metrics Snippet */}
      <div className="p-3.5 rounded-xl bg-slate-950/40 border border-slate-800/80 flex flex-wrap items-center justify-between text-xs text-slate-500 gap-3">
        <div className="flex items-center gap-4">
          <span className="flex items-center gap-1">
            <Clock className="h-3.5 w-3.5 text-slate-400" /> Latency: {metrics.duration_ms} ms
          </span>
          <span className="hidden sm:inline">•</span>
          <span>Deterministic: {metrics.deterministic_duration_ms} ms</span>
          <span className="hidden sm:inline">•</span>
          <span>AI Request: {metrics.ai_duration_ms} ms</span>
          {metrics.tokens_used && (
            <>
              <span className="hidden sm:inline">•</span>
              <span>Tokens: {metrics.tokens_used}</span>
            </>
          )}
        </div>
        <span className="font-mono text-[11px]">ID: {result.scan_id}</span>
      </div>

      {/* Report Actions */}
      <div className="flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-slate-800">
        <button
          onClick={onNewScan}
          className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-700 bg-slate-800 hover:bg-slate-700 text-white text-sm font-medium transition-colors cursor-pointer"
        >
          <RotateCcw className="h-4 w-4" />
          <span>Scan Another Item</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={copyReportToClipboard}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-slate-700 bg-slate-900 hover:bg-slate-800 text-slate-200 text-sm font-medium transition-colors cursor-pointer"
          >
            {copied ? (
              <>
                <Check className="h-4 w-4 text-emerald-400" />
                <span className="text-emerald-400">Copied!</span>
              </>
            ) : (
              <>
                <Copy className="h-4 w-4" />
                <span>Copy Report</span>
              </>
            )}
          </button>

          <button
            onClick={downloadJsonReport}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-cyan-800/80 bg-cyan-950/60 hover:bg-cyan-900/80 text-cyan-300 text-sm font-medium transition-colors cursor-pointer"
          >
            <Download className="h-4 w-4" />
            <span>Download JSON</span>
          </button>
        </div>
      </div>
    </div>
  );
};
