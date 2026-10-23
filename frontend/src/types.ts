export type ScanType = 'text' | 'email' | 'url' | 'screenshot';

export type RiskLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';

export type ThreatType =
  | 'PHISHING'
  | 'CREDENTIAL_HARVESTING'
  | 'IMPERSONATION'
  | 'ADVANCE_FEE_FRAUD'
  | 'MALICIOUS_URL'
  | 'EXTORTION'
  | 'INVESTMENT_SCAM'
  | 'BENIGN'
  | 'UNKNOWN';

export type EvidenceType = 'DETERMINISTIC' | 'EXTERNAL' | 'AI_INTERPRETATION';

export interface IndicatorItem {
  name: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  evidence_type: EvidenceType;
  supporting_quote?: string | null;
}

export interface EvidenceItem {
  source: string;
  evidence_type: EvidenceType;
  detail: string;
  verified: boolean;
}

export interface RecommendationItem {
  priority: number;
  action: string;
  explanation: string;
}

export interface RiskAssessment {
  risk_score: number;
  risk_level: RiskLevel;
  threat_type: ThreatType;
  summary: string;
  confidence_score: number;
  uncertainty_notes: string[];
  is_partial: boolean;
}

export interface OperationalMetrics {
  scan_id: string;
  duration_ms: number;
  deterministic_duration_ms: number;
  ai_duration_ms: number;
  tokens_used?: number | null;
  timestamp: string;
}

export interface ScanResponse {
  scan_id: string;
  scan_type: ScanType;
  target_analyzed: string;
  assessment: RiskAssessment;
  indicators: IndicatorItem[];
  evidence: EvidenceItem[];
  recommendations: RecommendationItem[];
  deterministic_checks: Record<string, any>;
  extracted_text?: string | null;
  metrics: OperationalMetrics;
  created_at: string;
  user_id?: string | null;
}

export interface MetricsSummary {
  total_scans: number;
  successful_scans: number;
  failed_scans: number;
  success_rate_percent: number;
  total_tokens_used: number;
  latency_metrics: {
    avg_ms: number;
    p50_ms: number;
    p95_ms: number;
    avg_deterministic_ms: number;
    avg_ai_ms: number;
  };
  risk_distribution: Record<string, number>;
  scan_type_distribution: Record<string, number>;
  threat_type_distribution: Record<string, number>;
}

export interface HealthStatus {
  status: string;
  app_name: string;
  version: string;
  environment: string;
  gemini_ai: {
    configured: boolean;
    model: string;
  };
  storage: {
    type: string;
  };
}
