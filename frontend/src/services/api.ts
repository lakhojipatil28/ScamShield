import type {
  ScanResponse,
  MetricsSummary,
  HealthStatus,
  ScanType,
  RiskLevel,
} from '../types';

const API_BASE = '/api/v1';

export async function checkHealth(): Promise<HealthStatus> {
  const res = await fetch('/health');
  if (!res.ok) throw new Error('Health check failed');
  return res.json();
}

export async function getMetrics(): Promise<MetricsSummary> {
  const res = await fetch(`${API_BASE}/metrics`);
  if (!res.ok) throw new Error('Failed to fetch metrics');
  return res.json();
}

export async function scanText(content: string, context?: string): Promise<ScanResponse> {
  const res = await fetch(`${API_BASE}/scan/text`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content, context }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(err.detail || 'Text scan failed');
  }
  return res.json();
}

export async function scanEmail(
  body: string,
  sender?: string,
  subject?: string,
  context?: string
): Promise<ScanResponse> {
  const res = await fetch(`${API_BASE}/scan/email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ body, sender, subject, context }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(err.detail || 'Email scan failed');
  }
  return res.json();
}

export async function scanUrl(url: string): Promise<ScanResponse> {
  const res = await fetch(`${API_BASE}/scan/url`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(err.detail || 'URL scan failed');
  }
  return res.json();
}

export async function scanScreenshot(file: File): Promise<ScanResponse> {
  const formData = new FormData();
  formData.append('file', file);

  const res = await fetch(`${API_BASE}/scan/screenshot`, {
    method: 'POST',
    body: formData,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Upload scan failed' }));
    throw new Error(err.detail || 'Screenshot scan failed');
  }
  return res.json();
}

export async function listScans(
  limit: number = 50,
  offset: number = 0,
  riskLevel?: RiskLevel,
  scanType?: ScanType
): Promise<ScanResponse[]> {
  const params = new URLSearchParams();
  params.append('limit', limit.toString());
  params.append('offset', offset.toString());
  if (riskLevel) params.append('risk_level', riskLevel);
  if (scanType) params.append('scan_type', scanType);

  const res = await fetch(`${API_BASE}/scans?${params.toString()}`);
  if (!res.ok) throw new Error('Failed to fetch scans');
  return res.json();
}

export async function deleteScan(scanId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/scans/${scanId}`, {
    method: 'DELETE',
  });
  if (!res.ok) throw new Error('Failed to delete scan');
}
