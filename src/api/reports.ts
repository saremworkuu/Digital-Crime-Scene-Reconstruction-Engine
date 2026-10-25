import { apiClient } from './client';
import { ForensicReport } from '../types';

export interface ReportHistoryItem {
  id: string;
  case_id: string;
  title: string;
  version: string;
  generator_name?: string;
  generated_at: string;
}

/** Extended backend report shape (superset of ForensicReport) */
export interface BackendReport extends ForensicReport {
  id: string;
  case_id: string;
  case_name: string;
  generated_at: string;
  generator_name: string;
  generator_role: string;
  version: string;
  status: string;           // "DRAFT" | "APPROVED"
  draft_notice?: string;
  classification: string;
  executive_summary: string;
  report_hash: string;

  evidence_manifest: Array<{
    filename: string;
    sha256_hash: string;
    size_bytes: number;
    event_count: number;
    uploaded_at: string;
    uploader: string;
  }>;
  chain_of_custody: Array<{
    filename: string;
    sha256_hash: string;
    hash_status: string;    // "recorded (not re-verified)" | "match" | "MISMATCH"
    uploaded_by: string;
    uploaded_at: string;
    event_count: number;
  }>;
  chain_of_custody_note: string;

  mitre_coverage: Array<{
    id: string;
    rule_name: string;
    rule_id?: string;
    mitre_technique?: string;
    mitre_techniques_all?: string[];
    mitre_tactic?: string;
    severity: string;
    first_seen?: string | null; // first linked event_time; absent if no matching event is available
    last_seen?: string;
    target_host?: string;
    host?: string;
    description?: string;
  }>;

  attack_timeline_summary: Array<{
    timestamp: string;
    severity: string;
    host: string;
    user: string;
    action: string;
    src_ip?: string;
    mitre_technique?: string;
    corroborated_by?: string[];
  }>;

  compromised_assets: {
    hosts: string[];
    users: string[];
    adversary_infrastructure: string[];
    observed_ips?: string[];
    dwell_time: string;
  };

  remediation: Array<{ action: string; finding_refs: string } | string>;
  recommendations?: string[];
  methodology?: string;
  limitations?: string;
  rule_set_version?: string;
}

export const reportsApi = {
  /** Load the latest saved report, creating the initial saved version only if none exists. */
  latest: async (caseId: string) => {
    return apiClient.get<BackendReport>(`/reports/${caseId}/report`);
  },

  /** Generate a new version, save it, return the full report data */
  generate: async (caseId: string) => {
    return apiClient.post<BackendReport>(`/reports/${caseId}/reports/generate`);
  },

  /** List saved report versions for a case (newest first) */
  list: async (caseId: string) => {
    return apiClient.get<ReportHistoryItem[]>(`/reports/${caseId}/reports`);
  },

  /** Load one saved report version for viewing. */
  getSaved: async (caseId: string, reportId: string) => {
    return apiClient.get<BackendReport>(`/reports/${caseId}/reports/${reportId}/data`);
  },

  /** Delete one saved report version. */
  deleteSaved: async (caseId: string, reportId: string) => {
    return apiClient.delete<{ message: string }>(`/reports/${caseId}/reports/${reportId}`);
  },

  /** Current-version PDF (always freshly compiled) */
  exportPdf: async (caseId: string) => {
    return apiClient.getBlob(`/reports/${caseId}/reports/pdf`);
  },

  /** Current-version HTML (always freshly compiled) */
  exportHtml: async (caseId: string) => {
    return apiClient.getText(`/reports/${caseId}/reports/html`);
  },

  /** Download a specific saved version as PDF */
  downloadSavedPdf: async (caseId: string, reportId: string) => {
    return apiClient.getBlob(`/reports/${caseId}/reports/${reportId}/pdf`);
  },

  /** Download a specific saved version as HTML */
  downloadSavedHtml: async (caseId: string, reportId: string) => {
    return apiClient.getText(`/reports/${caseId}/reports/${reportId}/html`);
  },
};
