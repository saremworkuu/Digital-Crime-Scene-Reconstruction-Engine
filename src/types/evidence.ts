export type EvidenceType = 'linux_auth' | 'web_server' | 'windows_evtx' | 'pcap_summary' | 'generic' | 'generic_json_csv';
export type EvidenceStatus = 'Pending' | 'Hashing' | 'Parsing' | 'Parsed' | 'Failed';

export interface EvidenceFile {
  id: string;
  caseId?: string;
  case_id?: string;
  filename: string;
  type?: EvidenceType;
  file_type?: string;
  sizeBytes?: number;
  size_bytes: number;
  sha256Hash?: string;
  sha256_hash: string;
  uploadedAt?: string;
  uploaded_at: string;
  uploaderName?: string;
  uploader_name?: string;
  uploader_id?: string;
  status: EvidenceStatus | string;
  parserUsed?: string;
  parser_used?: string;
  parseWarnings?: string[];
  parse_errors?: string[];
  eventCount?: number;
  event_count: number;
  raw_sample?: string;
}
