export type CaseStatus = 'Open' | 'In Progress' | 'Closed';

export interface Case {
  id: string;
  name: string;
  description: string;
  status: CaseStatus;
  leadInvestigator?: string;
  lead_investigator?: string;
  owner_id?: string;
  ownerId?: string;
  owner_name?: string;
  ownerName?: string;
  evidenceCount?: number;
  evidence_count: number;
  eventCount?: number;
  event_count: number;
  detectionCount?: number;
  detection_count: number;
  criticalDetections?: number;
  critical_detections?: number;
  critical_detection_count?: number;
  tags: string[];
  createdAt?: string;
  created_at: string;
  updatedAt?: string;
  updated_at: string;
  time_start?: string;
  time_end?: string;
  assigned_users?: string[];
}
