/**
 * Evidence Service (Admin-Only)
 * Handles evidence inspection, cryptographic SHA-256 integrity verification,
 * and deletion protection when cases are preserved under legal hold.
 *
 * NOTE: The `evidenceAdapter` abstracts storage. To point to an S3/MinIO bucket or FastAPI
 * evidence endpoint, update only the adapter methods.
 */

import { AdminEvidence } from '../../admin/types';
import { SEED_EVIDENCE } from '../../mocks/admin/seedData';
import { delay, getStored, setStored } from './storageHelper';
import { casesService } from './casesService';
import { auditService } from './auditService';

// ============================================================================
// DATA ACCESS ADAPTER (Mock Implementation -> Swappable to Real Backend API)
// ============================================================================
const evidenceAdapter = {
  async getAll(): Promise<AdminEvidence[]> {
    await delay(300, 500);
    return getStored<AdminEvidence[]>('evidence', SEED_EVIDENCE);
  },

  async saveAll(evidence: AdminEvidence[]): Promise<void> {
    await delay(200, 400);
    setStored('evidence', evidence);
  }
};

// ============================================================================
// SERVICE INTERFACE
// ============================================================================
export const evidenceService = {
  async getEvidence(filters?: {
    case_id?: string;
    type?: string;
    status?: string;
    search?: string;
  }): Promise<AdminEvidence[]> {
    const list = await evidenceAdapter.getAll();
    return list.filter((item) => {
      if (filters?.case_id && filters.case_id !== 'all' && item.case_id !== filters.case_id) {
        return false;
      }
      if (filters?.type && filters.type !== 'all' && item.type !== filters.type) {
        return false;
      }
      if (filters?.status && filters.status !== 'all' && item.parsing_status !== filters.status) {
        return false;
      }
      if (filters?.search) {
        const q = filters.search.toLowerCase();
        return (
          item.file_name.toLowerCase().includes(q) ||
          item.uploader.toLowerCase().includes(q) ||
          item.sha256.toLowerCase().includes(q)
        );
      }
      return true;
    });
  },

  async verifyIntegrity(id: string): Promise<{
    verified: boolean;
    computed_sha256: string;
    expected_sha256: string;
    match: boolean;
  }> {
    await delay(400, 650);
    const list = await evidenceAdapter.getAll();
    const item = list.find((e) => e.id === id);
    if (!item) throw new Error(`Evidence ${id} not found.`);

    // Mock verification: match if expected === current sha256
    const match = item.sha256 === item.expected_sha256;
    item.verified = match;
    await evidenceAdapter.saveAll(list);

    await auditService.log({
      action: 'EVIDENCE_VERIFY',
      target_type: 'EVIDENCE',
      target_id: id,
      case_id: item.case_id,
      details: {
        file_name: item.file_name,
        match,
        sha256: item.sha256
      }
    });

    return {
      verified: true,
      computed_sha256: item.sha256,
      expected_sha256: item.expected_sha256,
      match
    };
  },

  async deleteEvidence(id: string): Promise<void> {
    const list = await evidenceAdapter.getAll();
    const item = list.find((e) => e.id === id);
    if (!item) throw new Error(`Evidence ${id} not found.`);

    // Check Legal Hold enforcement on associated case
    const parentCase = await casesService.getCaseById(item.case_id);
    if (parentCase?.legal_hold) {
      throw new Error(`Deletion Blocked: Case "${parentCase.title}" is currently locked under Legal Hold.`);
    }

    const filtered = list.filter((e) => e.id !== id);
    await evidenceAdapter.saveAll(filtered);

    await auditService.log({
      action: 'EVIDENCE_DELETE',
      target_type: 'EVIDENCE',
      target_id: id,
      case_id: item.case_id,
      details: {
        file_name: item.file_name,
        sha256: item.sha256
      }
    });
  }
};
