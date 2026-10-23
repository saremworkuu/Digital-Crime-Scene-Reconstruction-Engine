/**
 * Cases Service (Admin-Only)
 * Handles case status updates, investigator assignment, archiving, and legal hold preservation.
 *
 * NOTE: The `casesAdapter` abstracts storage. To point to a live backend,
 * replace only the methods in the adapter.
 */

import { AdminCase, CaseStatus } from '../../admin/types';
import { SEED_CASES } from '../../mocks/admin/seedData';
import { delay, getStored, setStored } from './storageHelper';
import { auditService } from './auditService';

// ============================================================================
// DATA ACCESS ADAPTER (Mock Implementation -> Swappable to Real Backend API)
// ============================================================================
const casesAdapter = {
  async getAll(): Promise<AdminCase[]> {
    await delay(300, 500);
    return getStored<AdminCase[]>('cases', SEED_CASES);
  },

  async saveAll(cases: AdminCase[]): Promise<void> {
    await delay(200, 400);
    setStored('cases', cases);
  }
};

// ============================================================================
// SERVICE INTERFACE
// ============================================================================
export const casesService = {
  async getCases(filters?: { status?: string; search?: string; archived?: boolean }): Promise<AdminCase[]> {
    const list = await casesAdapter.getAll();
    return list.filter((c) => {
      if (filters?.status && filters.status !== 'all' && c.status !== filters.status) {
        return false;
      }
      if (typeof filters?.archived === 'boolean' && c.is_archived !== filters.archived) {
        return false;
      }
      if (filters?.search) {
        const q = filters.search.toLowerCase();
        return (
          c.title.toLowerCase().includes(q) ||
          c.owner.toLowerCase().includes(q) ||
          c.description.toLowerCase().includes(q) ||
          c.assigned_investigators.some((inv) => inv.toLowerCase().includes(q))
        );
      }
      return true;
    });
  },

  async getCaseById(id: string): Promise<AdminCase | null> {
    const list = await casesAdapter.getAll();
    return list.find((c) => c.id === id) || null;
  },

  async updateStatus(id: string, newStatus: CaseStatus): Promise<AdminCase> {
    const list = await casesAdapter.getAll();
    const item = list.find((c) => c.id === id);
    if (!item) throw new Error(`Case ${id} not found.`);

    const oldStatus = item.status;
    item.status = newStatus;
    await casesAdapter.saveAll(list);

    await auditService.log({
      action: 'CASE_STATUS_UPDATE',
      target_type: 'CASE',
      target_id: id,
      case_id: id,
      details: { from: oldStatus, to: newStatus }
    });

    return item;
  },

  async assignInvestigators(id: string, investigators: string[]): Promise<AdminCase> {
    const list = await casesAdapter.getAll();
    const item = list.find((c) => c.id === id);
    if (!item) throw new Error(`Case ${id} not found.`);

    item.assigned_investigators = investigators;
    await casesAdapter.saveAll(list);

    await auditService.log({
      action: 'CASE_ASSIGNMENT',
      target_type: 'CASE',
      target_id: id,
      case_id: id,
      details: { assigned_investigators: investigators }
    });

    return item;
  },

  async toggleLegalHold(id: string, legalHold: boolean, reason?: string): Promise<AdminCase> {
    const list = await casesAdapter.getAll();
    const item = list.find((c) => c.id === id);
    if (!item) throw new Error(`Case ${id} not found.`);

    item.legal_hold = legalHold;
    await casesAdapter.saveAll(list);

    await auditService.log({
      action: legalHold ? 'CASE_LEGAL_HOLD_SET' : 'CASE_LEGAL_HOLD_REMOVED',
      target_type: 'CASE',
      target_id: id,
      case_id: id,
      details: { legal_hold: legalHold, reason: reason || 'Admin command directive' }
    });

    return item;
  },

  async toggleArchive(id: string, isArchived: boolean): Promise<AdminCase> {
    const list = await casesAdapter.getAll();
    const item = list.find((c) => c.id === id);
    if (!item) throw new Error(`Case ${id} not found.`);

    item.is_archived = isArchived;
    await casesAdapter.saveAll(list);

    await auditService.log({
      action: isArchived ? 'CASE_ARCHIVE' : 'CASE_UNARCHIVE',
      target_type: 'CASE',
      target_id: id,
      case_id: id,
      details: { is_archived: isArchived }
    });

    return item;
  }
};
