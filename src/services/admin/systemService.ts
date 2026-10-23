/**
 * System Service (Admin-Only)
 * Handles ingestion queue monitoring, parser health metrics, retry dispatching,
 * storage consumption, settings persistence, and demo data reset.
 *
 * NOTE: The `systemAdapter` abstracts telemetry and settings storage.
 */

import { AdminSystemHealth, AdminSettings, AdminQueueJob } from '../../admin/types';
import { SEED_SYSTEM_HEALTH, SEED_SETTINGS } from '../../mocks/admin/seedData';
import { delay, getStored, setStored, resetAllAdminData } from './storageHelper';
import { auditService } from './auditService';

// ============================================================================
// DATA ACCESS ADAPTER (Mock Implementation -> Swappable to Real Backend API)
// ============================================================================
const systemAdapter = {
  async getHealth(): Promise<AdminSystemHealth> {
    await delay(300, 500);
    return getStored<AdminSystemHealth>('system_health', SEED_SYSTEM_HEALTH);
  },

  async saveHealth(health: AdminSystemHealth): Promise<void> {
    await delay(150, 300);
    setStored('system_health', health);
  },

  async getSettings(): Promise<AdminSettings> {
    await delay(200, 400);
    return getStored<AdminSettings>('settings', SEED_SETTINGS);
  },

  async saveSettings(settings: AdminSettings): Promise<void> {
    await delay(200, 400);
    setStored('settings', settings);
  }
};

// ============================================================================
// SERVICE INTERFACE
// ============================================================================
export const systemService = {
  async getSystemHealth(): Promise<AdminSystemHealth> {
    return systemAdapter.getHealth();
  },

  async retryQueueJob(jobId: string): Promise<AdminQueueJob> {
    await delay(450, 700);
    const health = await systemAdapter.getHealth();
    const job = health.queue.find((j) => j.id === jobId);
    if (!job) throw new Error(`Job ${jobId} not found in ingestion queue.`);

    job.status = 'processing';
    delete job.error;
    await systemAdapter.saveHealth(health);

    await auditService.log({
      action: 'INGESTION_JOB_RETRY',
      target_type: 'QUEUE_JOB',
      target_id: jobId,
      details: { file_name: job.file_name, parser_type: job.parser_type }
    });

    // Simulate completion after short delay
    setTimeout(async () => {
      const refreshed = await systemAdapter.getHealth();
      const updatedJob = refreshed.queue.find((j) => j.id === jobId);
      if (updatedJob) {
        updatedJob.status = 'completed';
        await systemAdapter.saveHealth(refreshed);
      }
    }, 2500);

    return job;
  },

  async getSettings(): Promise<AdminSettings> {
    return systemAdapter.getSettings();
  },

  async updateSettings(patch: Partial<AdminSettings>): Promise<AdminSettings> {
    const current = await systemAdapter.getSettings();
    const updated = { ...current, ...patch };
    await systemAdapter.saveSettings(updated);

    await auditService.log({
      action: 'SYSTEM_SETTINGS_UPDATE',
      target_type: 'SETTINGS',
      target_id: 'global-settings',
      details: patch
    });

    return updated;
  },

  async resetDemoData(): Promise<void> {
    await delay(400, 600);
    resetAllAdminData();

    await auditService.log({
      action: 'DEMO_DATA_RESET',
      target_type: 'SYSTEM',
      target_id: 'admin-seed-reset',
      details: { reset_initiated: true }
    });
  }
};
