/**
 * System Service (Admin-Only)
 * Handles ingestion queue monitoring, parser health metrics, retry dispatching,
 * storage consumption, settings persistence, and demo data reset.
 *
 * Fully integrated with live FastAPI endpoints (/api/v1/admin/system)
 * with graceful fallback to preserved mock seed data.
 */

import { AdminSystemHealth, AdminSettings, AdminQueueJob } from '../../admin/types';
import { SEED_SYSTEM_HEALTH, SEED_SETTINGS } from '../../mocks/admin/seedData';
import { delay, getStored, setStored, resetAllAdminData } from './storageHelper';
import { auditService } from './auditService';
import { apiClient } from '../../api';

// ============================================================================
// DATA ACCESS ADAPTER (Real Backend API with Mock Preserving Fallback)
// ============================================================================
const systemAdapter = {
  async getHealth(): Promise<AdminSystemHealth> {
    try {
      const res = await apiClient.get<AdminSystemHealth>('/admin/system/health');
      if (res.data?.parsers && Array.isArray(res.data.parsers)) {
        setStored('system_health', res.data);
        return res.data;
      }
    } catch (err) {
      console.warn('Backend live health API fallback to local data:', err);
    }
    await delay(150, 300);
    return getStored<AdminSystemHealth>('system_health', SEED_SYSTEM_HEALTH);
  },

  async saveHealth(health: AdminSystemHealth): Promise<void> {
    setStored('system_health', health);
  },

  async getSettings(): Promise<AdminSettings> {
    try {
      const res = await apiClient.get<AdminSettings>('/admin/system/settings');
      if (res.data?.org_name) {
        setStored('settings', res.data);
        return res.data;
      }
    } catch (err) {
      console.warn('Backend live settings API fallback to local data:', err);
    }
    await delay(150, 300);
    return getStored<AdminSettings>('settings', SEED_SETTINGS);
  },

  async saveSettings(settings: AdminSettings): Promise<void> {
    try {
      await apiClient.patch('/admin/system/settings', settings);
    } catch (err) {
      console.warn('Live API settings update error, proceeding with local save:', err);
    }
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
    try {
      const res = await apiClient.post<AdminQueueJob>(`/admin/system/queue/${jobId}/retry`);
      if (res.data) {
        return res.data;
      }
    } catch {
      // fallback
    }

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
    try {
      await apiClient.post('/admin/system/reset-demo');
    } catch (err) {
      console.warn('Live API reset demo error, proceeding with local reset:', err);
    }

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
