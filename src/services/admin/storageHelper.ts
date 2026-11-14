/**
 * Admin LocalStorage Persistence & Delay Helpers
 * Prefixed with `dcsre_admin_` to isolate mock admin data from live forensic stores.
 */

import {
  SEED_USERS,
  SEED_CASES,
  SEED_EVIDENCE,
  SEED_SIGMA_RULES,
  SEED_MESSAGES,
  SEED_AUDIT_LOGS,
  SEED_SYSTEM_HEALTH,
  SEED_SETTINGS
} from '../../mocks/admin/seedData';

export const delay = (minMs = 300, maxMs = 600): Promise<void> => {
  const ms = Math.floor(Math.random() * (maxMs - minMs + 1)) + minMs;
  return new Promise((resolve) => setTimeout(resolve, ms));
};

export const getStored = <T>(key: string, defaultValue: T): T => {
  try {
    const raw = localStorage.getItem(`dcsre_admin_v3_${key}`);
    if (raw) {
      return JSON.parse(raw) as T;
    }
  } catch (err) {
    console.warn(`[Admin Storage] Failed to read key dcsre_admin_v3_${key}:`, err);
  }
  // Initialize with seed value if not present
  setStored(key, defaultValue);
  return defaultValue;
};

export const setStored = <T>(key: string, value: T): void => {
  try {
    localStorage.setItem(`dcsre_admin_v3_${key}`, JSON.stringify(value));
  } catch (err) {
    console.warn(`[Admin Storage] Failed to write key dcsre_admin_v3_${key}:`, err);
  }
};

export const resetAllAdminData = (): void => {
  setStored('users', SEED_USERS);
  setStored('cases', SEED_CASES);
  setStored('evidence', SEED_EVIDENCE);
  setStored('rules', SEED_SIGMA_RULES);
  setStored('messages', SEED_MESSAGES);
  setStored('audit', SEED_AUDIT_LOGS);
  setStored('system_health', SEED_SYSTEM_HEALTH);
  setStored('settings', SEED_SETTINGS);
};
