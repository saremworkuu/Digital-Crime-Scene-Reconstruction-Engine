export const APP_NAME = "አሻራ";
export const APP_FULL_NAME = "አሻራ - Digital Crime Scene Reconstruction Engine";
export const RENDER_BACKEND_URL = "https://digital-crime-scene-reconstruction-engine.onrender.com";
export const API_BASE_URL = (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL)
  ? import.meta.env.VITE_API_BASE_URL
  : (typeof import.meta !== 'undefined' && import.meta.env?.PROD)
    ? `${RENDER_BACKEND_URL}/api/v1`
    : "/api/v1";
export const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB

export const SUPPORTED_LOG_EXTENSIONS = [
  '.log', '.txt', '.evtx', '.pcap', '.csv', '.json'
];

export const DEMO_PERSONAS = [
  { id: 'usr-admin', name: 'Sarem Worku (System Administrator)', email: 'saremworkuu@gmail.com', role: 'admin', department: 'DFIR Command' }
];

