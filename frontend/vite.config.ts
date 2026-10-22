import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'path';
import fs from 'fs';
import {defineConfig} from 'vite';

// Sync user-provided artwork into public assets
try {
  const userPuppet = 'C:\\Users\\Admin\\.gemini\\antigravity-ide\\brain\\b87a5a80-1f2e-4d6e-af40-6b70bc481498\\.user_uploaded\\media_1792668093214.png';
  if (fs.existsSync(userPuppet)) {
    fs.copyFileSync(userPuppet, path.resolve(__dirname, 'public/assets/auth_art.png'));
    const rootPath = path.resolve(__dirname, '../public/assets/auth_art.png');
    if (fs.existsSync(path.dirname(rootPath))) {
      fs.copyFileSync(userPuppet, rootPath);
    }
  }

  const userContact = 'C:\\Users\\Admin\\.gemini\\antigravity-ide\\brain\\b87a5a80-1f2e-4d6e-af40-6b70bc481498\\.user_uploaded\\media_1792673156106.png';
  if (fs.existsSync(userContact)) {
    fs.copyFileSync(userContact, path.resolve(__dirname, 'public/assets/contact_art.png'));
    const rootContact = path.resolve(__dirname, '../public/assets/contact_art.png');
    if (fs.existsSync(path.dirname(rootContact))) {
      fs.copyFileSync(userContact, rootContact);
    }
  }
} catch (e) {
  // ignore
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, '.'),
      },
    },
    server: {
      proxy: {
        '/api': {
          target: 'http://localhost:8000',
          changeOrigin: true,
        },
      },
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
