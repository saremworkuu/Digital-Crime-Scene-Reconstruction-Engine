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

  const userContact = 'C:\\Users\\Admin\\.gemini\\antigravity-ide\\brain\\b87a5a80-1f2e-4d6e-af40-6b70bc481498\\.user_uploaded\\media_1792710719849.png';
  if (fs.existsSync(userContact)) {
    fs.copyFileSync(userContact, path.resolve(__dirname, 'public/assets/contact_art.png'));
    const rootContact = path.resolve(__dirname, '../public/assets/contact_art.png');
    if (fs.existsSync(path.dirname(rootContact))) {
      fs.copyFileSync(userContact, rootContact);
    }
  }

  // Sync 5 user-provided About page images
  const aboutImages = [
    { src: 'media_1792712007641.png', dest: 'about_art_1.png' },
    { src: 'media_1792712160200.png', dest: 'about_art_2.png' },
    { src: 'media_1792712287825.png', dest: 'about_art_3.png' },
    { src: 'media_1792712319111.png', dest: 'about_art_4.png' },
    { src: 'media_1792712344791.png', dest: 'about_art_5.png' },
  ];

  for (const img of aboutImages) {
    const srcPath = path.resolve('C:\\Users\\Admin\\.gemini\\antigravity-ide\\brain\\b87a5a80-1f2e-4d6e-af40-6b70bc481498\\.user_uploaded', img.src);
    if (fs.existsSync(srcPath)) {
      const frontendDest = path.resolve(__dirname, 'public/assets', img.dest);
      fs.copyFileSync(srcPath, frontendDest);
      const rootDest = path.resolve(__dirname, '../public/assets', img.dest);
      if (fs.existsSync(path.dirname(rootDest))) {
        fs.copyFileSync(srcPath, rootDest);
      }
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
          target: process.env.VITE_BACKEND_TARGET || 'http://localhost:8000',
          changeOrigin: true,
          secure: false,
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
