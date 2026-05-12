import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { crx } from '@crxjs/vite-plugin';
import path from 'path';
import manifest from './manifest.json';

export default defineConfig({
  plugins: [react(), crx({ manifest })],
  resolve: {
    alias: {
      // Import shared React components from the frontend project.
      '@frontend': path.resolve(__dirname, '../frontend/src'),
      '@shared': path.resolve(__dirname, '../shared'),
    },
  },
  server: {
    // Allow Vite to serve files from the sibling frontend folder.
    port: 5174,           // explicitly pinned, different from frontend's 5173
    strictPort: true,     // fail loudly if 5174 is busy, don't silently switch
    hmr: {
      port: 5174,
      host: 'localhost',
    },
    fs: {
      allow: ['..'],
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: path.resolve(__dirname, 'popup.html'),
        warning: path.resolve(__dirname, 'warning.html'),  // ← add this
      },
    }
  },
});