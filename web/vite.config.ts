// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// DUVORA_DEV_API points the dev proxy at another control plane (e.g. a lab's
// https://host:30880 with its self-signed cert) instead of a local server.
const api = process.env.DUVORA_DEV_API || 'http://127.0.0.1:8787';
const upstream = { target: api, secure: false, changeOrigin: true };

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../duvora/static',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': upstream,
      '/healthz': upstream,
    },
  },
});
