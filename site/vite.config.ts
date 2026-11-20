// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Served from https://zyvorai.github.io/zyvor-duvora/
export default defineConfig({
  base: '/zyvor-duvora/',
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
});
