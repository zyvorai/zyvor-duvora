import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Served from https://zyvorai.github.io/duvora/
export default defineConfig({
  base: '/duvora/',
  plugins: [react()],
  build: { outDir: 'dist', emptyOutDir: true },
});
