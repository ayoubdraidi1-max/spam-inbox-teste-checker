import { defineConfig } from 'vite';

export default defineConfig({
  root: 'preview',
  server: {
    port: 5173,
    host: true,
  },
  build: {
    outDir: 'dist',
  },
});
