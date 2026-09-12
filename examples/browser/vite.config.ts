import { defineConfig } from 'vite';

export default defineConfig({
  preview: {
    headers: {
      'Content-Security-Policy': "default-src 'none'; script-src 'self'; worker-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'",
    },
  },
});
