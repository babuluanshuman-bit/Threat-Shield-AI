import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    host: true,
    port: 5173,
    proxy: {
      '/api/abuseipdb': {
        target: 'https://api.abuseipdb.com/api/v2',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/abuseipdb/, ''),
      },
      '/api/virustotal': {
        target: 'https://www.virustotal.com/api/v3',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/virustotal/, ''),
      },
      '/api/huggingface': {
        target: 'https://router.huggingface.co/hf-inference',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/huggingface/, ''),
      },
      '/api/gemini': {
        target: 'https://generativelanguage.googleapis.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/gemini/, ''),
      },
    },
  },
  preview: {
    host: true,
    port: 4173,
    proxy: {
      '/api/abuseipdb': {
        target: 'https://api.abuseipdb.com/api/v2',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/abuseipdb/, ''),
      },
      '/api/virustotal': {
        target: 'https://www.virustotal.com/api/v3',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/virustotal/, ''),
      },
      '/api/huggingface': {
        target: 'https://router.huggingface.co/hf-inference',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/huggingface/, ''),
      },
      '/api/gemini': {
        target: 'https://generativelanguage.googleapis.com',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api\/gemini/, ''),
      },
    },
  },
})
