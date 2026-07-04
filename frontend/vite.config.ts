import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  build: {
    rollupOptions: {
      output: {
        // Split heavy, rarely-changing libraries into their own chunks so the
        // browser can cache them across deploys and the initial parse is lighter.
        manualChunks: {
          charts: ['recharts'],
          map: ['leaflet', 'react-leaflet'],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:5432',
        changeOrigin: true,
      }
    }
  }
})
