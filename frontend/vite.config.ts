import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// Public origin of the deployed app. Every absolute URL the crawlers care about
// (canonical, Open Graph, sitemap, robots) is built from this one value, so
// moving the app to another domain means changing it here or setting SITE_URL
// at build time. The app also answers on its Azure hostname, and the canonical
// tag is what tells Google which of the two to index.
const SITE_URL = (process.env.SITE_URL ?? 'https://pcap.eissayou.com').replace(/\/$/, '')

// Writes robots.txt and sitemap.xml from SITE_URL and fills the %SITE_URL%
// placeholders in index.html, so the origin is never hardcoded twice.
function seoFiles(): Plugin {
  return {
    name: 'seo-files',
    transformIndexHtml: (html) => html.replaceAll('%SITE_URL%', SITE_URL),
    generateBundle() {
      const today = new Date().toISOString().slice(0, 10)
      this.emitFile({
        type: 'asset',
        fileName: 'robots.txt',
        source: `User-agent: *\nAllow: /\n\nSitemap: ${SITE_URL}/sitemap.xml\n`,
      })
      this.emitFile({
        type: 'asset',
        fileName: 'sitemap.xml',
        source: `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>${SITE_URL}/</loc>
    <lastmod>${today}</lastmod>
    <changefreq>monthly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
`,
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    seoFiles(),
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
