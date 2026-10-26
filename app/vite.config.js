import { defineConfig } from 'vite';
import { VitePWA } from 'vite-plugin-pwa';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const protocolRoot = path.resolve(here, '../analysis/protocol-js');
const METADATA_FILE = path.resolve(here, 'src/generated/metadata.json');

/**
 * `virtual:reamplifi-metadata`: the slim model metadata you generated from your own APK
 * (src/generated/metadata.json, gitignored), or `null`.
 *
 * - dev server: included when the file exists;
 * - `npm run build`: NOT included (safe to deploy publicly: no Line 6-derived data);
 * - `npm run build:local`: included (REAMPLIFI_METADATA=1), for your own private use only.
 */
function localMetadata({ isBuild }) {
  const id = 'virtual:reamplifi-metadata';
  const resolved = '\0' + id;
  return {
    name: 'reamplifi-local-metadata',
    resolveId(source) {
      if (source === id) return resolved;
    },
    load(target) {
      if (target !== resolved) return;
      const wanted = isBuild ? process.env.REAMPLIFI_METADATA === '1' : process.env.REAMPLIFI_METADATA !== '0';
      if (!wanted || !existsSync(METADATA_FILE)) return 'export default null;';
      this.addWatchFile(METADATA_FILE);
      return `export default ${readFileSync(METADATA_FILE, 'utf8')};`;
    },
  };
}

export default defineConfig(({ command }) => ({
  base: './',
  resolve: {
    alias: {
      // protocol-js is the single source of truth for every byte on the wire
      '@protocol': path.join(protocolRoot, 'src'),
      '@mock': path.join(protocolRoot, 'mock'),
    },
  },
  server: {
    port: 5173,
    strictPort: false,
    fs: { allow: [here, protocolRoot] },
  },
  build: {
    target: 'es2022',
    sourcemap: true,
  },
  plugins: [
    localMetadata({ isBuild: command === 'build' }),
    VitePWA({
      registerType: 'autoUpdate', // the web app's own service worker; nothing to do with amp firmware
      injectRegister: 'auto',
      includeAssets: ['icon.svg', 'icon-maskable.svg'],
      manifest: {
        name: 'ReAmpliFi',
        short_name: 'ReAmpliFi',
        description: 'Independent read-only remote that works with the AMPLIFi 150 over Bluetooth (Web Serial). Not affiliated with Line 6.',
        theme_color: '#0f766e',
        background_color: '#0e1215',
        display: 'standalone',
        start_url: './',
        scope: './',
        icons: [
          { src: 'icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
          { src: 'icon-maskable.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'maskable' },
        ],
      },
      workbox: {
        globPatterns: ['**/*.{js,css,html,svg,webmanifest}'],
      },
    }),
  ],
}));
