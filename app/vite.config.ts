import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, '.', '');
    return {
      server: {
        port: 3000,
        host: '0.0.0.0',
        // Proxy API requests to the Rust server
        proxy: {
          '/api': {
            target: 'http://localhost:8080',
            changeOrigin: true,
          },
          '/ws': {
            target: 'ws://localhost:8080',
            ws: true,
          },
        },
      },
      plugins: [react()],
      define: {
        'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
        'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY)
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, '.'),
        }
      },
      // WASM support
      optimizeDeps: {
        exclude: ['onyx_crypto_wasm'],
      },
      esbuild: {
        // Strip all console.* and debugger in production
        drop: mode === 'production' ? ['console', 'debugger'] : [],
      },
      build: {
        target: 'esnext',
        outDir: '../static/app',
        emptyOutDir: true,
        // Obfuscate chunk names — no function/module names leaked
        rollupOptions: {
          // External WASM module - loaded at runtime from public assets
          external: [/\/assets\/onyx_crypto_wasm.*\.js$/],
          output: {
            manualChunks: undefined,
            chunkFileNames: 'assets/[hash].js',
            entryFileNames: 'assets/[hash].js',
            assetFileNames: 'assets/[hash].[ext]',
          },
        },
        // No source maps in production
        sourcemap: false,
        // Minify with esbuild (fast + strips dead code)
        minify: 'esbuild',
      },
      // Serve WASM files from local public directory
      publicDir: 'public',
    };
});
