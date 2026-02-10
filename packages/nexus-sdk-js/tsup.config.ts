import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    escrow: 'src/escrow.ts',
    webhooks: 'src/webhooks.ts',
    frost: 'src/frost.ts',
    fees: 'src/fees.ts',
    analytics: 'src/analytics.ts',
    apikeys: 'src/apikeys.ts',
    chat: 'src/chat.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  minify: false,
  target: 'es2020',
});
