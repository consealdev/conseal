import { defineConfig } from 'tsup'

const banner = `/*!
 * Conseal __VERSION__ | Zero-knowledge cryptography and private communication
 * Copyright (c) 2026 Codesense
 * Licensed under the AGPL-3.0 License. https://github.com/consealdev/conseal/blob/main/LICENSE
 */`

export default defineConfig([
  {
    entry: [
      'src/index.ts',
    ],
    format: ['esm'],
    outDir: 'dist',
    noExternal: [/.*/],
    dts: {
      compilerOptions: {
        // tsup's DTS build via rollup-plugin-dts always injects baseUrl: ".",
        // which TypeScript 6.0 flags as deprecated. This silences that deprecation
        // only for DTS generation — the main tsconfig.json remains unmodified.
        ignoreDeprecations: '6.0',
      },
    },
  },
  {
    entry: [
      'src/index.ts',
    ],
    format: ['esm'],
    outDir: 'dist',
    noExternal: [/.*/],
    minify: true,
    dts: false,
    outExtension: () => ({ js: '.min.js' }),
    banner: { js: banner },
  },
  // ── IIFE builds for GitHub Pages demo ──────────────────────────────────
  {
    entry: { conseal: 'src/index.ts' },
    format: ['iife'],
    outDir: 'docs/assets',
    globalName: 'conseal',
    noExternal: [/.*/],
    minify: true,
    dts: false,
    outExtension: () => ({ js: '.js' }),
  },
  {
    entry: { bip39: 'src/bip39-bundle.ts' },
    format: ['iife'],
    outDir: 'docs/assets',
    globalName: 'bip39',
    noExternal: [/.*/],
    minify: true,
    dts: false,
    outExtension: () => ({ js: '.js' }),
  },
])
