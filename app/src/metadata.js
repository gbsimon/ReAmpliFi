// Model metadata (display names, categories, param ranges).
//
// `virtual:reamplifi-metadata` is provided by vite.config.js: the contents of
// src/generated/metadata.json when you generated it from your own APK
// (analysis/protocol-js/tools/gen-metadata.js), otherwise `null`. That file is derived from
// Line 6 assets and is gitignored. Without it the app shows raw symbol names and 0..1 ranges.

import generated from 'virtual:reamplifi-metadata';

export const metadata = generated && generated.models ? generated : null;

export const metadataSummary = Object.freeze({
  present: !!metadata,
  models: metadata ? Object.keys(metadata.models).length : 0,
  source: metadata?.source ?? null,
});

/** { name, kind, category, params } for a model symbol, or null. */
export function modelInfo(symbol) {
  return (symbol && metadata?.models?.[symbol]) || null;
}

/** Display name of a model symbol (raw symbol without metadata). */
export function modelName(symbol) {
  return modelInfo(symbol)?.name ?? symbol ?? '—';
}
