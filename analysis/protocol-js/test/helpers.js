// Shared test helpers. Line 6 assets are READ at test time from ../work/apktool/assets;
// nothing is copied into protocol-js.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { indexModels } from '../src/mapping.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const PROJECT_ROOT = path.resolve(here, '..');
export const ANALYSIS_ROOT = path.resolve(here, '..', '..');
export const ASSETS_DIR = path.join(ANALYSIS_ROOT, 'work', 'apktool', 'assets');
export const VECTORS_PATH = path.join(ANALYSIS_ROOT, 'notes', 'test_vectors.json');
export const TABLE_PATH = path.join(ASSETS_DIR, 'defaultSymbolTable.bin');

export const haveAssets = existsSync(TABLE_PATH);
export const assetsSkipReason = haveAssets ? false : `assets not found at ${ASSETS_DIR}`;

export function readTable() {
  return new Uint8Array(readFileSync(TABLE_PATH));
}

// Vectors derived from Line 6 files (default_preset.json blobs) are kept out of git in
// test_vectors.local.json; merge them in when present.
export const LOCAL_VECTORS_PATH = path.join(ANALYSIS_ROOT, 'notes', 'test_vectors.local.json');

export function loadVectors() {
  const data = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'));
  if (existsSync(LOCAL_VECTORS_PATH)) {
    data.vectors.push(...JSON.parse(readFileSync(LOCAL_VECTORS_PATH, 'utf8')).vectors);
  }
  return data;
}

export function loadModels() {
  const arrays = readdirSync(ASSETS_DIR)
    .filter((f) => f.endsWith('.models'))
    .map((f) => JSON.parse(readFileSync(path.join(ASSETS_DIR, f), 'utf8')));
  return indexModels(...arrays);
}

export function loadDefaultPresetJson() {
  return JSON.parse(readFileSync(path.join(ASSETS_DIR, 'default_preset.json'), 'utf8'));
}

export const hex = (b) => Buffer.from(b).toString('hex');
