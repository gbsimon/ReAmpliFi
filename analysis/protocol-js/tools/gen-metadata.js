#!/usr/bin/env node
// gen-metadata: slim model metadata (display names, categories, param ranges) from YOUR OWN copy
// of the Line 6 Remote app's assets, for local use by the ReAmpliFi app (PLAN.md §3.5).
//
//   node analysis/protocol-js/tools/gen-metadata.js                      # analysis/work/apktool/assets
//   node analysis/protocol-js/tools/gen-metadata.js --assets <dir>
//   node analysis/protocol-js/tools/gen-metadata.js --apk <Line.6.Remote.apk>   # uses `unzip -p`
//   node analysis/protocol-js/tools/gen-metadata.js --out <file.json>
//
// Output (default app/src/generated/metadata.json, which is gitignored):
//   { schema: 1, generatedAt, source, models: { <symbolicID>: { name, kind, category,
//     params: [{ symbolicID, name, min, max, default, valueType }] } } }
//
// Only interoperability facts are kept (identifiers, names, numeric ranges). Icons, ids, image
// references and every other field are dropped. Nothing is written into the repository's
// tracked files: the output folder is gitignored and must stay that way. Never commit it.

import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(here, '..', '..', '..');
export const DEFAULT_ASSETS = path.join(REPO_ROOT, 'analysis', 'work', 'apktool', 'assets');
export const DEFAULT_OUT = path.join(REPO_ROOT, 'app', 'src', 'generated', 'metadata.json');

/** *.models file → block kind. */
export const MODEL_FILES = Object.freeze({
  'amps.models': 'amp',
  'cabs.models': 'cab',
  'stomps.models': 'stomp',
  'mod.models': 'mod',
  'delay.models': 'delay',
  'reverbs.models': 'reverb',
  'wahs.models': 'wah',
  'fixed.models': 'fixed',
});

/** Catalog files: { "<category name>": [symbolicID, …] }. */
export const CATALOG_FILES = Object.freeze(['AmpCatalog.json', 'CabCatalog.json', 'FXCatalog.json', 'ReverbCatalog.json', 'WahCatalog.json']);

const num = (v) => (v === undefined || v === null || v === '' ? null : Number.isFinite(Number(v)) ? Number(v) : null);

/** Keep only {symbolicID, name, min, max, default, valueType} of one param definition. */
export function slimParam(p) {
  const out = { symbolicID: String(p.symbolicID), name: String(p.name ?? p.symbolicID), valueType: Number(p.valueType) };
  for (const k of ['min', 'max']) {
    const v = num(p[k]);
    if (v !== null) out[k] = v;
  }
  if (p.default !== undefined) out.default = typeof p.default === 'number' || typeof p.default === 'boolean' ? p.default : num(p.default) ?? String(p.default);
  return out;
}

/**
 * Pure slimming step (no I/O).
 * @param {{models: Record<string, object[]>, catalogs: Record<string, Record<string,string[]>>}} input
 *        models: file name → parsed *.models array; catalogs: file name → parsed catalog
 * @returns {{schema:number, models:Record<string,{name:string, kind:string, category:string|null, params:object[]}>}}
 */
export function slimMetadata({ models, catalogs = {} }) {
  const categoryOf = new Map();
  for (const cat of Object.values(catalogs)) {
    for (const [category, ids] of Object.entries(cat ?? {})) {
      if (!Array.isArray(ids)) continue;
      for (const id of ids) if (!categoryOf.has(id)) categoryOf.set(id, category);
    }
  }
  const out = {};
  for (const [file, arr] of Object.entries(models)) {
    const kind = MODEL_FILES[file] ?? path.basename(file, '.models');
    if (!Array.isArray(arr)) throw new Error(`${file}: expected a JSON array of model definitions`);
    for (const m of arr) {
      if (!m || typeof m.symbolicID !== 'string') continue;
      out[m.symbolicID] = {
        name: String(m.name ?? m.shortname ?? m.symbolicID),
        kind,
        category: categoryOf.get(m.symbolicID) ?? null,
        params: (m.params ?? []).filter((p) => p && p.symbolicID !== undefined).map(slimParam),
      };
    }
  }
  return { schema: 1, models: out };
}

/** Read the inputs from an extracted assets folder. */
export function readAssetsDir(dir) {
  if (!existsSync(dir)) throw new Error(`assets folder not found: ${dir}`);
  const files = readdirSync(dir);
  const models = {};
  const catalogs = {};
  for (const f of files) {
    if (f in MODEL_FILES) models[f] = JSON.parse(readFileSync(path.join(dir, f), 'utf8'));
    if (CATALOG_FILES.includes(f)) catalogs[f] = JSON.parse(readFileSync(path.join(dir, f), 'utf8'));
  }
  if (!Object.keys(models).length) throw new Error(`no *.models files in ${dir}`);
  return { models, catalogs };
}

/** Read the inputs straight from an APK with the system `unzip` (nothing is extracted to disk). */
export function readApk(apk, { unzip = 'unzip' } = {}) {
  if (!existsSync(apk)) throw new Error(`APK not found: ${apk}`);
  const list = execFileSync(unzip, ['-Z1', apk], { encoding: 'utf8', maxBuffer: 64 << 20 }).split('\n').map((s) => s.trim());
  const pick = (name) => list.find((e) => e === `assets/${name}`);
  const read = (entry) => JSON.parse(execFileSync(unzip, ['-p', apk, entry], { encoding: 'utf8', maxBuffer: 64 << 20 }));
  const models = {};
  const catalogs = {};
  for (const f of Object.keys(MODEL_FILES)) if (pick(f)) models[f] = read(pick(f));
  for (const f of CATALOG_FILES) if (pick(f)) catalogs[f] = read(pick(f));
  if (!Object.keys(models).length) throw new Error(`no assets/*.models entries in ${apk}`);
  return { models, catalogs };
}

export function parseArgs(argv) {
  const o = { assets: null, apk: null, out: DEFAULT_OUT, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--assets') o.assets = argv[++i];
    else if (a === '--apk') o.apk = argv[++i];
    else if (a === '--out') o.out = argv[++i];
    else if (a === '-h' || a === '--help') o.help = true;
    else throw new Error(`unknown argument ${a}`);
  }
  return o;
}

export function main(argv = process.argv.slice(2), log = console.log) {
  const o = parseArgs(argv);
  if (o.help) {
    log('usage: gen-metadata.js [--assets <dir> | --apk <file.apk>] [--out <file.json>]');
    return 0;
  }
  const input = o.apk ? readApk(path.resolve(o.apk)) : readAssetsDir(path.resolve(o.assets ?? DEFAULT_ASSETS));
  const meta = slimMetadata(input);
  const source = o.apk ? `apk:${path.basename(o.apk)}` : `assets:${path.relative(REPO_ROOT, path.resolve(o.assets ?? DEFAULT_ASSETS)) || '.'}`;
  const doc = { schema: meta.schema, generatedAt: new Date().toISOString(), source, models: meta.models };
  mkdirSync(path.dirname(path.resolve(o.out)), { recursive: true });
  writeFileSync(path.resolve(o.out), JSON.stringify(doc) + '\n');
  const counts = {};
  for (const m of Object.values(meta.models)) counts[m.kind] = (counts[m.kind] ?? 0) + 1;
  log(`wrote ${Object.keys(meta.models).length} models (${Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(', ')}) to ${o.out}`);
  log('This file is derived from Line 6 assets: keep it local (gitignored). Do not commit or publish it.');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    process.exitCode = main();
  } catch (e) {
    console.error(`gen-metadata: ${e.message}`);
    process.exitCode = 1;
  }
}
