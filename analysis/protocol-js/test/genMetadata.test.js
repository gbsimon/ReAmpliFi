// tools/gen-metadata.js with synthetic inputs (no Line 6 data in this file), plus a smoke run on
// the local analysis copy of the assets when it exists.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { slimMetadata, slimParam, readAssetsDir, readApk, main, parseArgs } from '../tools/gen-metadata.js';
import { ASSETS_DIR, assetsSkipReason } from './helpers.js';

const SYNTH_MODELS = {
  'amps.models': [
    {
      symbolicID: 'TestAmpA',
      id: 1,
      category: 1,
      name: 'Test Amp A',
      icon: 'drop-me',
      params: [
        { symbolicID: 'Drive', name: 'Drive', min: 0, max: 1, default: 0.5, valueType: 1, persist: 0, tweak: 3 },
        { symbolicID: 'Ch', name: 'Channel', min: '0', max: '3', default: '1', valueType: 0 },
      ],
    },
  ],
  'stomps.models': [{ symbolicID: 'TestFuzz', name: 'Test Fuzz', params: [{ symbolicID: 'On', name: 'On', default: true, valueType: 2 }] }],
};
const SYNTH_CATALOGS = { 'AmpCatalog.json': { Testers: ['TestAmpA'] } };

test('slimMetadata keeps names, kind, category and numeric ranges only', () => {
  const m = slimMetadata({ models: SYNTH_MODELS, catalogs: SYNTH_CATALOGS });
  assert.equal(m.schema, 1);
  assert.deepEqual(m.models.TestAmpA, {
    name: 'Test Amp A',
    kind: 'amp',
    category: 'Testers',
    params: [
      { symbolicID: 'Drive', name: 'Drive', valueType: 1, min: 0, max: 1, default: 0.5 },
      { symbolicID: 'Ch', name: 'Channel', valueType: 0, min: 0, max: 3, default: 1 },
    ],
  });
  assert.deepEqual(m.models.TestFuzz, { name: 'Test Fuzz', kind: 'stomp', category: null, params: [{ symbolicID: 'On', name: 'On', valueType: 2, default: true }] });
  assert.ok(!JSON.stringify(m).includes('drop-me'), 'icons and other fields are dropped');
  assert.deepEqual(slimParam({ symbolicID: 'x', valueType: 3, default: 'abc' }), { symbolicID: 'x', name: 'x', valueType: 3, default: 'abc' });
});

test('assets dir and --apk (system unzip) inputs give the same result', async (t) => {
  const tmp = mkdtempSync(path.join(os.tmpdir(), 'gen-metadata-'));
  try {
    const assets = path.join(tmp, 'pkg', 'assets');
    mkdirSync(assets, { recursive: true });
    for (const [f, v] of Object.entries({ ...SYNTH_MODELS, ...SYNTH_CATALOGS })) writeFileSync(path.join(assets, f), JSON.stringify(v));
    const fromDir = slimMetadata(readAssetsDir(assets));
    assert.deepEqual(Object.keys(fromDir.models).sort(), ['TestAmpA', 'TestFuzz']);

    let haveZip = true;
    try {
      execFileSync('zip', ['-v'], { stdio: 'ignore' });
      execFileSync('unzip', ['-v'], { stdio: 'ignore' });
    } catch {
      haveZip = false;
    }
    if (!haveZip) return t.skip('zip/unzip not installed');
    const apk = path.join(tmp, 'synthetic.apk');
    execFileSync('zip', ['-qr', apk, 'assets'], { cwd: path.join(tmp, 'pkg') });
    assert.deepEqual(slimMetadata(readApk(apk)), fromDir);

    const out = path.join(tmp, 'out', 'metadata.json');
    const logs = [];
    assert.equal(main(['--apk', apk, '--out', out], (s) => logs.push(s)), 0);
    const doc = JSON.parse(readFileSync(out, 'utf8'));
    assert.equal(doc.source, 'apk:synthetic.apk');
    assert.deepEqual(doc.models, fromDir.models);
    assert.match(logs.join('\n'), /wrote 2 models/);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('argument parsing', () => {
  assert.deepEqual(parseArgs(['--apk', 'a.apk', '--out', 'o.json']).apk, 'a.apk');
  assert.throws(() => parseArgs(['--bogus']), /unknown argument/);
});

test('local analysis assets slim without error', { skip: assetsSkipReason }, () => {
  const m = slimMetadata(readAssetsDir(ASSETS_DIR));
  const kinds = new Set(Object.values(m.models).map((x) => x.kind));
  for (const k of ['amp', 'cab', 'stomp', 'mod', 'delay', 'reverb', 'wah', 'fixed']) assert.ok(kinds.has(k), k);
  assert.ok(Object.keys(m.models).length > 150);
  for (const x of Object.values(m.models)) for (const p of x.params) assert.ok(typeof p.symbolicID === 'string' && Number.isInteger(p.valueType));
});
