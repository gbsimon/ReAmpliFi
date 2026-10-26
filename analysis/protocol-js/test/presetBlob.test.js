import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readTable, loadModels, loadDefaultPresetJson, loadVectors, hex, assetsSkipReason } from './helpers.js';
import { parseSymbolTable, buildSymbolTable } from '../src/symtab.js';
import { decodeBlobRecords, encodeBlobRecords, blobToPreset, presetToBlob, encodeToneJson, describeBlob, setRecordValue, getPresetState, setPresetState, presetToEditorParams, BLOB_TAG, DIRECTIVE, STATUS } from '../src/presetBlob.js';
import { makeSyntheticPreset } from '../mock/MockAmp.js';
import { MOCK_SYMBOL_NAMES } from '../mock/mockSymbols.js';
import { hexToBytes, tvFloat, concatBytes } from '../src/values.js';

const skip = assetsSkipReason;
const sym = skip ? null : parseSymbolTable(readTable());
const blobVectors = skip ? [] : loadVectors().vectors.filter((v) => v.name.startsWith('preset_blob_'));

test('presetBlob is marked INFERRED', () => {
  assert.equal(STATUS, 'INFERRED');
});

for (const v of blobVectors) {
  test(`decode → encode round trip is byte-exact: ${v.name}`, () => {
    const bytes = hexToBytes(v.payload_hex);
    const dec = decodeBlobRecords(bytes);
    assert.equal(dec.trailer.length, 0);
    assert.equal(hex(encodeBlobRecords(dec)), v.payload_hex);
  });
  test(`blobToPreset → presetToBlob is byte-exact: ${v.name}`, () => {
    const bytes = hexToBytes(v.payload_hex);
    assert.equal(hex(presetToBlob(blobToPreset(bytes, sym), sym)), v.payload_hex);
  });
}

test('decode → encode keeps non-canonical payloads (bool=5, unknown tag, odd string, trailer)', () => {
  const rec = (key, tag, payloadHex) => concatBytes(hexToBytes(key), hexToBytes(tag), hexToBytes(payloadHex));
  const weird = concatBytes(
    rec('01000000', '0100', '05000000'), // bool with value 5
    rec('02000000', '0500', 'aabbccdd'), // unknown tag 5
    rec('00000000', '0400', '03000000414243'), // string without NUL terminator
    rec('03000000', '0300', '0000c07f'), // NaN float
    hexToBytes('ffee'), // trailer < 6 bytes
  );
  const dec = decodeBlobRecords(weird);
  assert.equal(hex(encodeBlobRecords(dec)), hex(weird));
  assert.equal(dec.records[2].value, 'ABC');
});

test('setRecordValue re-encodes the new value', () => {
  const dec = decodeBlobRecords(concatBytes(hexToBytes('01000000 0100 05000000')));
  setRecordValue(dec.records[0], false);
  assert.equal(hex(encodeBlobRecords(dec)), '01000000010000000000');
});

test('default preset: structured view and editor params', { skip }, () => {
  const bytes = encodeToneJson(loadDefaultPresetJson(), sym, loadModels()).blob;
  const p = blobToPreset(bytes, sym);
  assert.equal(p.name, 'Fidelity Lead');
  assert.equal(p.root.slot, 'GuitarProc');
  assert.equal(p.root.asset, 'ToneMatchGuitarFlow');
  assert.equal(p.root.children.length, 13);
  assert.ok(Math.abs(getPresetState(p, 'Amp', 'Drive') - 0.49538) < 1e-6);
  const ep = presetToEditorParams(p);
  assert.equal(ep.groups.amp['@model'], 'BritGainJ800');
  assert.equal(ep.groups.cab['@model'], '4x12BritT75Studio');
  assert.equal(ep.groups.cab['@mic'], 2);
  assert.equal(ep.groups.fx3['@enabled'], true);
  assert.match(describeBlob(bytes, sym), /Asset \[7\] = "BritGainJ800"/);
});

test('editing a state and re-serialising changes only that value', { skip }, () => {
  const bytes = encodeToneJson(loadDefaultPresetJson(), sym, loadModels()).blob;
  const p = blobToPreset(bytes, sym);
  setPresetState(p, 'Amp', 'Drive', tvFloat(0.25), sym);
  const out = presetToBlob(p, sym);
  assert.equal(out.length, bytes.length);
  const diff = [...out].filter((b, i) => b !== bytes[i]).length;
  assert.ok(diff > 0 && diff <= 4);
  assert.equal(getPresetState(blobToPreset(out, sym), 'Amp', 'Drive'), 0.25);
});

test('synthetic mock presets (made-up values) round-trip in the synthetic table and the real one', () => {
  const tables = [parseSymbolTable(buildSymbolTable(MOCK_SYMBOL_NAMES))];
  if (sym) tables.push(sym);
  for (const t of tables) {
    for (let i = 0; i < 8; i++) {
      const blob = presetToBlob(makeSyntheticPreset(i), t);
      const back = blobToPreset(blob, t);
      assert.equal(back.name, `Mock Tone ${i + 1}`);
      assert.equal(hex(presetToBlob(back, t)), hex(blob));
      assert.equal(hex(encodeBlobRecords(decodeBlobRecords(blob))), hex(blob));
      assert.ok(blob.length < 0x8000);
    }
  }
});

test('partial blob for an amp model change has only Amp/Air/StudioCab/LiveCab slots', { skip }, () => {
  const { blob } = encodeToneJson(loadDefaultPresetJson(), sym, loadModels(), { group: 'amp' });
  const p = blobToPreset(blob, sym);
  assert.deepEqual(p.root.children.map((c) => c.slot), ['Amp', 'Air', 'StudioCab', 'LiveCab']);
  const keys = decodeBlobRecords(blob).records.filter((r) => r.key < 16 && r.tag !== BLOB_TAG.INT).map((r) => r.key);
  assert.ok(!keys.includes(3), 'no tempo PS key in a partial blob');
  assert.ok(decodeBlobRecords(blob).records.some((r) => r.key === DIRECTIVE.SLOT_START));
});
