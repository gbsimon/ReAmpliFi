import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readTable, assetsSkipReason } from './helpers.js';
import { parseSymbolTable, buildSymbolTable, tableCrc, ROOT_SLOT_INDEX } from '../src/symtab.js';
import { SymbolNotFoundError } from '../src/errors.js';

const skip = assetsSkipReason;

test('real defaultSymbolTable.bin: 611 entries, size field = file length, CRC32 0xB68B291E', { skip }, () => {
  const bytes = readTable();
  const t = parseSymbolTable(bytes);
  assert.equal(t.count, 611);
  assert.equal(t.size, 15764);
  assert.equal(bytes.length, 15764);
  assert.equal(tableCrc(bytes), 0xb68b291e);
  assert.equal(t.crc32, 0xb68b291e);
});

test('real table: every entry hash = crc32(name)', { skip }, () => {
  const v = parseSymbolTable(readTable()).verify();
  assert.equal(v.sizeOk, true);
  assert.deepEqual(v.mismatches, []);
  assert.equal(v.ok, true);
});

test('real table: index lookups used by the vectors', { skip }, () => {
  const t = parseSymbolTable(readTable());
  const expect = { Gain: 0, Delay: 1, Drive: 23, Bass: 17, Amp: 535, Air: 536, StudioCab: 538, GuitarProc: 596, ChannelVolume: 540, FX1Enable: 576, Tuner: 587, Enable: 593, Note: 594, Master: 608, GuitOutputGain: 610, SyncSelect: 146, '4x12BritT75Studio421': 471 };
  for (const [name, idx] of Object.entries(expect)) {
    assert.equal(t.lookup(name), idx, name);
    assert.equal(t.nameOf(idx), name);
  }
  assert.equal(t.lookup(''), ROOT_SLOT_INDEX, '"" is the root slot');
  assert.equal(t.nameOf(ROOT_SLOT_INDEX), '');
  assert.throws(() => t.lookup('4x12BritT75Studio'), SymbolNotFoundError, 'cab names exist only with a mic suffix');
});

test('buildSymbolTable → parseSymbolTable round trip, hashes valid', () => {
  const names = ['Tuner', 'Enable', 'Note', 'Drive', 'Drive'];
  const bytes = buildSymbolTable(names);
  const t = parseSymbolTable(bytes);
  assert.deepEqual(t.names, names);
  assert.equal(t.lookup('Drive'), 3, 'first match wins');
  assert.equal(t.verify().ok, true);
  assert.equal(t.size, bytes.length);
});

test('truncated table is rejected', () => {
  const bytes = buildSymbolTable(['A', 'B']);
  assert.throws(() => parseSymbolTable(bytes.slice(0, 20)));
});
