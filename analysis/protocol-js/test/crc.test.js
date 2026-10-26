import { test } from 'node:test';
import assert from 'node:assert/strict';
import { crc16CcittFalse, crc32 } from '../src/crc.js';
import { asciiBytes } from '../src/values.js';

const check = asciiBytes('123456789');

test('CRC-16/CCITT-FALSE check value 0x29B1', () => {
  assert.equal(crc16CcittFalse(check), 0x29b1);
});

test('CRC-16 of empty input is the seed 0xFFFF', () => {
  assert.equal(crc16CcittFalse(new Uint8Array(0)), 0xffff);
});

test('CRC-16 is incremental (seed with the previous result)', () => {
  const a = crc16CcittFalse(check.subarray(0, 4));
  assert.equal(crc16CcittFalse(check.subarray(4), a), 0x29b1);
});

test('CRC-16 matches a bitwise reference implementation on 300 bytes', () => {
  const data = Uint8Array.from({ length: 300 }, (_, i) => (i * 37 + 11) & 0xff);
  let crc = 0xffff;
  for (const b of data) {
    crc ^= b << 8;
    for (let k = 0; k < 8; k++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  assert.equal(crc16CcittFalse(data), crc);
});

test('CRC-32 (zlib) check value 0xCBF43926', () => {
  assert.equal(crc32(check), 0xcbf43926);
});

test('CRC-32 is incremental like zlib.crc32(data, prev)', () => {
  assert.equal(crc32(check.subarray(5), crc32(check.subarray(0, 5))), 0xcbf43926);
  assert.equal(crc32(new Uint8Array(0)), 0);
});
