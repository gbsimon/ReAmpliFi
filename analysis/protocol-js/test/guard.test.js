// Firmware guardrail (PLAN.md §5.8): allow-list, refusals, storage-write confirmation, and a
// source scan that fails if update/flash/DFU/updater identifiers appear in src/ outside guard.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { PROJECT_ROOT } from './helpers.js';
import {
  assertServiceModeAllowed,
  assertPortModeAllowed,
  assertCommandAllowed,
  assertFirmwareSupported,
  assertStreamAllowed,
  FirmwareGuardError,
  UnsupportedFirmwareError,
  COMMAND_ALLOW_LIST,
} from '../src/guard.js';
import { WriteNotConfirmedError } from '../src/errors.js';
import * as ed from '../src/editor.js';
import * as lib from '../src/librarian.js';
import { RpcClient } from '../src/rpc.js';
import { tvBool } from '../src/values.js';

test('service-mode word 0 (UPDATER) throws; only 1 and 2 pass', () => {
  assert.throws(() => assertServiceModeAllowed(0), FirmwareGuardError);
  assert.throws(() => assertServiceModeAllowed(3), FirmwareGuardError);
  assertServiceModeAllowed(1);
  assertServiceModeAllowed(2);
});

test('port mode 1 throws; 2, 3, 4 pass', () => {
  assert.throws(() => assertPortModeAllowed(1), FirmwareGuardError);
  assert.throws(() => assertPortModeAllowed(0), FirmwareGuardError);
  for (const m of [2, 3, 4]) assertPortModeAllowed(m);
});

test('only the editor and librarian streams are allowed', () => {
  assertStreamAllowed(0x2002, 0x03ed);
  assertStreamAllowed(0x2003, 0x03ef);
  assert.throws(() => assertStreamAllowed(0x2004, 0x03ef), FirmwareGuardError);
  assert.throws(() => assertStreamAllowed(0x2002, 0x03ef), FirmwareGuardError);
});

test('command allow-list: unknown ids throw, librarian 13 is not allowed', () => {
  assert.throws(() => assertCommandAllowed('editor', 0), FirmwareGuardError);
  assert.throws(() => assertCommandAllowed('editor', 23), FirmwareGuardError);
  assert.throws(() => assertCommandAllowed('librarian', 13), FirmwareGuardError);
  assert.throws(() => assertCommandAllowed('librarian', 16), FirmwareGuardError);
  assert.throws(() => assertCommandAllowed('updater', 1), FirmwareGuardError);
  for (const id of [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 20, 21]) assertCommandAllowed('editor', id);
  for (const id of [1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 14]) assertCommandAllowed('librarian', id);
  assert.deepEqual(Object.keys(COMMAND_ALLOW_LIST.librarian).map(Number), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15]);
});

test('storage writes need { confirmWrite: true }: librarian 9, 12 (idx ≠ −1), 15; editor 18, 19, 22', () => {
  for (const id of [18, 19, 22]) {
    assert.throws(() => assertCommandAllowed('editor', id), WriteNotConfirmedError);
    assertCommandAllowed('editor', id, { confirmWrite: true });
  }
  for (const id of [9, 15]) {
    assert.throws(() => assertCommandAllowed('librarian', id), WriteNotConfirmedError);
    assertCommandAllowed('librarian', id, { confirmWrite: true });
  }
  assertCommandAllowed('librarian', 12, { index: 0xffffffff });
  assert.throws(() => assertCommandAllowed('librarian', 12, { index: 3 }), WriteNotConfirmedError);
  assert.throws(() => assertCommandAllowed('librarian', 12), FirmwareGuardError, 'index required');
  assertCommandAllowed('librarian', 12, { index: 3, confirmWrite: true });
});

test('encoders refuse unconfirmed storage writes too', () => {
  assert.throws(() => lib.encodeSetPresetFile(2, new Uint8Array(4)), WriteNotConfirmedError);
  lib.encodeSetPresetFile(lib.EDIT_BUFFER, new Uint8Array(4));
  assert.throws(() => lib.encodeMovePresetFiles(1, 2), WriteNotConfirmedError);
  assert.throws(() => lib.encodeSetPresetFileAeon(1, new Uint8Array(4)), WriteNotConfirmedError);
  assert.throws(() => ed.encodeSetPersistentSysParam(7, tvBool(true)), WriteNotConfirmedError);
  assert.throws(() => ed.encodeSetPresetPSKeyParam(7, tvBool(true)), WriteNotConfirmedError);
  assert.throws(() => ed.encodeSetSystemSetting(1, tvBool(true)), WriteNotConfirmedError);
});

test('RpcClient re-checks the allow-list on the encoded bytes', async () => {
  const written = [];
  const fakeStream = { setDataHandler() {}, write: (b) => written.push(b) };
  const c = new RpcClient({ stream: fakeStream, name: 'lib', service: 'librarian' });
  await assert.rejects(c.request(lib.encodeSetPresetFile(4, new Uint8Array(4), { confirmWrite: true })), WriteNotConfirmedError);
  await assert.rejects(c.request(lib.encodeLoadHardwarePreset(1)), FirmwareGuardError);
  assert.equal(written.length, 0, 'nothing reached the stream');
  c.close();
});

test('firmware below 0x01000000 is refused (no update is ever offered)', () => {
  assert.throws(() => assertFirmwareSupported(0x00ff0000), UnsupportedFirmwareError);
  assertFirmwareSupported(0x01000000);
  assertFirmwareSupported(0x02320200);
});

// --------------------------------------------------------------------------- source scan

const FORBIDDEN = /update|flash|dfu|updater/i;

/** Remove comments so documentation can explain what is refused. */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/.*$/gm, '$1');
}

test('src/ has no update|flash|dfu|UPDATER identifiers outside guard.js', () => {
  const dir = path.join(PROJECT_ROOT, 'src');
  const hits = [];
  // recursive: src/transports/ and any later subfolder are scanned too
  const files = readdirSync(dir, { recursive: true }).map(String).filter((f) => f.endsWith('.js') && f !== 'guard.js');
  assert.ok(files.includes(path.join('transports', 'webSerial.js')), 'the scan reaches src/transports/');
  for (const f of files) {
    const code = stripComments(readFileSync(path.join(dir, f), 'utf8'));
    code.split('\n').forEach((line, i) => {
      // identifiers only (string literals are messages, not code paths, but we flag them too)
      const ids = line.match(/[A-Za-z_$][\w$]*/g) ?? [];
      for (const id of ids) if (FORBIDDEN.test(id)) hits.push(`${f}:${i + 1}: ${id}`);
    });
  }
  assert.deepEqual(hits, [], `forbidden identifiers found:\n${hits.join('\n')}`);
});

test('the source scan itself detects a planted identifier', () => {
  const planted = stripComments('const x = 1; // update is fine in a comment\nfunction startFirmwareUpdate() {}\n');
  const ids = planted.match(/[A-Za-z_$][\w$]*/g);
  assert.ok(ids.some((id) => FORBIDDEN.test(id)));
  assert.ok(!stripComments('// flash').match(FORBIDDEN));
});
