// Librarian service (stream 0x2003 <-> 0x03EF after service-mode word 1): request encoders,
// response decoders, and amp-side encoders for the mock.
//
// Spec: native_messages.md §4 and §8 command table (which CORRECTS native_transport.md §6.4:
// cmds 1, 2, 3 and 5 reply WITHOUT a status word - GetVersion 0x10b670 / GetNumPresets 0x10b95e
// pass a null status pointer). Every other librarian response starts with i32 status.

import { concatBytes, EMPTY, readI32, readU32, readU64, u32words, viewOf } from './values.js';
import { encodeRpcInbound, encodeRpcRequest, INBOUND } from './rpc.js';
import { assertWriteConfirmed } from './guard.js';
import { AmpProtocolError } from './errors.js';

/** Preset index meaning "the edit buffer" (0xFFFFFFFF). CONFIRMED. */
export const EDIT_BUFFER = 0xffffffff;
/** Blob size limit. CONFIRMED (§4). */
export const MAX_PRESET_FILE_SIZE = 0x8000;
/** Preset names are ≤ 64 bytes (char[64]); the blob name key is ≤ 63 chars. */
export const MAX_PRESET_NAME = 64;

/** @typedef {import('./editor.js').CommandInfo & {writesStorage: boolean | ((idx:number)=>boolean)}} LibCommandInfo */

/** @type {Record<string, LibCommandInfo>} */
export const LIBRARIAN_COMMANDS = Object.freeze({
  GetVersion: { id: 1, name: 'GetVersion', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote::GetVersion 0x10b670' },
  GetSymbolTableSize: { id: 2, name: 'GetSymbolTableSize', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote', note: 'unused (librarian never fetches the table)' },
  GetSymbolTable: { id: 3, name: 'GetSymbolTable', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: null, source: 'ToneMatchLibrarian_Remote', note: 'unused: Librarian FetchSymbolTable returns −1' },
  Handshake: { id: 4, name: 'Handshake', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote::Handshake 0x10b884' },
  GetNumPresets: { id: 5, name: 'GetNumPresets', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote::GetNumPresets 0x10b95e', note: 'reply is exactly 01000000 04000000 <u32 count>' },
  GetPresetName: { id: 6, name: 'GetPresetName', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote::GetPresetName 0x10ba0e', note: 'nameLen includes the NUL: INFERRED' },
  GetPresetUUID: { id: 7, name: 'GetPresetUUID', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote' },
  GetPresetChecksum: { id: 8, name: 'GetPresetChecksum', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote' },
  MovePresetFiles: { id: 9, name: 'MovePresetFiles', status: 'CONFIRMED', writesStorage: true, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote::MovePresetFiles 0x10bcb4', note: 'arg order dst, src CONFIRMED; amp semantics INFERRED' },
  GetPresetFileSize: { id: 10, name: 'GetPresetFileSize', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote' },
  GetPresetFile: { id: 11, name: 'GetPresetFile', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote::GetPresetFile 0x10be42' },
  SetPresetFile: { id: 12, name: 'SetPresetFile', status: 'CONFIRMED', writesStorage: (idx) => idx >>> 0 !== EDIT_BUFFER, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote::SetPresetFile 0x10bf12', note: 'writes storage when idx ≠ 0xFFFFFFFF' },
  LoadHardwarePreset: { id: 13, name: 'LoadHardwarePreset', status: 'INFERRED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote', note: 'layout CONFIRMED, never used by the app; effect (recall) INFERRED' },
  GetPresetInfo: { id: 14, name: 'GetPresetInfo', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote::GetPresetInfo 0x10c0d4' },
  SetPresetFileAeon: { id: 15, name: 'SetPresetFileAeon', status: 'CONFIRMED', writesStorage: true, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchLibrarian_Remote', note: 'AEON only' },
});

export const LIBRARIAN_COMMANDS_BY_ID = Object.freeze(Object.fromEntries(Object.values(LIBRARIAN_COMMANDS).map((c) => [c.id, c])));
export const LIBRARIAN_CMD = Object.freeze(Object.fromEntries(Object.values(LIBRARIAN_COMMANDS).map((c) => [c.name, c.id])));

const req = (name, payload = EMPTY) => encodeRpcRequest(LIBRARIAN_COMMANDS[name].id, payload);

// ------------------------------------------------------------------------------ requests

/** cmd 1. Response: u32 version, NO status. */
export const encodeGetVersion = () => req('GetVersion');
/** cmd 2 (unused). Response: u32, no status. */
export const encodeGetSymbolTableSize = () => req('GetSymbolTableSize');
/** cmd 3 (unused). Response: raw table, no status. */
export const encodeGetSymbolTable = () => req('GetSymbolTable');
/** cmd 4 Handshake(u32 crc32). Response: i32 status. */
export const encodeHandshake = (crc) => req('Handshake', u32words(crc));
/** cmd 5. Response: u32 count, NO status. */
export const encodeGetNumPresets = () => req('GetNumPresets');
/** cmd 6 {u32 idx}. Response: i32 status, u32 nameLen, char[nameLen ≤ 64]. */
export const encodeGetPresetName = (idx) => req('GetPresetName', u32words(idx));
/** cmd 7 {u32 idx}. Response: i32 status, u64 uuid. */
export const encodeGetPresetUUID = (idx) => req('GetPresetUUID', u32words(idx));
/** cmd 8 {u32 idx}. Response: i32 status, u32 checksum. */
export const encodeGetPresetChecksum = (idx) => req('GetPresetChecksum', u32words(idx));

/**
 * cmd 9 MovePresetFiles {u32 dst, u32 src}. CONFIRMED order (dst first). writesStorage:
 * requires { confirmWrite: true }.
 */
export function encodeMovePresetFiles(dst, src, opts) {
  assertWriteConfirmed('MovePresetFiles (librarian cmd 9)', opts);
  return req('MovePresetFiles', u32words(dst, src));
}

/** cmd 10 {u32 idx}. Response: i32 status, u32 size. */
export const encodeGetPresetFileSize = (idx) => req('GetPresetFileSize', u32words(idx));
/** cmd 11 GetPresetFile {u32 idx | EDIT_BUFFER}. Response: i32 status, blob. */
export const encodeGetPresetFile = (idx) => req('GetPresetFile', u32words(idx));

/**
 * cmd 12 SetPresetFile {u32 idx, u32 L, blob}; header len = 8 + L. CONFIRMED.
 * idx = EDIT_BUFFER (0xFFFFFFFF) only replaces the edit buffer (preset select / tone load).
 * Any other idx WRITES A PRESET SLOT and requires { confirmWrite: true }.
 */
export function encodeSetPresetFile(idx, blob, opts) {
  if (idx >>> 0 !== EDIT_BUFFER) assertWriteConfirmed(`SetPresetFile to slot ${idx} (librarian cmd 12)`, opts);
  if (blob.length > MAX_PRESET_FILE_SIZE) throw new AmpProtocolError(`preset blob of ${blob.length} bytes exceeds 0x8000`);
  return req('SetPresetFile', concatBytes(u32words(idx, blob.length), blob));
}

/** cmd 13 LoadHardwarePreset {u32 idx}. Layout CONFIRMED, unused by the app, effect INFERRED. */
export const encodeLoadHardwarePreset = (idx) => req('LoadHardwarePreset', u32words(idx));
/** cmd 14 GetPresetInfo {u32 idx}. Response: i32 status, u64 uuid, u32 checksum, u32 size, u32 nameLen, char[64]. */
export const encodeGetPresetInfo = (idx) => req('GetPresetInfo', u32words(idx));

/** cmd 15 (AEON flag variant of 12). writesStorage: always requires confirmWrite. Not for the 150. */
export function encodeSetPresetFileAeon(idx, blob, opts) {
  assertWriteConfirmed('SetPresetFile AEON variant (librarian cmd 15)', opts);
  return req('SetPresetFileAeon', concatBytes(u32words(idx, blob.length), blob));
}

// ------------------------------------------------------------------------------ responses

function cString(bytes) {
  let end = bytes.indexOf(0);
  if (end < 0) end = bytes.length;
  return new TextDecoder('utf-8').decode(bytes.subarray(0, end));
}

/**
 * Decode a librarian response body for `cmdId`. Status-less for 1, 2, 3, 5.
 * @returns {object}
 */
export function decodeLibrarianResponse(cmdId, body) {
  const info = LIBRARIAN_COMMANDS_BY_ID[cmdId];
  if (!info) throw new AmpProtocolError(`unknown librarian command ${cmdId}`);
  switch (cmdId) {
    case 1:
    case 2:
    case 5:
      return { value: readU32(body, 0) };
    case 3:
      return { table: body };
  }
  const status = readI32(body, 0);
  if (status < 0 || body.length <= 4) return { status };
  switch (cmdId) {
    case 6: {
      const nameLen = readU32(body, 4);
      return { status, nameLen, name: cString(body.subarray(8, 8 + Math.min(nameLen, body.length - 8))) };
    }
    case 7:
      return { status, uuid: readU64(body, 4) };
    case 8:
      return { status, checksum: readU32(body, 4) };
    case 10:
      return { status, size: readU32(body, 4) };
    case 11:
      return { status, blob: body.slice(4) };
    case 14: {
      const nameLen = readU32(body, 20);
      return {
        status,
        uuid: readU64(body, 4),
        checksum: readU32(body, 12),
        size: readU32(body, 16),
        nameLen,
        name: cString(body.subarray(24, 24 + Math.min(nameLen, 64, body.length - 24))),
      };
    }
    default:
      return { status };
  }
}

// ------------------------------------------------------------------------------ amp side (mock)

/** Decode a librarian request payload into named arguments (amp side). */
export function decodeLibrarianRequest(cmdId, payload) {
  switch (cmdId) {
    case 4:
      return { crc: readU32(payload, 0) };
    case 6:
    case 7:
    case 8:
    case 10:
    case 11:
    case 13:
    case 14:
      return { index: readU32(payload, 0) };
    case 9:
      return { dst: readU32(payload, 0), src: readU32(payload, 4) };
    case 12:
    case 15: {
      const index = readU32(payload, 0);
      const len = readU32(payload, 4);
      return { index, blob: payload.slice(8, 8 + len) };
    }
    default:
      return {};
  }
}

const enc = new TextEncoder();
const resp = (body) => encodeRpcInbound(INBOUND.RESPONSE, body);

/** u32 response without status (cmds 1, 2, 5). */
export const encodeLibU32Response = (v) => resp(u32words(v));
/** Status-only response. */
export const encodeLibStatusResponse = (status) => resp(u32words(status));
/** GetPresetName response: i32 status, u32 nameLen (incl. NUL, INFERRED), name + NUL. */
export function encodeLibPresetNameResponse(status, name) {
  const s = enc.encode(name).slice(0, MAX_PRESET_NAME - 1);
  return resp(concatBytes(u32words(status, s.length + 1), s, new Uint8Array(1)));
}
/** GetPresetFile response: i32 status, blob. */
export const encodeLibPresetFileResponse = (status, blob) => resp(concatBytes(u32words(status), blob));
/** i32 status + u32 (checksum / size). */
export const encodeLibStatusU32Response = (status, v) => resp(u32words(status, v));
/** GetPresetUUID response: i32 status, u64. */
export function encodeLibUuidResponse(status, uuid) {
  const b = new Uint8Array(12);
  viewOf(b).setInt32(0, status, true);
  viewOf(b).setBigUint64(4, BigInt(uuid), true);
  return resp(b);
}
/** GetPresetInfo response: i32 status, u64 uuid, u32 checksum, u32 size, u32 nameLen, char[64]. */
export function encodeLibPresetInfoResponse(status, { uuid, checksum, size, name }) {
  const b = new Uint8Array(4 + 8 + 4 + 4 + 4 + 64);
  const v = viewOf(b);
  const s = enc.encode(name).slice(0, MAX_PRESET_NAME - 1);
  v.setInt32(0, status, true);
  v.setBigUint64(4, BigInt(uuid), true);
  v.setUint32(12, checksum >>> 0, true);
  v.setUint32(16, size >>> 0, true);
  v.setUint32(20, s.length + 1, true);
  b.set(s, 24);
  return resp(b);
}
