// Editor service (stream 0x2002 <-> 0x03ED): request encoders, response and event decoders,
// plus amp-side encoders (used by the mock amp and by capture analysis).
//
// Spec: native_messages.md §8 command table, §6 inbound events; native_transport.md §6.4.
// Every request = u32 cmd, u32 len, payload (ToneMatchEdit_Remote::DoCommandCommon 0x103850).
// Editor responses are RAW: they start with an i32 status only where `responseHasStatus`.

import { decodeTypedValue, encodeTypedValue, f32le, readF32, readI32, readU32, TV, u32words, concatBytes, EMPTY, tvBool, tvFloat, tvInt } from './values.js';
import { encodeRpcInbound, encodeRpcRequest, INBOUND } from './rpc.js';
import { assertWriteConfirmed } from './guard.js';
import { AmpProtocolError } from './errors.js';

/**
 * @typedef {object} CommandInfo
 * @property {number} id
 * @property {string} name
 * @property {'CONFIRMED'|'INFERRED'} status   how well the layout is established
 * @property {boolean} writesStorage           modifies the amp's persistent data
 * @property {boolean} responseHasStatus       response body starts with i32 status
 * @property {number|null} timeoutMs           null = no timeout
 * @property {string} source                   native function it was read from
 * @property {string} [note]
 */

/** @type {Record<string, CommandInfo>} */
export const EDITOR_COMMANDS = Object.freeze({
  GetVersion: { id: 1, name: 'GetVersion', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::GetVersion 0x1039d2' },
  GetSymbolTableSize: { id: 2, name: 'GetSymbolTableSize', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::GetSymbolTableSize 0x103a6e' },
  GetSymbolTable: { id: 3, name: 'GetSymbolTable', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: null, source: 'ToneMatchEdit_Remote::GetSymbolTable 0x103b0a', note: 'no timeout; body = raw table' },
  Handshake: { id: 4, name: 'Handshake', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::Handshake 0x103bac' },
  GetNumAddressableSlots: { id: 5, name: 'GetNumAddressableSlots', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'DoCommandCommon call site', note: 'unused by the app' },
  GetAddressableSlots: { id: 6, name: 'GetAddressableSlots', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'DoCommandCommon call site', note: 'unused by the app' },
  QueryCurrentDspModel: { id: 7, name: 'QueryCurrentDspModel', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'DoCommandCommon call site', note: 'unused by the app' },
  LoadDspModel: { id: 8, name: 'LoadDspModel', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::LoadDspModel 0x103e86' },
  GetDspModelParam: { id: 9, name: 'GetDspModelParam', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::GetDspModelParam 0x103f50' },
  SetDspModelParam: { id: 10, name: 'SetDspModelParam', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::SetModelParamCommon 0x10403e' },
  RegisterDspEvent: { id: 11, name: 'RegisterDspEvent', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::RegisterDspEvent 0x104ef6' },
  UnregisterDspEvent: { id: 12, name: 'UnregisterDspEvent', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::UnregisterDspEvent 0x10519c' },
  BindTweakParam: { id: 13, name: 'BindTweakParam', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 1000, source: 'ToneMatchEdit_Remote::BindTweakParam 0x1053e0' },
  SetGlobalTempo: { id: 14, name: 'SetGlobalTempo', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::SetGlobalTempo 0x1054aa' },
  GetDirtyState: { id: 15, name: 'GetDirtyState', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::GetDirtyState 0x105558' },
  GetFbvConnectivityStatus: { id: 16, name: 'GetFbvConnectivityStatus', status: 'CONFIRMED', writesStorage: false, responseHasStatus: false, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::GetFbvConnectivityStatus 0x1055f4' },
  GetPersistentSysParam: { id: 17, name: 'GetPersistentSysParam', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'DoCommandCommon call site', note: 'AMPLIFi fw gate ≥ 0x02000600' },
  SetPersistentSysParam: { id: 18, name: 'SetPersistentSysParam', status: 'CONFIRMED', writesStorage: true, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::SetPersistentSysParam 0x105768', note: 'persistent system setting; AMPLIFi fw gate ≥ 0x02000600' },
  SetPresetPSKeyParam: { id: 19, name: 'SetPresetPSKeyParam', status: 'CONFIRMED', writesStorage: true, responseHasStatus: true, timeoutMs: 5000, source: 'ToneMatchEdit_Remote::SetPresetPSKeyParam 0x105980', note: 'listed as "modifies stored data" in the notes; AMPLIFi fw gate ≥ 0x02110300' },
  GetPresetPSKeyParam: { id: 20, name: 'GetPresetPSKeyParam', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'DoCommandCommon call site' },
  GetSystemSetting: { id: 21, name: 'GetSystemSetting', status: 'CONFIRMED', writesStorage: false, responseHasStatus: true, timeoutMs: 5000, source: 'DoCommandCommon call site', note: 'AEON only' },
  SetSystemSetting: { id: 22, name: 'SetSystemSetting', status: 'CONFIRMED', writesStorage: true, responseHasStatus: true, timeoutMs: 5000, source: 'DoCommandCommon call site', note: 'AEON only' },
});

/** id -> CommandInfo */
export const EDITOR_COMMANDS_BY_ID = Object.freeze(Object.fromEntries(Object.values(EDITOR_COMMANDS).map((c) => [c.id, c])));

/** Command ids by name, e.g. EDITOR_CMD.SetDspModelParam === 10. */
export const EDITOR_CMD = Object.freeze(Object.fromEntries(Object.values(EDITOR_COMMANDS).map((c) => [c.name, c.id])));

const req = (name, payload = EMPTY) => encodeRpcRequest(EDITOR_COMMANDS[name].id, payload);

// ------------------------------------------------------------------------------ requests

/** cmd 1. CONFIRMED. Response: u32 version (no status). */
export const encodeGetVersion = () => req('GetVersion');
/** cmd 2. CONFIRMED. Response: u32 table size. */
export const encodeGetSymbolTableSize = () => req('GetSymbolTableSize');
/** cmd 3. CONFIRMED. Response: raw table bytes. No timeout. */
export const encodeGetSymbolTable = () => req('GetSymbolTable');
/** cmd 4 Handshake(u32 crc32 of symbol table). CONFIRMED. Response: i32 status (≥ 0 ok). */
export const encodeHandshake = (crc) => req('Handshake', u32words(crc));
/** cmd 5. CONFIRMED (unused by the app). Response: u32. */
export const encodeGetNumAddressableSlots = () => req('GetNumAddressableSlots');
/** cmd 6. CONFIRMED (unused by the app). Response: u32[n]. */
export const encodeGetAddressableSlots = () => req('GetAddressableSlots');
/** cmd 7 {u32 slot}. CONFIRMED (unused). Response: i32 status, u32 model. */
export const encodeQueryCurrentDspModel = (slot) => req('QueryCurrentDspModel', u32words(slot));
/** cmd 8 LoadDspModel {u32 slot, u32 model}. CONFIRMED. Used for the cab mic change. */
export const encodeLoadDspModel = (slot, model) => req('LoadDspModel', u32words(slot, model));
/** cmd 9 GetDspModelParam {u32 slot, u32 param}. CONFIRMED. Response: i32 status, TypedValue. */
export const encodeGetDspModelParam = (slot, param) => req('GetDspModelParam', u32words(slot, param));
/** cmd 10 SetDspModelParam {u32 slot, u32 param, TypedValue}. CONFIRMED. Response: i32 status. */
export const encodeSetDspModelParam = (slot, param, tv) => req('SetDspModelParam', concatBytes(u32words(slot, param), encodeTypedValue(tv)));
/** cmd 11 RegisterDspEvent {u32 slot, u32 param}. CONFIRMED (tuner Note). */
export const encodeRegisterDspEvent = (slot, param) => req('RegisterDspEvent', u32words(slot, param));
/** cmd 12 UnregisterDspEvent {u32 slot, u32 param}. CONFIRMED. */
export const encodeUnregisterDspEvent = (slot, param) => req('UnregisterDspEvent', u32words(slot, param));
/** cmd 13 BindTweakParam {u32 slot, u32 param}. CONFIRMED. 1000 ms timeout. */
export const encodeBindTweakParam = (slot, param) => req('BindTweakParam', u32words(slot, param));
/** cmd 14 SetGlobalTempo {f32 bpm}. CONFIRMED. 30..240 BPM. */
export const encodeSetGlobalTempo = (bpm) => req('SetGlobalTempo', f32le(bpm));
/** cmd 15. CONFIRMED. Response: u32 (no status). */
export const encodeGetDirtyState = () => req('GetDirtyState');
/** cmd 16. CONFIRMED. Response: u32 (no status). */
export const encodeGetFbvConnectivityStatus = () => req('GetFbvConnectivityStatus');
/** cmd 17 {u32 key}. CONFIRMED. Response: i32 status, TypedValue. */
export const encodeGetPersistentSysParam = (key) => req('GetPersistentSysParam', u32words(key));

/**
 * cmd 18 SetPersistentSysParam {u32 key, TypedValue}. CONFIRMED. writesStorage: requires
 * { confirmWrite: true }.
 */
export function encodeSetPersistentSysParam(key, tv, opts) {
  assertWriteConfirmed('SetPersistentSysParam (editor cmd 18)', opts);
  return req('SetPersistentSysParam', concatBytes(u32words(key), encodeTypedValue(tv)));
}

/**
 * cmd 19 SetPresetPSKeyParam {u32 key, TypedValue}. CONFIRMED. Listed by the notes among the
 * commands that modify stored data: requires { confirmWrite: true }.
 */
export function encodeSetPresetPSKeyParam(key, tv, opts) {
  assertWriteConfirmed('SetPresetPSKeyParam (editor cmd 19)', opts);
  return req('SetPresetPSKeyParam', concatBytes(u32words(key), encodeTypedValue(tv)));
}

/** cmd 20 {u32 key}. CONFIRMED. Response: i32 status, TypedValue. */
export const encodeGetPresetPSKeyParam = (key) => req('GetPresetPSKeyParam', u32words(key));
/** cmd 21 {u32 key}. CONFIRMED, AEON only. */
export const encodeGetSystemSetting = (key) => req('GetSystemSetting', u32words(key));

/** cmd 22 {u32 key, TypedValue}. CONFIRMED, AEON only. writesStorage: requires confirmWrite. */
export function encodeSetSystemSetting(key, tv, opts) {
  assertWriteConfirmed('SetSystemSetting (editor cmd 22)', opts);
  return req('SetSystemSetting', concatBytes(u32words(key), encodeTypedValue(tv)));
}

// ------------------------------------------------------------------------------ responses

/**
 * Decode an editor response body for command `cmdId`.
 * @returns {object} e.g. {value}, {status}, {status, value:TypedValue}, {table}, {slots}
 */
export function decodeEditorResponse(cmdId, body) {
  const info = EDITOR_COMMANDS_BY_ID[cmdId];
  if (!info) throw new AmpProtocolError(`unknown editor command ${cmdId}`);
  switch (cmdId) {
    case 1:
    case 2:
    case 5:
    case 15:
    case 16:
      return { value: readU32(body, 0) };
    case 3:
      return { table: body };
    case 6: {
      const slots = [];
      for (let o = 0; o + 4 <= body.length; o += 4) slots.push(readU32(body, o));
      return { slots };
    }
    case 7:
      return { status: readI32(body, 0), model: readU32(body, 4) };
    case 9:
    case 17:
    case 20:
    case 21:
      return { status: readI32(body, 0), value: body.length >= 12 ? decodeTypedValue(body, 4) : null };
    default:
      return { status: readI32(body, 0) };
  }
}

// ------------------------------------------------------------------------------ events (amp → phone)

/** Editor inbound event names by type. */
export const EDITOR_EVENT_NAMES = Object.freeze({
  2: 'dsp',
  3: 'patch',
  4: 'param',
  5: 'tapTempo',
  6: 'fbvStatus',
  7: 'psKeyChange',
  8: 'sysSettingChange',
});

/**
 * Decode an editor event body (types 2..8, ≤ 16 bytes). CONFIRMED (§6 inbound table).
 * @returns {object}
 */
export function decodeEditorEvent(type, body) {
  switch (type) {
    case INBOUND.DSP_EVENT: // u32 slot, u32 param, TV
    case INBOUND.PARAM_EVENT:
      return { type, name: EDITOR_EVENT_NAMES[type], slot: readU32(body, 0), param: readU32(body, 4), value: decodeTypedValue(body, 8) };
    case INBOUND.PATCH_EVENT: // TV int presetIndex, TV int isSave
      return { type, name: 'patch', presetIndex: decodeTypedValue(body, 0), isSave: decodeTypedValue(body, 8) };
    case INBOUND.TAP_TEMPO_EVENT: // TV float BPM
    case INBOUND.FBV_STATUS_EVENT: // TV float (> 0 connected)
      return { type, name: EDITOR_EVENT_NAMES[type], value: decodeTypedValue(body, 0) };
    case INBOUND.PSKEY_CHANGE_EVENT: // u32 key, TV
    case INBOUND.SYS_SETTING_CHANGE_EVENT:
      return { type, name: EDITOR_EVENT_NAMES[type], key: readU32(body, 0), value: decodeTypedValue(body, 4) };
    default:
      throw new AmpProtocolError(`unknown editor event type ${type}`);
  }
}

/**
 * Decode a full inbound editor message (u32 type, u32 len, body) such as the test vectors.
 */
export function decodeEditorInbound(bytes) {
  const type = readU32(bytes, 0);
  const len = readU32(bytes, 4);
  const body = bytes.slice(8, 8 + len);
  if (type === INBOUND.RESPONSE) return { type, name: 'response', body };
  if (type === INBOUND.NONE) return { type, name: 'none' };
  return decodeEditorEvent(type, body);
}

// ------------------------------------------------------------------------------ amp side (mock)

/** Decode an editor request payload into named arguments (amp side). */
export function decodeEditorRequest(cmdId, payload) {
  const tv = (o) => decodeTypedValue(payload, o);
  switch (cmdId) {
    case 4:
      return { crc: readU32(payload, 0) };
    case 7:
      return { slot: readU32(payload, 0) };
    case 8:
      return { slot: readU32(payload, 0), model: readU32(payload, 4) };
    case 9:
    case 11:
    case 12:
    case 13:
      return { slot: readU32(payload, 0), param: readU32(payload, 4) };
    case 10:
      return { slot: readU32(payload, 0), param: readU32(payload, 4), value: tv(8) };
    case 14:
      return { bpm: readF32(payload, 0) };
    case 17:
    case 20:
    case 21:
      return { key: readU32(payload, 0) };
    case 18:
    case 19:
    case 22:
      return { key: readU32(payload, 0), value: tv(4) };
    default:
      return {};
  }
}

/** Response with a raw u32 body. */
export const encodeU32Response = (v) => encodeRpcInbound(INBOUND.RESPONSE, u32words(v));
/** Response with an i32 status. */
export const encodeStatusResponse = (status) => encodeRpcInbound(INBOUND.RESPONSE, u32words(status));
/** Response with i32 status + TypedValue. */
export const encodeStatusValueResponse = (status, tv) => encodeRpcInbound(INBOUND.RESPONSE, concatBytes(u32words(status), encodeTypedValue(tv)));
/** Response with raw bytes. */
export const encodeRawResponse = (bytes) => encodeRpcInbound(INBOUND.RESPONSE, bytes);

/** Type-2 DSP event {slot, param, TV} (tuner Note). */
export const encodeDspEvent = (slot, param, tv) => encodeRpcInbound(INBOUND.DSP_EVENT, concatBytes(u32words(slot, param), encodeTypedValue(tv)));
/** Type-3 patch event {TV int presetIndex, TV int isSave}. */
export const encodePatchEvent = (presetIndex, isSave = false) => encodeRpcInbound(INBOUND.PATCH_EVENT, concatBytes(encodeTypedValue(tvInt(presetIndex)), encodeTypedValue(tvInt(isSave ? 1 : 0))));
/** Type-4 param event {slot, param, TV}. */
export const encodeParamEvent = (slot, param, tv) => encodeRpcInbound(INBOUND.PARAM_EVENT, concatBytes(u32words(slot, param), encodeTypedValue(tv)));
/** Type-5 tap tempo event {TV float BPM}. */
export const encodeTapTempoEvent = (bpm) => encodeRpcInbound(INBOUND.TAP_TEMPO_EVENT, encodeTypedValue(tvFloat(bpm)));
/** Type-6 FBV status event {TV float}. */
export const encodeFbvStatusEvent = (connected) => encodeRpcInbound(INBOUND.FBV_STATUS_EVENT, encodeTypedValue(tvFloat(connected ? 1 : 0)));
/** Type-7 PS-key change event {u32 key, TV}. */
export const encodePsKeyChangeEvent = (key, tv) => encodeRpcInbound(INBOUND.PSKEY_CHANGE_EVENT, concatBytes(u32words(key), encodeTypedValue(tv)));

export { TV, tvBool, tvFloat, tvInt };

// ------------------------------------------------------------------------------ tuner math

/** Note names for the tuner note index (0 = A … 11 = G#/Ab), as Java tunerValue(note, cents) uses. */
export const TUNER_NOTE_NAMES = Object.freeze(['A', 'A#/Bb', 'B', 'C', 'C#/Db', 'D', 'D#/Eb', 'E', 'F', 'F#/Gb', 'G', 'G#/Ab']);

/**
 * convertA36TunerValueToNoteCents 0xea729 (CONFIRMED math, amp-side semantics INFERRED):
 * v = pitch in semitones above A within one octave, [0, 12); v ≥ 11.5 wraps to v − 12;
 * f = 440·2^(v/12); note = bucket of f (0 = A … 11 = G#); cents = 1200·log2(f / f_note);
 * v < 0 or v ≥ 12 → note −1 (no signal).
 * @param {number} v
 * @returns {{note:number, cents:number, name:string|null}}
 */
export function tunerValueToNoteCents(v) {
  if (!(v >= 0 && v < 12)) return { note: -1, cents: 0, name: null };
  if (v >= 11.5) v -= 12;
  const f = 440 * 2 ** (v / 12);
  for (let n = 0; n < 12; n++) {
    const lo = 440 * 2 ** ((n - 0.5) / 12);
    const hi = 440 * 2 ** ((n + 0.5) / 12);
    if (lo <= f && f < hi) {
      return { note: n, cents: Math.log2(f / (440 * 2 ** (n / 12))) * 1200, name: TUNER_NOTE_NAMES[n] };
    }
  }
  return { note: -1, cents: 0, name: null };
}
