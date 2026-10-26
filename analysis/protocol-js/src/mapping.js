// Editor-name layer: (group, paramID) as the official app uses them → DSP (slot, param) names →
// symbol indexes → editor command bytes.
//
// Spec: native_messages.md §2 (GetDSPSlotForGroupAndParam 0xeafcf, sendParamToDevice 0xdaa7a),
// §3 (setDeviceSetting 0xe15ac), §7 (tuner). AMPLIFi (non-AEON) tables only.
// This file contains only structural mapping tables (names), no Line 6 asset data.

import { TV, tvBool, tvFloat, tvInt, toFloat32 } from './values.js';
import { MappingError, AmpProtocolError } from './errors.js';
import { ROOT_SLOT_INDEX } from './symtab.js';
import {
  encodeBindTweakParam,
  encodeLoadDspModel,
  encodeSetDspModelParam,
  encodeSetGlobalTempo,
  encodeSetPersistentSysParam,
  encodeSetPresetPSKeyParam,
} from './editor.js';

/** Editor group ids (SlidersLogicLibConstants; default_preset.json "tone" keys). CONFIRMED (java_side.md §3.1). */
export const GROUPS = Object.freeze(['amp', 'cab', 'compressor', 'eq', 'fx1', 'fx2', 'fx3', 'gate', 'global', 'reverb', 'volume', 'wah']);

/**
 * GuitarProc table @0x23e540 (FUN_000eb6c2), non-AEON: [dspParam, group, editorParam].
 * '@'-params live on the root DSP slot "GuitarProc". CONFIRMED.
 */
export const GUITARPROC_PARAMS = Object.freeze([
  ['CabEnable', 'cab', '@enabled'],
  ['GateEnable', 'gate', '@enabled'],
  ['PostCompEnable', 'compressor', '@enabled'],
  ['PostEQEnable', 'eq', '@enabled'],
  ['WahEnable', 'wah', '@enabled'],
  ['VolumePedalEnable', 'volume', '@enabled'],
  ['FX1Enable', 'fx1', '@enabled'],
  ['FX2Enable', 'fx2', '@enabled'],
  ['FX3Enable', 'fx3', '@enabled'],
  ['FX4Enable', 'reverb', '@enabled'],
  ['VolumePost', 'volume', '@post'],
  ['FX1Post', 'fx1', '@post'],
  ['FX2Post', 'fx2', '@post'],
  ['FX3Post', 'fx3', '@post'],
  ['FX4Post', 'reverb', '@post'],
  ['FX1Mix', 'fx1', '@mix'],
  ['FX2Mix', 'fx2', '@mix'],
  ['FX3Mix', 'fx3', '@mix'],
  ['FX4Mix', 'reverb', '@mix'],
  ['FX1MixType', 'fx1', '@mixtype'],
  ['FX2MixType', 'fx2', '@mixtype'],
  ['FX3MixType', 'fx3', '@mixtype'], // reverb has no @mixtype (fails −4)
  ['ChannelVolume', 'amp', '@volume'],
]);

/** Root DSP slot holding the GuitarProc params. */
export const GUITARPROC_SLOT = 'GuitarProc';
/** Asset of the GuitarProc slot in preset blobs. */
export const GUITARPROC_ASSET = 'ToneMatchGuitarFlow';

/** GroupIDToSlotSymbol 0xeaec6 (table @0x23e820), non-AEON. CONFIRMED. */
export const GROUP_TO_SLOT = Object.freeze({
  gate: 'Gate',
  volume: 'VolumePedal',
  wah: 'Wah',
  fx1: 'FX1',
  fx2: 'FX2',
  fx3: 'FX3',
  reverb: 'FX4',
  amp: 'Amp',
  cab: 'StudioCab',
  compressor: 'PostComp',
  eq: 'PostEQ',
});

/** Reverse slot → group (preset_blob.py SLOT_GROUP; LiveCab and Air belong to cab). */
export const SLOT_TO_GROUP = Object.freeze({
  Gate: 'gate',
  VolumePedal: 'volume',
  Wah: 'wah',
  FX1: 'fx1',
  FX2: 'fx2',
  FX3: 'fx3',
  FX4: 'reverb',
  Amp: 'amp',
  StudioCab: 'cab',
  LiveCab: 'cab',
  Air: 'cab',
  PostComp: 'compressor',
  PostEQ: 'eq',
});

/** Mic suffixes appended to the cab model for StudioCab (table @0x23eb04). @mic 0..3. CONFIRMED. */
export const MIC_SUFFIXES = Object.freeze(['57OnAxis', '57OffAxis', '421', 'U67']);
export const NO_CABINET = '@NoCabinet';
/** StudioCab symbol used when the cab is @NoCabinet (preset_blob.py). */
export const NO_CABINET_STUDIO_SYMBOL = '2x12Line6Studio57OnAxis';

/** ParamIDToPSKey 0xeb1c9 (table @0x23e9e0), AMPLIFi part. CONFIRMED. */
export const PS_KEYS = Object.freeze({
  '@tempo': 3, // NOTE: @tempo is actually sent with SetGlobalTempo (cmd 14), not as a PS key
  '@tweakmin': 7,
  '@tweakmax': 8,
  '@pedal2assign': 9,
  '@modelmagmode': 25, // Variax keys 25..33: not relevant for the 150
  '@variaxmodel': 26,
  '@toneknob': 27,
  '@string1tuning': 28,
  '@string2tuning': 29,
  '@string3tuning': 30,
  '@string4tuning': 31,
  '@string5tuning': 32,
  '@string6tuning': 33,
});

/** ParamIDToSysParamKey 0xeb30b (table @0x23e480). CONFIRMED. Sent with SetPersistentSysParam (cmd 18). */
export const SYS_PARAM_KEYS = Object.freeze({
  TapTempoLED: 7,
  VariaxSettings: 8,
  VariaxTuningMode: 9,
  GlobalLowCut: 14,
  GlobalLowFreq: 15,
  GlobalLowQ: 16,
  GlobalLowGain: 17,
  GlobalMidFreq: 18,
  GlobalMidQ: 19,
  GlobalMidGain: 20,
  GlobalHighFreq: 21,
  GlobalHighQ: 22,
  GlobalHighGain: 23,
  GlobalHighCut: 24,
  GuitarOnlyGlobalEQ: 25,
  BypassGlobalEQ: 26,
  Divergence: 27,
  StereoWidth: 28,
  Crossover: 29, // sends a TypedValue tag 1 (symbol index)
});

/** setDeviceSetting name aliases. CONFIRMED (§3). */
export const DEVICE_SETTING_ALIASES = Object.freeze({ MasterVolume: 'Master', GuitarVolume: 'GuitOutputGain' });
/** Read-only device settings (setting them returns −4). CONFIRMED. */
export const READ_ONLY_DEVICE_SETTINGS = Object.freeze(['FBVConnected', 'VariaxConnected']);
/** Root-slot settings reported back as Device_SettingChanged by consumeRootSlotParamEvent. CONFIRMED. */
export const ROOT_DEVICE_SETTINGS = Object.freeze(['Master', 'GuitOutputGain']);

/** Tuner DSP address. CONFIRMED (§7). */
export const TUNER = Object.freeze({ slot: 'Tuner', enable: 'Enable', note: 'Note' });

/** Params that are integers even without model definitions (ranges from the notes). */
export const INT_PARAMS = new Set(['SyncSelect', '@mixtype', '@mic']);

/** Firmware gates (native_messages.md §9). Compared against the raw firmwareRevision (INFERRED which version word). */
export const FW_GATE = Object.freeze({
  PERSISTENT_SYS_PARAMS: 0x02000600, // cmds 17/18 need fw > 0x020005FF (FUN_001084af)
  PS_KEYS: 0x02110300, // cmds 19/20 need fw > 0x021102FF (FUN_001084fb)
  UI_EVENTS: 0x01000900, // fw ≤ 0x010008FF: no patch/param/tap/FBV events, librarian V1
});

/**
 * GetDSPSlotForGroupAndParam 0xeafcf (non-AEON). CONFIRMED.
 * @param {string} group
 * @param {string} paramId
 * @returns {{slot:string, param:string}}
 */
export function dspAddress(group, paramId) {
  if (paramId.startsWith('@')) {
    const row = GUITARPROC_PARAMS.find(([, g, p]) => g === group && p === paramId);
    if (!row) throw new MappingError(`no DSP mapping for ${group}/${paramId} on AMPLIFi (native returns −4)`);
    return { slot: GUITARPROC_SLOT, param: row[0] };
  }
  if (group === 'cab' && paramId === 'Level') return { slot: 'Air', param: 'Level' }; // exception
  const slot = GROUP_TO_SLOT[group];
  if (!slot) throw new MappingError(`no DSP slot for group ${group}`);
  return { slot, param: paramId };
}

/**
 * Reverse mapping used for inbound param events (GetGroupForDSPSlotAndParam; INFERRED to be the
 * inverse of dspAddress). Returns null for addresses that are not editor params.
 * @param {string} slot
 * @param {string} param
 * @returns {{group:string, paramId:string}|null}
 */
export function groupForDspAddress(slot, param) {
  if (slot === GUITARPROC_SLOT) {
    const row = GUITARPROC_PARAMS.find(([dsp]) => dsp === param);
    return row ? { group: row[1], paramId: row[2] } : null;
  }
  if (slot === 'Air' && param === 'Level') return { group: 'cab', paramId: 'Level' };
  const group = SLOT_TO_GROUP[slot];
  return group ? { group, paramId: param } : null;
}

/** CabModelAndMicToStudioCabSymbol: '<cab>' + mic suffix, e.g. 4x12BritT75Studio421. CONFIRMED. */
export function studioCabSymbol(cabModel, mic) {
  if (cabModel === NO_CABINET) return NO_CABINET_STUDIO_SYMBOL;
  const m = Math.round(Number(mic));
  if (!(m >= 0 && m < MIC_SUFFIXES.length)) throw new MappingError(`@mic must be 0..3, got ${mic}`);
  return cabModel + MIC_SUFFIXES[m];
}

/** Inverse of studioCabSymbol: '4x12BritT75Studio421' → { cab, mic: 2 }. */
export function parseStudioCabSymbol(symbol) {
  for (let m = 0; m < MIC_SUFFIXES.length; m++) {
    if (symbol.endsWith(MIC_SUFFIXES[m])) return { cab: symbol.slice(0, -MIC_SUFFIXES[m].length), mic: m };
  }
  return { cab: symbol, mic: null };
}

/**
 * Index model definitions (the `*.models` JSON arrays the app ships, loaded by YOUR code at
 * runtime - this library does not include them): symbolicID → model.
 * @param {...Array<{symbolicID:string, params?:Array}>} arrays
 */
export function indexModels(...arrays) {
  const out = {};
  for (const arr of arrays) for (const m of arr) out[m.symbolicID] = m;
  return out;
}

/** Param definition {valueType,min,max,default} of `paramId` in model `modelId`, or null. */
export function paramDefFor(models, modelId, paramId) {
  const m = models?.[modelId];
  return m?.params?.find((p) => p.symbolicID === paramId) ?? null;
}

const roundHalfAway = (v) => (v >= 0 ? Math.floor(v + 0.5) : -Math.floor(-v + 0.5));

/**
 * L6EdLibModelDefs::CheckParamValueForModel 0xc2e10 → TypedValue. CONFIRMED rules:
 *   valueType 1 float: number → clamp(min,max); non-number → default; → TV float
 *   valueType 0 int:   bool → 0/1; float → round half away from zero; (clamped, as preset_blob.py) → TV int
 *   valueType 2 bool:  truthiness → TV bool
 *   valueType 3 string: never sent as a TypedValue → throws
 * Without a definition: `type` ('float'|'int'|'bool') if given, else boolean → bool,
 * INT_PARAMS → int, anything else → float (no clamping).
 * @param {*} value
 * @param {{paramDef?:object|null, type?:'float'|'int'|'bool', paramId?:string}} [o]
 * @returns {import('./values.js').TypedValue}
 */
export function coerceValue(value, { paramDef = null, type, paramId } = {}) {
  if (paramDef) {
    const { valueType, min, max } = paramDef;
    if (valueType === 1) {
      let x = typeof value === 'number' ? value : Number(paramDef.default);
      x = Math.min(Math.max(x, Number(min)), Number(max));
      return tvFloat(x);
    }
    if (valueType === 0) {
      let x = typeof value === 'boolean' ? Number(value) : typeof value === 'number' ? (Number.isInteger(value) ? value : roundHalfAway(value)) : Number(paramDef.default);
      if (min !== undefined && max !== undefined) x = Math.min(Math.max(x, Number(min)), Number(max));
      return tvInt(x);
    }
    if (valueType === 2) return tvBool(typeof value === 'boolean' || typeof value === 'number' ? Boolean(value) : Boolean(paramDef.default));
    throw new MappingError(`${paramId ?? 'param'} is a string parameter (valueType 3); it is never sent as a TypedValue`);
  }
  const t = type ?? (typeof value === 'boolean' ? 'bool' : INT_PARAMS.has(paramId) ? 'int' : 'float');
  if (t === 'bool') return tvBool(Boolean(value));
  if (t === 'int') return tvInt(typeof value === 'boolean' ? Number(value) : roundHalfAway(Number(value)));
  if (t === 'float') return tvFloat(Number(value));
  throw new MappingError(`unknown value type ${t}`);
}

/**
 * @typedef {object} CommandPlan
 * @property {string} command      editor command name
 * @property {Uint8Array} request  bytes to write to the editor stream
 * @property {boolean} writesStorage
 * @property {object} [address]    {slot, param, slotIndex, paramIndex}
 * @property {import('./values.js').TypedValue} [value]
 * @property {string} [note]
 */

/**
 * Turn nativeSetEditBufferParam(group, paramId, value) into an editor request
 * (A36EditBufferContext::sendParamToDevice 0xdaa7a). CONFIRMED paths:
 *  - plain / '@' params                → cmd 10 SetDspModelParam {slotIdx, paramIdx, TV}
 *  - @temposync false/true             → cmd 10 on (FXn, SyncSelect) with int 0 / stored SyncSelect
 *  - cab/@mic                          → cmd 8 LoadDspModel {idx(StudioCab), idx(cab+suffix)}
 *  - global/@tempo                     → cmd 14 SetGlobalTempo(f32)
 *  - global/@tweakmin|@tweakmax|@pedal2assign → cmd 19 SetPresetPSKeyParam (needs confirmWrite)
 *  - global/@tweakgroup|@tweakparam    → cmd 13 BindTweakParam {slotIdx, paramIdx} of the target
 *  - @model                            → not a single message (partial preset blob): throws
 *
 * @param {object} o
 * @param {string} o.group
 * @param {string} o.paramId
 * @param {*} o.value
 * @param {import('./symtab.js').SymbolTable} o.symtab   the table the amp accepted
 * @param {object} [o.paramDef]      model param definition for coercion / clamping
 * @param {'float'|'int'|'bool'} [o.type]
 * @param {number} [o.syncSelect]    stored SyncSelect for @temposync=true
 * @param {string} [o.cabModel]      current cab @model for @mic
 * @param {{group:string, param:string}} [o.tweak]  target for @tweakgroup/@tweakparam
 * @param {boolean} [o.confirmWrite]
 * @returns {CommandPlan}
 */
export function planSetParam({ group, paramId, value, symtab, paramDef, type, syncSelect, cabModel, tweak, confirmWrite }) {
  if (paramId === '@model') {
    throw new MappingError('@model changes are sent as a partial preset blob (librarian SetPresetFile to the edit buffer), not a single editor message; build one with presetBlob.encodeToneJson(…, {group}) and AmpSession.writeEditBuffer()');
  }
  if (paramId === '@stereo') throw new MappingError('@stereo exists only on AEON (native returns −4 on the 150)');
  if (group === 'global') {
    if (paramId === '@tempo') {
      let bpm = Number(value);
      if (paramDef) bpm = Math.min(Math.max(bpm, Number(paramDef.min)), Number(paramDef.max));
      return { command: 'SetGlobalTempo', request: encodeSetGlobalTempo(bpm), writesStorage: false, value: tvFloat(bpm) };
    }
    if (paramId === '@tweakgroup' || paramId === '@tweakparam') {
      if (!tweak?.group || !tweak?.param) throw new MappingError('@tweakgroup/@tweakparam need opts.tweak = {group, param} (the tweaked parameter)');
      const a = dspAddress(tweak.group, tweak.param);
      const slotIndex = symtab.lookup(a.slot);
      const paramIndex = symtab.lookup(a.param);
      return { command: 'BindTweakParam', request: encodeBindTweakParam(slotIndex, paramIndex), writesStorage: false, address: { ...a, slotIndex, paramIndex } };
    }
    if (paramId in PS_KEYS) {
      const tv = coerceValue(value, { paramDef, type: type ?? (paramId === '@pedal2assign' ? 'bool' : undefined), paramId });
      return { command: 'SetPresetPSKeyParam', request: encodeSetPresetPSKeyParam(PS_KEYS[paramId], tv, { confirmWrite }), writesStorage: true, value: tv, note: 'fw gate ≥ 0x02110300' };
    }
    throw new MappingError(`unknown global param ${paramId}`);
  }
  if (group === 'cab' && paramId === '@mic') {
    if (!cabModel) throw new MappingError('cab/@mic needs opts.cabModel (current cab @model)');
    const sym = studioCabSymbol(cabModel, value);
    const slotIndex = symtab.lookup('StudioCab');
    const modelIndex = symtab.lookup(sym);
    return { command: 'LoadDspModel', request: encodeLoadDspModel(slotIndex, modelIndex), writesStorage: false, address: { slot: 'StudioCab', param: sym, slotIndex, paramIndex: modelIndex } };
  }
  if (paramId === '@temposync') {
    const slot = GROUP_TO_SLOT[group];
    if (!slot || !/^fx[123]$/.test(group)) throw new MappingError(`@temposync only exists on fx1..fx3, not ${group}`);
    let tv;
    if (!value) tv = tvInt(0);
    else {
      if (syncSelect == null) throw new MappingError('@temposync=true sends the stored SyncSelect value; pass opts.syncSelect (1..14)');
      tv = tvInt(syncSelect);
    }
    const slotIndex = symtab.lookup(slot);
    const paramIndex = symtab.lookup('SyncSelect');
    return { command: 'SetDspModelParam', request: encodeSetDspModelParam(slotIndex, paramIndex, tv), writesStorage: false, address: { slot, param: 'SyncSelect', slotIndex, paramIndex }, value: tv };
  }
  const a = dspAddress(group, paramId);
  const tv = coerceValue(value, { paramDef, type, paramId });
  const slotIndex = symtab.lookup(a.slot);
  const paramIndex = symtab.lookup(a.param);
  return { command: 'SetDspModelParam', request: encodeSetDspModelParam(slotIndex, paramIndex, tv), writesStorage: false, address: { ...a, slotIndex, paramIndex }, value: tv };
}

/**
 * nativeSetDeviceSetting(name, value) → editor request (A36EditorLibrarian::setDeviceSetting 0xe15ac).
 * CONFIRMED: aliases; SYS_PARAM_KEYS → cmd 18 (persistent; needs confirmWrite; fw gate);
 * read-only names throw; anything else → cmd 10 on the root slot 0xFFFFFFFF as float32
 * (Master, GuitOutputGain; range 0..1 INFERRED).
 */
export function planDeviceSetting({ name, value, symtab, type, confirmWrite }) {
  const n = DEVICE_SETTING_ALIASES[name] ?? name;
  if (READ_ONLY_DEVICE_SETTINGS.includes(n)) throw new MappingError(`${n} is read-only (native returns −4)`);
  if (n in SYS_PARAM_KEYS) {
    let tv;
    if (n === 'Crossover') {
      if (typeof value !== 'string') throw new MappingError('Crossover takes a symbol name');
      tv = { tag: TV.SYMBOL, bits: symtab.lookup(value) };
    } else {
      tv = coerceValue(value, { type: type ?? (typeof value === 'boolean' ? 'bool' : 'float'), paramId: n });
    }
    return { command: 'SetPersistentSysParam', request: encodeSetPersistentSysParam(SYS_PARAM_KEYS[n], tv, { confirmWrite }), writesStorage: true, value: tv, key: SYS_PARAM_KEYS[n], name: n };
  }
  const tv = coerceValue(value, { type: type ?? 'float', paramId: n });
  const paramIndex = symtab.lookup(n);
  return {
    command: 'SetDspModelParam',
    request: encodeSetDspModelParam(ROOT_SLOT_INDEX, paramIndex, tv),
    writesStorage: false,
    value: tv,
    name: n,
    address: { slot: '', param: n, slotIndex: ROOT_SLOT_INDEX, paramIndex },
  };
}

/** Float values for @enabled count as "on" when > 0.1 (handleParamEvent). CONFIRMED. */
export function enabledFromTypedValue(tv) {
  if (tv.tag === TV.FLOAT) return toFloat32(new Float32Array(new Uint32Array([tv.bits]).buffer)[0]) > 0.1;
  return tv.bits !== 0;
}

export { AmpProtocolError };

/**
 * Which editor command a (group, paramId) edit will use — computed WITHOUT encoding anything,
 * so callers can run the guard.js allow-list check before any bytes exist.
 * @returns {number} editor command id
 */
export function editorCommandForParam(group, paramId) {
  if (group === 'global') {
    if (paramId === '@tempo') return 14;
    if (paramId === '@tweakgroup' || paramId === '@tweakparam') return 13;
    if (paramId in PS_KEYS) return 19;
    throw new MappingError(`unknown global param ${paramId}`);
  }
  if (group === 'cab' && paramId === '@mic') return 8;
  return 10;
}

/** Editor command id a device setting will use (18 persistent sys param, else 10 root slot). */
export function editorCommandForDeviceSetting(name) {
  const n = DEVICE_SETTING_ALIASES[name] ?? name;
  return n in SYS_PARAM_KEYS ? 18 : 10;
}
