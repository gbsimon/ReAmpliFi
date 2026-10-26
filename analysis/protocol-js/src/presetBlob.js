// Device-preset ("SPe") blob codec. *** INFERRED *** — static re-implementation of
// L6A36Preset::SerializeToDeviceForGroup 0xfa480 + L6SPePresetSerializer 0x100302.. (serializer)
// and the parser at 0x100eec. Port of analysis/scripts/preset_blob.py. NOT verified on hardware:
// state order inside a slot is UNKNOWN (hash order on the amp); the amp probably matches by symbol.
//
// Guarantee: encodeBlobRecords(decodeBlobRecords(bytes)) reproduces `bytes` exactly for any blob
// this module decoded (unknown tags and non-canonical payloads are kept raw).
//
// Record = u32 key LE, u16 tag LE, payload. Blob tags are NOT the editor TypedValue tags:
//   0 void (no payload) | 1 bool u32 | 2 int i32 | 3 float f32 | 4 string: u32 len (incl. NUL) + bytes
//   6 varray: u32 word count + words | 7 symbol: u32 symbol INDEX
// Directive keys: 0x80000000 SectionID, 0x80000001 SectionMagic, 0x80000002 SectionEnd,
//   0x80000003 SlotStart(symbol), 0x80000004 SlotEnd, 0x80000005 Asset(symbol), 0x80000006 StateCount(int)

import { concatBytes, readU16, readU32, readI32, readF32, viewOf, TV, float32ToBits, bitsToFloat32 } from './values.js';
import { AmpProtocolError } from './errors.js';
import { GUITARPROC_PARAMS, GUITARPROC_SLOT, GUITARPROC_ASSET, GROUP_TO_SLOT, SLOT_TO_GROUP, MIC_SUFFIXES, NO_CABINET, NO_CABINET_STUDIO_SYMBOL, dspAddress } from './mapping.js';

export const STATUS = 'INFERRED';

/** Blob record tags (≠ editor TypedValue tags). */
export const BLOB_TAG = Object.freeze({ VOID: 0, BOOL: 1, INT: 2, FLOAT: 3, STRING: 4, VARRAY: 6, SYMBOL: 7 });
const TAG_NAME = { 0: 'void', 1: 'bool', 2: 'int', 3: 'float', 4: 'string', 6: 'varray', 7: 'symbol' };
const TAG_BY_NAME = { void: 0, bool: 1, int: 2, float: 3, string: 4, varray: 6, symbol: 7 };

export const DIRECTIVE = Object.freeze({
  SECTION_ID: 0x80000000,
  SECTION_MAGIC: 0x80000001,
  SECTION_END: 0x80000002,
  SLOT_START: 0x80000003,
  SLOT_END: 0x80000004,
  ASSET: 0x80000005,
  STATE_COUNT: 0x80000006,
});

export const SECTION = Object.freeze({ PS: 2, DSP: 1 });
export const SECTION_MAGIC = Object.freeze({ PS: 0x50525350 /* "PSRP" */, DSP: 0x47545254 /* "TRTG" */ });

/** PS-section keys. */
export const PS_KEY = Object.freeze({ NAME: 0, TNID_LO: 1, TNID_HI: 2, TEMPO: 3, TWEAK_SLOT: 4, TWEAK_PARAM: 5, TWEAKMIN: 7, TWEAKMAX: 8, PEDAL2ASSIGN: 9 });

/** Full-tone DSP slot order (child slots of GuitarProc). */
export const FULL_SLOTS = Object.freeze(['Gate', 'VolumePedal', 'Wah', 'FX1', 'FX2', 'FX3', 'FX4', 'Amp', 'Air', 'StudioCab', 'LiveCab', 'PostComp', 'PostEQ']);

/** PS keys taken from editor params: key → [group, param, blob tag]. */
const PSKEY_PARAM = {
  3: ['global', '@tempo', BLOB_TAG.FLOAT],
  7: ['global', '@tweakmin', BLOB_TAG.FLOAT],
  8: ['global', '@tweakmax', BLOB_TAG.FLOAT],
  9: ['global', '@pedal2assign', BLOB_TAG.BOOL],
};

/** Blob size limit (librarian). */
export const MAX_BLOB_SIZE = 0x8000;

const utf8 = new TextEncoder();
const utf8d = new TextDecoder('utf-8');

// ------------------------------------------------------------------------------ records

/**
 * @typedef {object} BlobRecord
 * @property {number} key
 * @property {number} tag      blob tag
 * @property {*} value         bool→boolean, int→number, float→number, string→string,
 *                             symbol→index (signed: −1 = missing), varray→Uint32 words[], void→null
 * @property {Uint8Array} [raw] exact payload bytes when the value form is not canonical
 */

function encodeValue(tag, value) {
  const b4 = (fn) => {
    const b = new Uint8Array(4);
    fn(viewOf(b));
    return b;
  };
  switch (tag) {
    case BLOB_TAG.VOID:
      return new Uint8Array(0);
    case BLOB_TAG.BOOL:
      return b4((v) => v.setUint32(0, value === true ? 1 : value === false ? 0 : value >>> 0, true));
    case BLOB_TAG.INT:
      return b4((v) => v.setInt32(0, value | 0, true));
    case BLOB_TAG.FLOAT:
      return b4((v) => v.setFloat32(0, value, true));
    case BLOB_TAG.SYMBOL:
      return b4((v) => v.setUint32(0, value >>> 0, true));
    case BLOB_TAG.STRING: {
      const s = utf8.encode(value);
      const out = new Uint8Array(4 + s.length + 1);
      viewOf(out).setUint32(0, s.length + 1, true);
      out.set(s, 4);
      return out;
    }
    case BLOB_TAG.VARRAY: {
      const out = new Uint8Array(4 + 4 * value.length);
      viewOf(out).setUint32(0, value.length, true);
      value.forEach((w, i) => viewOf(out).setUint32(4 + 4 * i, w >>> 0, true));
      return out;
    }
    default:
      throw new AmpProtocolError(`cannot encode blob tag ${tag} without raw bytes`);
  }
}

/**
 * Decode a blob into its flat record list (lossless).
 * @param {Uint8Array} bytes
 * @returns {{records: BlobRecord[], trailer: Uint8Array}}
 */
export function decodeBlobRecords(bytes) {
  const records = [];
  let o = 0;
  while (o + 6 <= bytes.length) {
    const key = readU32(bytes, o);
    const tag = readU16(bytes, o + 4);
    const start = o + 6;
    let end;
    let value;
    if (tag === BLOB_TAG.VOID) {
      end = start;
      value = null;
    } else if (tag === BLOB_TAG.STRING) {
      if (start + 4 > bytes.length) break;
      const n = readU32(bytes, start);
      end = start + 4 + n;
      if (end > bytes.length) break;
      const sb = bytes.subarray(start + 4, end);
      const nul = sb.indexOf(0);
      value = utf8d.decode(nul >= 0 ? sb.subarray(0, nul) : sb);
    } else if (tag === BLOB_TAG.VARRAY) {
      if (start + 4 > bytes.length) break;
      const n = readU32(bytes, start);
      end = start + 4 + 4 * n;
      if (end > bytes.length) break;
      value = [];
      for (let i = 0; i < n; i++) value.push(readU32(bytes, start + 4 + 4 * i));
    } else {
      end = start + 4;
      if (end > bytes.length) break;
      if (tag === BLOB_TAG.BOOL) value = readU32(bytes, start) !== 0;
      else if (tag === BLOB_TAG.INT) value = readI32(bytes, start);
      else if (tag === BLOB_TAG.FLOAT) value = readF32(bytes, start);
      else if (tag === BLOB_TAG.SYMBOL) value = readI32(bytes, start);
      else value = readU32(bytes, start); // unknown tag: 4-byte payload, as preset_blob.py assumes
    }
    const payload = bytes.subarray(start, end);
    const rec = { key, tag, value };
    // keep raw bytes whenever re-encoding the value would not give the same payload
    const known = tag in TAG_NAME;
    let canonical = false;
    if (known) {
      try {
        const re = encodeValue(tag, value);
        canonical = re.length === payload.length && re.every((b, i) => b === payload[i]);
      } catch {
        canonical = false;
      }
    }
    if (!canonical) rec.raw = payload.slice();
    records.push(rec);
    o = end;
  }
  return { records, trailer: bytes.slice(o) };
}

/**
 * Encode records back to bytes. Accepts the object returned by decodeBlobRecords or a plain array.
 * A record with `raw` is written with exactly those payload bytes.
 */
export function encodeBlobRecords(input) {
  const records = Array.isArray(input) ? input : input.records;
  const trailer = Array.isArray(input) ? new Uint8Array(0) : input.trailer ?? new Uint8Array(0);
  const parts = [];
  for (const r of records) {
    const head = new Uint8Array(6);
    viewOf(head).setUint32(0, r.key >>> 0, true);
    viewOf(head).setUint16(4, r.tag, true);
    parts.push(head, r.raw ?? encodeValue(r.tag, r.value));
  }
  parts.push(trailer);
  return concatBytes(...parts);
}

/** Change a record's value (drops its raw bytes so the new value is encoded). */
export function setRecordValue(rec, value) {
  rec.value = value;
  delete rec.raw;
  return rec;
}

// ------------------------------------------------------------------------------ structured view

/**
 * @typedef {object} PresetState
 * @property {string} name   state symbol, e.g. "DriveState"
 * @property {string} param  e.g. "Drive"
 * @property {'bool'|'int'|'float'|'string'|'symbol'|'varray'|'void'} type
 * @property {*} value
 *
 * @typedef {object} PresetSlot
 * @property {string} slot   DSP slot name (e.g. "Amp")
 * @property {string|null} asset  model symbol (e.g. "BritGainJ800")
 * @property {PresetState[]} states
 * @property {PresetSlot[]} children
 *
 * @typedef {object} Preset
 * @property {string|undefined} name
 * @property {{key:number, type:string, value:*}[]} psKeys   PS-section records other than the name
 * @property {PresetSlot|null} root   GuitarProc slot (children = the DSP slots)
 */

const symName = (symtab, idx) => (idx >= 0 && idx < symtab.count ? symtab.nameOf(idx) : `#${idx}`);
const symIndex = (symtab, name) => {
  if (typeof name === 'number') return name;
  if (/^#-?\d+$/.test(name)) return Number(name.slice(1));
  return symtab.indexOf(name);
};

/**
 * Blob bytes → structured preset (names resolved through the symbol table the amp accepted).
 * @param {Uint8Array} bytes
 * @param {import('./symtab.js').SymbolTable} symtab
 * @returns {Preset}
 */
export function blobToPreset(bytes, symtab) {
  const { records } = decodeBlobRecords(bytes);
  /** @type {Preset} */
  const preset = { name: undefined, psKeys: [], root: null };
  let section = null;
  const stack = [];
  let pendingStates = 0;
  for (const r of records) {
    if (r.key === DIRECTIVE.SECTION_ID) {
      section = r.value;
      continue;
    }
    if (r.key === DIRECTIVE.SECTION_MAGIC || r.key === DIRECTIVE.SECTION_END) continue;
    if (section === SECTION.PS) {
      if (r.key === PS_KEY.NAME && r.tag === BLOB_TAG.STRING) preset.name = r.value;
      else preset.psKeys.push({ key: r.key, type: TAG_NAME[r.tag] ?? `tag${r.tag}`, value: r.tag === BLOB_TAG.SYMBOL ? symName(symtab, r.value) : r.value });
      continue;
    }
    if (r.key === DIRECTIVE.SLOT_START) {
      const slot = { slot: symName(symtab, r.value), asset: null, states: [], children: [] };
      if (stack.length) stack[stack.length - 1].children.push(slot);
      else preset.root = slot;
      stack.push(slot);
      continue;
    }
    if (r.key === DIRECTIVE.SLOT_END) {
      stack.pop();
      continue;
    }
    const cur = stack[stack.length - 1];
    if (!cur) continue;
    if (r.key === DIRECTIVE.ASSET) {
      cur.asset = symName(symtab, r.value);
      continue;
    }
    if (r.key === DIRECTIVE.STATE_COUNT) {
      pendingStates = r.value;
      continue;
    }
    const name = symName(symtab, r.key);
    const param = name.endsWith('State') ? name.slice(0, -5) : name;
    cur.states.push({ name, param, type: TAG_NAME[r.tag] ?? `tag${r.tag}`, value: r.tag === BLOB_TAG.SYMBOL ? symName(symtab, r.value) : r.value });
    if (pendingStates > 0) pendingStates--;
  }
  return preset;
}

/**
 * Structured preset → blob bytes (same record layout as the serializer).
 * @param {Preset} preset
 * @param {import('./symtab.js').SymbolTable} symtab
 */
export function presetToBlob(preset, symtab) {
  const recs = [];
  const kv = (key, tag, value) => recs.push({ key, tag, value });
  const need = (name) => {
    const i = symIndex(symtab, name);
    if (i < 0) throw new AmpProtocolError(`preset symbol missing from table: ${name}`);
    return i;
  };
  kv(DIRECTIVE.SECTION_ID, BLOB_TAG.INT, SECTION.PS);
  kv(DIRECTIVE.SECTION_MAGIC, BLOB_TAG.INT, SECTION_MAGIC.PS);
  if (typeof preset.name === 'string') kv(PS_KEY.NAME, BLOB_TAG.STRING, truncateUtf8(preset.name, 63));
  for (const k of preset.psKeys ?? []) {
    const tag = TAG_BY_NAME[k.type];
    kv(k.key, tag, tag === BLOB_TAG.SYMBOL ? symIndex(symtab, k.value) : k.value);
  }
  kv(DIRECTIVE.SECTION_END, BLOB_TAG.VOID, null);
  kv(DIRECTIVE.SECTION_ID, BLOB_TAG.INT, SECTION.DSP);
  kv(DIRECTIVE.SECTION_MAGIC, BLOB_TAG.INT, SECTION_MAGIC.DSP);
  const emitSlot = (s) => {
    kv(DIRECTIVE.SLOT_START, BLOB_TAG.SYMBOL, need(s.slot));
    kv(DIRECTIVE.ASSET, BLOB_TAG.SYMBOL, s.asset == null ? -1 : need(s.asset));
    kv(DIRECTIVE.STATE_COUNT, BLOB_TAG.INT, s.states.length);
    for (const st of s.states) {
      const tag = TAG_BY_NAME[st.type];
      kv(need(st.name ?? `${st.param}State`), tag, tag === BLOB_TAG.SYMBOL ? need(st.value) : st.value);
    }
    for (const c of s.children ?? []) emitSlot(c);
    kv(DIRECTIVE.SLOT_END, BLOB_TAG.VOID, null);
  };
  if (preset.root) emitSlot(preset.root);
  kv(DIRECTIVE.SECTION_END, BLOB_TAG.VOID, null);
  return encodeBlobRecords(recs);
}

/** Find a slot by DSP slot name (GuitarProc = root). */
export function findSlot(preset, slotName) {
  const walk = (s) => {
    if (!s) return null;
    if (s.slot === slotName) return s;
    for (const c of s.children ?? []) {
      const f = walk(c);
      if (f) return f;
    }
    return null;
  };
  return walk(preset?.root);
}

/** Read a state value: getPresetState(preset, 'Amp', 'Drive') → 0.5 (or undefined). */
export function getPresetState(preset, slotName, param) {
  return findSlot(preset, slotName)?.states.find((s) => s.param === param)?.value;
}

/**
 * Set (or add) a state from an editor TypedValue. Returns true when the slot exists.
 * @param {Preset} preset
 * @param {string} slotName
 * @param {string} param
 * @param {import('./values.js').TypedValue} tv
 * @param {import('./symtab.js').SymbolTable} [symtab]  to resolve symbol values
 */
export function setPresetState(preset, slotName, param, tv, symtab) {
  const slot = findSlot(preset, slotName);
  if (!slot) return false;
  const { type, value } = typedValueToBlobState(tv, symtab);
  const st = slot.states.find((s) => s.param === param);
  if (st) Object.assign(st, { type, value });
  else slot.states.push({ name: `${param}State`, param, type, value });
  return true;
}

/** Editor TypedValue → blob state {type, value}. */
export function typedValueToBlobState(tv, symtab) {
  switch (tv.tag) {
    case TV.BOOL:
      return { type: 'bool', value: tv.bits !== 0 };
    case TV.INT:
      return { type: 'int', value: tv.bits | 0 };
    case TV.FLOAT:
      return { type: 'float', value: bitsToFloat32(tv.bits) };
    case TV.SYMBOL:
      return { type: 'symbol', value: symtab ? symName(symtab, tv.bits) : tv.bits };
    default:
      return { type: 'void', value: null };
  }
}

/** Blob state → editor TypedValue (for answering GetDspModelParam from a preset). */
export function blobStateToTypedValue(state, symtab) {
  switch (state.type) {
    case 'bool':
      return { tag: TV.BOOL, bits: state.value ? 1 : 0 };
    case 'int':
      return { tag: TV.INT, bits: state.value >>> 0 };
    case 'float':
      return { tag: TV.FLOAT, bits: float32ToBits(state.value) };
    case 'symbol':
      return { tag: TV.SYMBOL, bits: (symtab ? symIndex(symtab, state.value) : state.value) >>> 0 };
    default:
      return { tag: TV.VOID, bits: 0 };
  }
}

/**
 * Editor-level summary of a preset: { name, groups: { amp: {'@model':'BritGainJ800', Drive:0.5, ...},
 * fx1: {'@enabled': true, ...}, ... } }. Uses the GuitarProc table and slot → group mapping.
 */
export function presetToEditorParams(preset) {
  const groups = {};
  const g = (name) => (groups[name] ??= {});
  if (!preset?.root) return { name: preset?.name, groups };
  for (const st of preset.root.states) {
    const row = GUITARPROC_PARAMS.find(([dsp]) => dsp === st.param);
    if (row) g(row[1])[row[2]] = st.value;
  }
  for (const c of preset.root.children) {
    const group = SLOT_TO_GROUP[c.slot];
    if (!group) continue;
    if (c.slot === 'Air') {
      const lv = c.states.find((s) => s.param === 'Level');
      if (lv) g('cab').Level = lv.value;
      continue;
    }
    if (c.slot === 'LiveCab') continue;
    if (c.slot === 'StudioCab') {
      if (c.asset) {
        const m = MIC_SUFFIXES.findIndex((sfx) => c.asset.endsWith(sfx));
        g('cab')['@model'] = m >= 0 ? c.asset.slice(0, -MIC_SUFFIXES[m].length) : c.asset;
        if (m >= 0) g('cab')['@mic'] = m;
      }
      continue;
    }
    if (c.asset) g(group)['@model'] = c.asset;
    for (const st of c.states) g(group)[st.param] = st.value;
  }
  return { name: preset.name, groups };
}

function truncateUtf8(s, maxBytes) {
  let b = utf8.encode(s);
  if (b.length <= maxBytes) return s;
  b = b.slice(0, maxBytes);
  // drop a trailing partial UTF-8 sequence (Python 'ignore')
  return utf8d.decode(b).replace(/�+$/, '');
}

// ------------------------------------------------------------------------------ tone JSON → blob

/**
 * L6EdLibModelDefs::CheckParamValueForModel (preset_blob.py check_value) → [blobTag, value] or null.
 */
function checkValue(model, pname, v) {
  if (!model) return null;
  const pd = (model.params ?? []).find((p) => p.symbolicID === pname);
  if (!pd) return null;
  const vt = pd.valueType;
  const isNum = typeof v === 'number';
  if (vt === 1) {
    let x = isNum ? v : Number(pd.default);
    x = Math.min(Math.max(x, Number(pd.min)), Number(pd.max));
    return [BLOB_TAG.FLOAT, x];
  }
  if (vt === 0) {
    let x;
    if (typeof v === 'boolean') x = Number(v);
    else if (isNum) x = Number.isInteger(v) ? v : v >= 0 ? Math.trunc(v + 0.5) : Math.trunc(v - 0.5);
    else x = Math.trunc(Number(pd.default));
    x = Math.min(Math.max(x, Math.trunc(Number(pd.min))), Math.trunc(Number(pd.max)));
    return [BLOB_TAG.INT, x];
  }
  if (vt === 2) {
    const b = typeof v === 'boolean' || isNum ? Boolean(v) : Boolean(pd.default);
    return [BLOB_TAG.BOOL, b ? 1 : 0];
  }
  return [BLOB_TAG.STRING, String(v)];
}

/**
 * Port of preset_blob.py `encode()`: L6Preset v5 tone JSON → device blob. INFERRED.
 *
 * @param {object} toneJson  parsed L6Preset JSON ({ data: { meta, tone } })
 * @param {import('./symtab.js').SymbolTable} symtab
 * @param {Record<string, object>} models  symbolicID → model definition (from the app's *.models,
 *        loaded by the caller; see mapping.indexModels). Params without a definition are skipped.
 * @param {{group?:string, fw?:number}} [opts] group 'Preset' (full tone, default) or one editor
 *        group for a partial blob (model change); fw = target firmware (PS keys 7/8/9 only when
 *        fw ≥ 0x02110300)
 * @returns {{blob: Uint8Array, log: string[]}}
 */
export function encodeToneJson(toneJson, symtab, models, { group = 'Preset', fw = 0 } = {}) {
  const tone = toneJson.data.tone;
  const meta = toneJson.data.meta ?? {};
  const g = (grp, p) => tone[grp]?.[p];
  const look = (n) => (n ? symtab.indexOf(n) : -1);
  const gpv = (grp, p) => {
    const v = g(grp, p);
    if (v === undefined || v === null) return null;
    const mdl = grp === 'global' ? models['@global_params'] : models[g(grp, '@model')];
    return checkValue(mdl, p, v);
  };
  const recs = [];
  const log = [];
  const kv = (key, tag, value) => recs.push({ key: key >>> 0, tag, value });
  const asset = (assetIdx, states) => {
    kv(DIRECTIVE.ASSET, BLOB_TAG.SYMBOL, assetIdx);
    kv(DIRECTIVE.STATE_COUNT, BLOB_TAG.INT, states.length);
    for (const [k, [t, v]] of states) kv(k, t, v);
  };
  const normalize = (t, v) => (t === BLOB_TAG.BOOL ? (v ? 1 : 0) : t === BLOB_TAG.INT ? Math.trunc(v) : v);

  // ---- PS section
  kv(DIRECTIVE.SECTION_ID, BLOB_TAG.INT, SECTION.PS);
  kv(DIRECTIVE.SECTION_MAGIC, BLOB_TAG.INT, SECTION_MAGIC.PS);
  if (typeof meta.name === 'string') kv(PS_KEY.NAME, BLOB_TAG.STRING, truncateUtf8(meta.name, 63));
  const pskey = (k) => {
    const [grp, p, t] = PSKEY_PARAM[k];
    const cv = gpv(grp, p);
    if (!cv) return;
    const v = cv[1];
    kv(k, t, t === BLOB_TAG.BOOL ? (v ? 1 : 0) : t === BLOB_TAG.INT ? Math.trunc(v) : Number(v));
  };
  if (fw >= 0x02110300) for (const k of [7, 8, 9]) pskey(k);
  const tg = g('global', '@tweakgroup');
  const tp = g('global', '@tweakparam');
  if (tg != null && tp != null) {
    let addr = null;
    try {
      addr = dspAddress(tg, tp);
    } catch {
      addr = null;
    }
    if (!addr) {
      kv(PS_KEY.TWEAK_SLOT, BLOB_TAG.SYMBOL, -1);
      kv(PS_KEY.TWEAK_PARAM, BLOB_TAG.SYMBOL, -1);
    } else {
      const a = look(addr.slot);
      const b = look(addr.param);
      if (a < 0 || b < 0) throw new AmpProtocolError('tweak symbol missing');
      kv(PS_KEY.TWEAK_SLOT, BLOB_TAG.SYMBOL, a);
      kv(PS_KEY.TWEAK_PARAM, BLOB_TAG.SYMBOL, b);
    }
  }
  if (group === 'Preset') {
    if (meta.tnid !== undefined && meta.tnid !== null) {
      const tnid = Number(meta.tnid);
      kv(PS_KEY.TNID_LO, BLOB_TAG.INT, tnid % 2 ** 32 | 0);
      kv(PS_KEY.TNID_HI, BLOB_TAG.INT, Math.floor(tnid / 2 ** 32) | 0);
    }
    pskey(3);
  }
  kv(DIRECTIVE.SECTION_END, BLOB_TAG.VOID, null);

  // ---- DSP section
  kv(DIRECTIVE.SECTION_ID, BLOB_TAG.INT, SECTION.DSP);
  kv(DIRECTIVE.SECTION_MAGIC, BLOB_TAG.INT, SECTION_MAGIC.DSP);
  kv(DIRECTIVE.SLOT_START, BLOB_TAG.SYMBOL, look(GUITARPROC_SLOT));
  const sel = group === 'Preset' ? null : group === 'amp' ? ['amp', 'cab'] : [group];
  const states = [];
  for (const [dsp, grp, p] of GUITARPROC_PARAMS) {
    if (sel && !sel.includes(grp)) continue;
    let cv;
    if (dsp === 'CabEnable') cv = [BLOB_TAG.BOOL, g('cab', '@model') !== NO_CABINET ? 1 : 0];
    else {
      cv = gpv(grp, p);
      if (!cv && p === '@mix') cv = [BLOB_TAG.FLOAT, 1.0];
    }
    if (!cv) continue;
    const k = look(`${dsp}State`);
    if (k < 0) {
      log.push(`skip ${dsp}State (no symbol)`);
      continue;
    }
    states.push([k, [cv[0], normalize(cv[0], cv[1])]]);
  }
  asset(look(GUITARPROC_ASSET), states);

  const slots = group === 'Preset' ? FULL_SLOTS : group === 'amp' ? ['Amp', 'Air', 'StudioCab', 'LiveCab'] : group === 'cab' ? ['Air', 'StudioCab', 'LiveCab'] : [GROUP_TO_SLOT[group]];
  for (const s of slots) {
    kv(DIRECTIVE.SLOT_START, BLOB_TAG.SYMBOL, look(s));
    const st = [];
    const cab = g('cab', '@model');
    let assetIdx;
    if (s === 'Air') {
      assetIdx = look('TNGAIRReflections');
      const lv = cab === NO_CABINET ? [BLOB_TAG.FLOAT, 0.0] : gpv('cab', 'Level') ?? [BLOB_TAG.FLOAT, 0.0];
      st.push([look('LevelState'), [BLOB_TAG.FLOAT, Number(lv[1])]]);
    } else if (s === 'StudioCab') {
      if (cab === NO_CABINET) assetIdx = look(NO_CABINET_STUDIO_SYMBOL);
      else {
        const micv = gpv('cab', '@mic');
        const mic = micv ? micv[1] : 0;
        assetIdx = mic >= 0 && mic < 4 ? look(cab + MIC_SUFFIXES[mic]) : -1;
      }
    } else if (s === 'LiveCab') {
      assetIdx = look(models[cab]?.cablink ?? '');
    } else {
      const grp = SLOT_TO_GROUP[s];
      const mid = g(grp, '@model');
      const mdl = mid != null ? models[mid] : undefined;
      assetIdx = mid ? look(mid) : -1;
      const hasSync = !!mdl && (mdl.params ?? []).some((p) => p.symbolicID === 'SyncSelect');
      let didSync = false;
      for (const [p, v] of Object.entries(tone[grp] ?? {})) {
        if (p.startsWith('@')) continue;
        let cv = checkValue(mdl, p, v);
        if (!cv) continue;
        if (p === 'SyncSelect') {
          if (!g(grp, '@temposync')) cv = [BLOB_TAG.INT, 0];
          didSync = true;
        }
        const k = look(`${p}State`);
        if (k < 0) {
          log.push(`skip ${p}State for ${mid} (no symbol)`);
          continue;
        }
        st.push([k, [cv[0], normalize(cv[0], cv[1])]]);
      }
      if (hasSync && !didSync) st.push([look('SyncSelectState'), [BLOB_TAG.INT, 0]]);
    }
    if (assetIdx < 0) throw new AmpProtocolError(`asset symbol missing for slot ${s}`);
    asset(assetIdx, st);
    kv(DIRECTIVE.SLOT_END, BLOB_TAG.VOID, null);
  }
  kv(DIRECTIVE.SLOT_END, BLOB_TAG.VOID, null);
  kv(DIRECTIVE.SECTION_END, BLOB_TAG.VOID, null);
  return { blob: encodeBlobRecords(recs), log };
}

/**
 * Human-readable dump (port of preset_blob.py decode()).
 */
export function describeBlob(bytes, symtab) {
  const { records } = decodeBlobRecords(bytes);
  const names = {
    [DIRECTIVE.SECTION_ID]: 'SectionID',
    [DIRECTIVE.SECTION_MAGIC]: 'SectionMagic',
    [DIRECTIVE.SECTION_END]: 'SectionEnd',
    [DIRECTIVE.SLOT_START]: 'SlotStart',
    [DIRECTIVE.SLOT_END]: 'SlotEnd',
    [DIRECTIVE.ASSET]: 'Asset',
    [DIRECTIVE.STATE_COUNT]: 'StateCount',
  };
  let depth = 0;
  const lines = [];
  for (const r of records) {
    if (r.key === DIRECTIVE.SLOT_END) depth--;
    const kn = names[r.key] ?? (r.key < 0x80000000 && depth > 0 ? symName(symtab, r.key) : `PSKey${r.key}`);
    const val = r.tag === BLOB_TAG.SYMBOL ? symName(symtab, r.value) : r.value;
    lines.push(`${'  '.repeat(Math.max(depth, 0))}${kn} [${r.tag}] = ${JSON.stringify(val)}`);
    if (r.key === DIRECTIVE.SLOT_START) depth++;
  }
  return lines.join('\n');
}
