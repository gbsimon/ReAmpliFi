// Every vector in notes/test_vectors.json is rebuilt (or decoded) with this library and compared
// byte for byte. A vector without a builder FAILS (never silently skipped). Template vectors
// ("<u32 8+L>", "<blob>") are checked with a matcher; a vector is skipped only when its template
// cannot be interpreted, with the reason in the skip message.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadVectors, readTable, loadModels, loadDefaultPresetJson, hex, assetsSkipReason } from './helpers.js';
import { parseSymbolTable, tableCrc, ROOT_SLOT_INDEX } from '../src/symtab.js';
import * as ed from '../src/editor.js';
import * as lib from '../src/librarian.js';
import { planSetParam, planDeviceSetting, paramDefFor, TUNER } from '../src/mapping.js';
import { encodeToneJson } from '../src/presetBlob.js';
import { tvFloat, tvInt, tvBool, typedValueToJs, TV, hexToBytes, bytesToHex, concatBytes, u32words } from '../src/values.js';
import { encodeRpcInbound, INBOUND } from '../src/rpc.js';

const skip = assetsSkipReason;
const data = skip ? { vectors: [] } : loadVectors();
const table = skip ? null : readTable();
const sym = skip ? null : parseSymbolTable(table);
const models = skip ? null : loadModels();
const defaultPreset = skip ? null : loadDefaultPresetJson();
const W = { confirmWrite: true };

const setParam = (v) => {
  const i = v.inputs;
  const paramDef = i.model ? paramDefFor(models, i.model, i.param) : null;
  const plan = planSetParam({ group: i.group, paramId: i.param, value: i.value, symtab: sym, paramDef, cabModel: i.cab });
  if (i.slot_idx !== undefined) {
    assert.equal(plan.address.slotIndex, i.slot_idx, 'slot index');
    assert.equal(plan.address.paramIndex, i.param_idx, 'param index');
    assert.equal(plan.address.slot, i.dsp_slot);
    assert.equal(plan.address.param, i.dsp_param);
  }
  return plan.request;
};
const blobVector = (v) => encodeToneJson(defaultPreset, sym, models, { group: v.inputs.group }).blob;
const tuner = () => [sym.lookup(TUNER.slot), sym.lookup(TUNER.enable), sym.lookup(TUNER.note)];

/** name → () => Uint8Array (outbound bytes to compare with payload_hex) */
const BUILDERS = {
  editor_get_version: () => ed.encodeGetVersion(),
  editor_handshake_default_table: (v) => {
    assert.equal(tableCrc(table).toString(16).padStart(8, '0'), v.inputs.crc32);
    return ed.encodeHandshake(tableCrc(table));
  },
  editor_get_symtab_size: () => ed.encodeGetSymbolTableSize(),
  editor_get_symtab: () => ed.encodeGetSymbolTable(),
  'set_param_amp_Drive_0.5': setParam,
  'set_param_amp_Bass_0.25': setParam,
  'set_param_amp_volume_0.75': setParam,
  set_param_fx1_enabled_true: setParam,
  set_param_fx1_enabled_false: setParam,
  'set_param_reverb_mix_0.33': setParam,
  set_param_reverb_post_true: setParam,
  'set_param_cab_Level_0.5': setParam,
  'set_param_reverb_Decay_1.5': setParam,
  set_param_fx2_temposync_false: setParam,
  set_param_fx2_SyncSelect_4: setParam,
  cab_mic_change_to_421: setParam,
  global_tempo_120: setParam,
  'global_tweakmin_0.2': (v) => planSetParam({ ...v.inputs, paramId: v.inputs.param, symtab: sym, confirmWrite: true }).request,
  global_pedal2assign_true: (v) => planSetParam({ ...v.inputs, paramId: v.inputs.param, symtab: sym, confirmWrite: true }).request,
  tweak_bind_amp_Drive: (v) => planSetParam({ group: 'global', paramId: '@tweakparam', value: v.inputs.tweakparam, symtab: sym, tweak: { group: v.inputs.tweakgroup, param: v.inputs.tweakparam } }).request,
  'device_setting_Master_0.5': (v) => planDeviceSetting({ name: v.inputs.setting, value: v.inputs.value, symtab: sym }).request,
  'device_setting_GuitOutputGain_0.8': (v) => planDeviceSetting({ name: v.inputs.setting, value: v.inputs.value, symtab: sym }).request,
  device_setting_TapTempoLED_true: (v) => planDeviceSetting({ name: v.inputs.setting, value: v.inputs.value, symtab: sym, confirmWrite: true }).request,
  get_Master: () => ed.encodeGetDspModelParam(ROOT_SLOT_INDEX, sym.lookup('Master')),
  get_FBVConnected: () => ed.encodeGetFbvConnectivityStatus(),
  get_dirty_state: () => ed.encodeGetDirtyState(),
  tuner_query_state: () => ed.encodeGetDspModelParam(tuner()[0], tuner()[1]),
  tuner_engage: () => ed.encodeSetDspModelParam(tuner()[0], tuner()[1], tvInt(1)),
  tuner_register_note_events: () => ed.encodeRegisterDspEvent(tuner()[0], tuner()[2]),
  tuner_disengage: () => ed.encodeSetDspModelParam(tuner()[0], tuner()[1], tvInt(0)),
  tuner_unregister_note_events: () => ed.encodeUnregisterDspEvent(tuner()[0], tuner()[2]),
  // inbound: build with the amp-side encoders AND decode the vector bytes
  in_tuner_note_event: (v, bytes) => {
    const ev = ed.decodeEditorInbound(bytes);
    assert.equal(sym.nameOf(ev.slot), 'Tuner');
    assert.equal(sym.nameOf(ev.param), 'Note');
    assert.equal(ev.value.tag, TV.FLOAT);
    const r = ed.tunerValueToNoteCents(typedValueToJs(ev.value));
    assert.equal(r.note, v.inputs.expected_note);
    assert.ok(Math.abs(r.cents - v.inputs.expected_cents) < 1e-3, `cents ${r.cents}`);
    return ed.encodeDspEvent(tuner()[0], tuner()[2], tvFloat(v.inputs.value));
  },
  in_param_event_amp_drive: (v, bytes) => {
    const ev = ed.decodeEditorInbound(bytes);
    assert.equal(sym.nameOf(ev.slot), v.inputs.slot);
    assert.equal(sym.nameOf(ev.param), v.inputs.param);
    assert.ok(Math.abs(typedValueToJs(ev.value) - v.inputs.value) < 1e-6);
    return ed.encodeParamEvent(sym.lookup('Amp'), sym.lookup('Drive'), tvFloat(v.inputs.value));
  },
  in_param_event_master: (v, bytes) => {
    const ev = ed.decodeEditorInbound(bytes);
    assert.equal(ev.slot, v.inputs.slot);
    assert.equal(sym.nameOf(ev.param), 'Master');
    return ed.encodeParamEvent(ROOT_SLOT_INDEX, sym.lookup('Master'), tvFloat(v.inputs.value));
  },
  in_patch_event_select_5: (v, bytes) => {
    const ev = ed.decodeEditorInbound(bytes);
    assert.equal(typedValueToJs(ev.presetIndex), 5);
    assert.equal(typedValueToJs(ev.isSave), 0);
    return ed.encodePatchEvent(v.inputs.preset_index, !!v.inputs.is_save);
  },
  in_tap_tempo_event: (v, bytes) => {
    assert.equal(typedValueToJs(ed.decodeEditorInbound(bytes).value), 120);
    return ed.encodeTapTempoEvent(v.inputs.bpm);
  },
  in_fbv_connected: (v, bytes) => {
    assert.ok(typedValueToJs(ed.decodeEditorInbound(bytes).value) > 0);
    return ed.encodeFbvStatusEvent(v.inputs.connected);
  },
  in_response_status_ok: (v, bytes) => {
    assert.equal(ed.decodeEditorResponse(4, ed.decodeEditorInbound(bytes).body).status, 0);
    return ed.encodeStatusResponse(v.inputs.status);
  },
  lib_get_num_presets: () => lib.encodeGetNumPresets(),
  lib_handshake_default_table: () => lib.encodeHandshake(tableCrc(table)),
  lib_get_preset_name_0: (v) => lib.encodeGetPresetName(v.inputs.index),
  lib_get_preset_name_5: (v) => lib.encodeGetPresetName(v.inputs.index),
  select_preset_0_step1_get: (v) => lib.encodeGetPresetFile(v.inputs.index),
  select_preset_5_step1_get: (v) => lib.encodeGetPresetFile(v.inputs.index),
  select_preset_step2_put_editbuffer: (_v, _b, blob) => lib.encodeSetPresetFile(lib.EDIT_BUFFER, blob),
  save_to_slot_3: (v, _b, blob) => lib.encodeSetPresetFile(v.inputs.index, blob, W),
  lib_move_src1_dst4: (v) => lib.encodeMovePresetFiles(v.inputs.dst, v.inputs.src, W),
  lib_get_preset_info_0: (v) => lib.encodeGetPresetInfo(v.inputs.index),
  lib_get_editbuffer: () => lib.encodeGetPresetFile(lib.EDIT_BUFFER),
  preset_blob_default_preset_Preset: blobVector,
  preset_blob_default_preset_fx1: blobVector,
  preset_blob_default_preset_amp: blobVector,
  load_tone_json_editbuffer: (_v, _b, blob) => lib.encodeSetPresetFile(lib.EDIT_BUFFER, blob),
};

/**
 * Template matcher for payload_hex strings containing <u32 8+L>, <u32 L>, <blob>.
 * Returns the expected bytes for a given blob, or null if the template has unknown tokens.
 */
function expandTemplate(tpl, blob) {
  const parts = tpl.split(/(<[^>]+>)/).filter(Boolean);
  const out = [];
  for (const p of parts) {
    if (!p.startsWith('<')) {
      if (!/^[0-9a-f]*$/i.test(p) || p.length % 2) return null;
      out.push(hexToBytes(p));
    } else if (p === '<u32 8+L>') out.push(u32words(8 + blob.length));
    else if (p === '<u32 L>') out.push(u32words(blob.length));
    else if (p === '<blob>') out.push(blob);
    else return null;
  }
  return concatBytes(...out);
}

test('test_vectors.json is loaded and non-empty', { skip }, () => {
  assert.ok(data.vectors.length >= 50, `${data.vectors.length} vectors`);
});

for (const v of data.vectors) {
  const isTemplate = /<[^>]+>/.test(v.payload_hex);
  // template blob: the vector names another vector, or we use a synthetic blob
  let templateBlob = null;
  let skipReason = false;
  if (isTemplate) {
    const ref = typeof v.inputs.blob === 'string' && data.vectors.find((x) => x.name === v.inputs.blob);
    templateBlob = ref ? hexToBytes(ref.payload_hex) : Uint8Array.from({ length: 37 }, (_, i) => (i * 7) & 0xff);
    if (!expandTemplate(v.payload_hex, templateBlob)) skipReason = `payload_hex template not interpretable: ${v.payload_hex}`;
  } else if (!/^[0-9a-f]*$/i.test(v.payload_hex) || v.payload_hex.length % 2) {
    skipReason = `payload_hex is not valid hex: ${v.payload_hex.slice(0, 40)}`;
  }
  test(`vector ${v.name} [${v.status}]`, { skip: skip || skipReason }, () => {
    const build = BUILDERS[v.name];
    assert.ok(build, `no builder for vector ${v.name}: add one (vectors are never skipped silently)`);
    const expected = isTemplate ? expandTemplate(v.payload_hex, templateBlob) : hexToBytes(v.payload_hex);
    const got = build(v, expected, templateBlob);
    assert.equal(bytesToHex(got), bytesToHex(expected));
    if (v.inputs?.len !== undefined) assert.equal(got.length, v.inputs.len);
  });
}

test('every builder corresponds to a vector (no stale builders)', { skip }, () => {
  const names = new Set(data.vectors.map((v) => v.name));
  for (const k of Object.keys(BUILDERS)) assert.ok(names.has(k), `builder ${k} has no vector`);
});

test('response decoders: librarian no-status commands (correction in native_messages.md §1)', () => {
  // GetNumPresets reply is exactly 01000000 04000000 <u32 count>
  const reply = encodeRpcInbound(INBOUND.RESPONSE, u32words(8));
  assert.equal(hex(reply), '010000000400000008000000');
  assert.deepEqual(lib.decodeLibrarianResponse(5, reply.slice(8)), { value: 8 });
  assert.deepEqual(lib.decodeLibrarianResponse(1, u32words(3)), { value: 3 });
  // status-first commands
  assert.equal(lib.decodeLibrarianResponse(4, u32words(-1)).status, -1);
  const name = lib.encodeLibPresetNameResponse(0, 'Clean');
  assert.equal(lib.decodeLibrarianResponse(6, name.slice(8)).name, 'Clean');
});

test('tvBool and TV tags', () => {
  assert.deepEqual(tvBool(true), { tag: 3, bits: 1 });
});
