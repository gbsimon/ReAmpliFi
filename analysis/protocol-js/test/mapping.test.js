import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readTable, loadModels, hex, assetsSkipReason } from './helpers.js';
import { parseSymbolTable } from '../src/symtab.js';
import { planSetParam, planDeviceSetting, dspAddress, groupForDspAddress, coerceValue, studioCabSymbol, parseStudioCabSymbol, paramDefFor, editorCommandForParam, GUITARPROC_PARAMS } from '../src/mapping.js';
import { MappingError, WriteNotConfirmedError } from '../src/errors.js';
import { TV, bitsToFloat32 } from '../src/values.js';

const skip = assetsSkipReason;
const sym = skip ? null : parseSymbolTable(readTable());
const models = skip ? null : loadModels();

test('amp Drive 0.5 → exact bytes (native_messages.md §2 example)', { skip }, () => {
  const plan = planSetParam({ group: 'amp', paramId: 'Drive', value: 0.5, symtab: sym, paramDef: paramDefFor(models, 'BritGainJ800', 'Drive') });
  // 0a000000 10000000 | 17020000 (Amp=535) 17000000 (Drive=23) 04000000 0000003f (float 0.5)
  assert.equal(hex(plan.request), '0a000000' + '10000000' + '17020000' + '17000000' + '04000000' + '0000003f');
  assert.equal(plan.command, 'SetDspModelParam');
  assert.deepEqual(plan.address, { slot: 'Amp', param: 'Drive', slotIndex: 535, paramIndex: 23 });
});

test('dspAddress: GuitarProc table, group→slot, cab/Level exception, reverb→FX4', () => {
  assert.deepEqual(dspAddress('fx2', '@post'), { slot: 'GuitarProc', param: 'FX2Post' });
  assert.deepEqual(dspAddress('amp', '@volume'), { slot: 'GuitarProc', param: 'ChannelVolume' });
  assert.deepEqual(dspAddress('reverb', 'Decay'), { slot: 'FX4', param: 'Decay' });
  assert.deepEqual(dspAddress('cab', 'Level'), { slot: 'Air', param: 'Level' });
  assert.deepEqual(dspAddress('compressor', 'Gain'), { slot: 'PostComp', param: 'Gain' });
  assert.throws(() => dspAddress('reverb', '@mixtype'), MappingError, 'reverb has no @mixtype (−4)');
  assert.throws(() => dspAddress('amp', '@stereo'), MappingError);
});

test('groupForDspAddress is the inverse for every GuitarProc row and plain slots', () => {
  for (const [dsp, group, p] of GUITARPROC_PARAMS) assert.deepEqual(groupForDspAddress('GuitarProc', dsp), { group, paramId: p });
  assert.deepEqual(groupForDspAddress('Amp', 'Drive'), { group: 'amp', paramId: 'Drive' });
  assert.deepEqual(groupForDspAddress('Air', 'Level'), { group: 'cab', paramId: 'Level' });
  assert.equal(groupForDspAddress('Tuner', 'Enable'), null);
});

test('value coercion (CheckParamValueForModel): clamp, int rounding, bool', () => {
  const fdef = { valueType: 1, min: 0, max: 1, default: 0.3 };
  assert.equal(bitsToFloat32(coerceValue(1.5, { paramDef: fdef }).bits), 1);
  assert.equal(bitsToFloat32(coerceValue('x', { paramDef: fdef }).bits), Math.fround(0.3), 'non-number → default');
  const idef = { valueType: 0, min: 1, max: 14, default: 1 };
  assert.deepEqual(coerceValue(2.5, { paramDef: idef }), { tag: TV.INT, bits: 3 }, 'round half away from zero');
  assert.deepEqual(coerceValue(true, { paramDef: { valueType: 0, min: 0, max: 1 } }), { tag: TV.INT, bits: 1 });
  assert.deepEqual(coerceValue(1, { paramDef: { valueType: 2 } }), { tag: TV.BOOL, bits: 1 });
  assert.throws(() => coerceValue('BritGainJ800', { paramDef: { valueType: 3 } }), MappingError);
  // no definition
  assert.equal(coerceValue(true).tag, TV.BOOL);
  assert.equal(coerceValue(4, { paramId: 'SyncSelect' }).tag, TV.INT);
  assert.equal(coerceValue(0.4).tag, TV.FLOAT);
});

test('cab @mic: studio cab symbol and LoadDspModel', { skip }, () => {
  assert.equal(studioCabSymbol('4x12BritT75Studio', 2), '4x12BritT75Studio421');
  assert.deepEqual(parseStudioCabSymbol('4x12BritT75StudioU67'), { cab: '4x12BritT75Studio', mic: 3 });
  assert.equal(studioCabSymbol('@NoCabinet', 1), '2x12Line6Studio57OnAxis');
  const plan = planSetParam({ group: 'cab', paramId: '@mic', value: 2, symtab: sym, cabModel: '4x12BritT75Studio' });
  assert.equal(hex(plan.request), '08000000080000001a020000d7010000');
});

test('@temposync: false → int 0; true → stored SyncSelect; needs the stored value', { skip }, () => {
  assert.equal(hex(planSetParam({ group: 'fx3', paramId: '@temposync', value: true, symtab: sym, syncSelect: 6 }).request).slice(-16), '0200000006000000');
  assert.throws(() => planSetParam({ group: 'fx3', paramId: '@temposync', value: true, symtab: sym }), MappingError);
  assert.throws(() => planSetParam({ group: 'amp', paramId: '@temposync', value: false, symtab: sym }), MappingError);
});

test('global: @tempo → cmd 14, PS keys → cmd 19 (needs confirmWrite), @model refused', { skip }, () => {
  assert.equal(hex(planSetParam({ group: 'global', paramId: '@tempo', value: 120, symtab: sym }).request), '0e000000040000000000f042');
  assert.throws(() => planSetParam({ group: 'global', paramId: '@tweakmax', value: 0.9, symtab: sym }), WriteNotConfirmedError);
  assert.throws(() => planSetParam({ group: 'amp', paramId: '@model', value: 'BlackfaceLux', symtab: sym }), /partial preset blob/);
  assert.equal(editorCommandForParam('global', '@tweakmin'), 19);
  assert.equal(editorCommandForParam('cab', '@mic'), 8);
});

test('device settings: aliases, root slot float, persistent sys params need confirmWrite, read-only refused', { skip }, () => {
  assert.equal(hex(planDeviceSetting({ name: 'MasterVolume', value: 0.5, symtab: sym }).request), '0a00000010000000ffffffff60020000040000000000003f');
  assert.equal(planDeviceSetting({ name: 'GuitarVolume', value: 0.8, symtab: sym }).name, 'GuitOutputGain');
  assert.throws(() => planDeviceSetting({ name: 'TapTempoLED', value: true, symtab: sym }), WriteNotConfirmedError);
  assert.equal(hex(planDeviceSetting({ name: 'TapTempoLED', value: true, symtab: sym, confirmWrite: true }).request), '120000000c000000070000000300000001000000');
  assert.throws(() => planDeviceSetting({ name: 'FBVConnected', value: true, symtab: sym }), MappingError);
});
