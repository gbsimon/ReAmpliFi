// Names for the mock amp's own synthetic symbol table.
//
// These are only the DSP identifiers the protocol needs (slot / param / model names that also
// appear in the app's public UI and preset JSON). The order is deliberately different from any
// real table, so the mock's indexes differ and the handshake-fallback (table download) path is
// exercised. No Line 6 table file is copied into this project.

import { GUITARPROC_PARAMS, MIC_SUFFIXES } from '../src/mapping.js';

const slots = ['GuitarProc', 'Gate', 'VolumePedal', 'Wah', 'FX1', 'FX2', 'FX3', 'FX4', 'Amp', 'Air', 'StudioCab', 'LiveCab', 'PostComp', 'PostEQ', 'Tuner'];
const assets = ['ToneMatchGuitarFlow', 'TNGAIRReflections', 'BritGainJ800', 'BlackfaceLux', 'ClassA30Fawn', 'Screamer', 'UVibe', 'StereoDelay', 'DarkHall1', 'Line6Vetta', 'SharcPodFixedComp', 'ParaGraphic4_band', '4x12BritT75Live2x12'];
const cabs = ['4x12BritT75Studio', '2x12Line6Studio'];
const params = ['Drive', 'Bass', 'Mid', 'Treble', 'Presence', 'Gain', 'Tone', 'Depth', 'Speed', 'SyncSelect', 'Time', 'FbackL', 'FbackR', 'Decay', 'PreDelay', 'Thresh', 'Volume', 'MaxVol', 'MinVol', 'Pedal', 'Low', 'Level'];
const system = ['Enable', 'Note', 'Master', 'GuitOutputGain'];

const dsp = GUITARPROC_PARAMS.map(([d]) => d);

/** Synthetic name list (reversed-ish order on purpose). */
export const MOCK_SYMBOL_NAMES = Object.freeze([
  ...new Set([
    ...system,
    ...params.flatMap((p) => [`${p}State`, p]),
    ...dsp.flatMap((d) => [`${d}State`, d]),
    ...cabs.flatMap((c) => MIC_SUFFIXES.map((m) => c + m)),
    ...assets,
    ...slots,
  ]),
].reverse());
