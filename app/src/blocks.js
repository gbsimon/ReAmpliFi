// Read-only view model of the edit buffer for the Tone screen.
// Input: AmpSession.getEditBufferParams() → { name, groups: { amp: { '@model': 'BritGainJ800', Drive: 0.5, … } } }.

import { MIC_SUFFIXES } from '@protocol/mapping.js';
import { modelInfo } from './metadata.js';

/** Editor groups in display order, with labels. AMPLIFi: FX4 is the reverb group. */
export const BLOCKS = Object.freeze([
  { group: 'gate', label: 'Noise gate' },
  { group: 'wah', label: 'Wah' },
  { group: 'compressor', label: 'Compressor' },
  { group: 'fx1', label: 'FX 1' },
  { group: 'fx2', label: 'FX 2' },
  { group: 'fx3', label: 'FX 3' },
  { group: 'amp', label: 'Amp' },
  { group: 'cab', label: 'Cab' },
  { group: 'reverb', label: 'Reverb (FX 4)' },
  { group: 'eq', label: 'EQ' },
  { group: 'volume', label: 'Volume pedal' },
]);

const KIND_LABEL = Object.freeze({ amp: 'Amp', cab: 'Cab', stomp: 'Stomp', mod: 'Modulation', delay: 'Delay', reverb: 'Reverb', wah: 'Wah', fixed: 'Fixed' });

const MIC_LABELS = Object.freeze({ '57OnAxis': '57 on axis', '57OffAxis': '57 off axis', 421: '421', U67: 'U67' });

/** Editor params that are not knobs: shown in the block header, not as meters. */
const HIDDEN = new Set(['@model', '@enabled']);

const FALLBACK_NAMES = Object.freeze({ '@mix': 'Mix', '@post': 'Position', '@mixtype': 'Mix type', '@volume': 'Channel volume', '@mic': 'Mic', '@temposync': 'Tempo sync' });

const round = (x, d = 2) => {
  const p = 10 ** d;
  return Math.round(x * p) / p;
};

/**
 * One param display.
 * @returns {{id:string, name:string, kind:'float'|'int'|'bool', value:any, display:string, min:number|null, max:number|null, fraction:number|null}}
 */
export function paramView(id, value, def) {
  const metaName = def?.name && !def.name.startsWith('@') ? def.name : null;
  const name = metaName ?? FALLBACK_NAMES[id] ?? id;
  const vt = def?.valueType;
  if (typeof value === 'boolean' || vt === 2) {
    const on = Boolean(value);
    const display = id === '@post' ? (on ? 'post' : 'pre') : on ? 'on' : 'off';
    return { id, name, kind: 'bool', value: on, display, min: null, max: null, fraction: on ? 1 : 0 };
  }
  if (typeof value !== 'number') return { id, name, kind: 'float', value, display: String(value ?? '—'), min: null, max: null, fraction: null };
  if (id === '@mic') {
    const sfx = MIC_SUFFIXES[value];
    return { id, name, kind: 'int', value, display: sfx ? MIC_LABELS[sfx] ?? sfx : String(value), min: 0, max: 3, fraction: value / 3 };
  }
  const min = def && Number.isFinite(def.min) ? def.min : 0;
  const max = def && Number.isFinite(def.max) ? def.max : 1;
  const fraction = max > min ? Math.min(1, Math.max(0, (value - min) / (max - min))) : null;
  if (vt === 0) return { id, name, kind: 'int', value, display: String(Math.round(value)), min, max, fraction };
  return { id, name, kind: 'float', value, display: String(round(value, Math.abs(value) >= 10 ? 1 : 2)), min, max, fraction };
}

/**
 * @param {{name?:string, groups:Record<string,Record<string,any>>}|null} editBuffer
 * @returns {Array<{group:string, label:string, present:boolean, model:{symbol:string|null, name:string, kind:string|null, category:string|null, known:boolean}, enabled:boolean|null, params:ReturnType<typeof paramView>[]}>}
 */
export function buildBlocks(editBuffer) {
  const groups = editBuffer?.groups ?? {};
  return BLOCKS.map(({ group, label }) => {
    const values = groups[group] ?? {};
    const symbol = values['@model'] ?? null;
    const info = modelInfo(symbol);
    const defs = new Map((info?.params ?? []).map((p) => [p.symbolicID, p]));
    const ids = [];
    // metadata order first (the official app's order), then anything else the blob has
    for (const p of info?.params ?? []) if (p.symbolicID in values && !HIDDEN.has(p.symbolicID)) ids.push(p.symbolicID);
    for (const k of Object.keys(values)) if (!HIDDEN.has(k) && !ids.includes(k)) ids.push(k);
    const enabled = '@enabled' in values ? Boolean(values['@enabled']) : null;
    return {
      group,
      label,
      present: Object.keys(values).length > 0,
      model: {
        symbol,
        name: info?.name ?? symbol ?? '—',
        kind: info?.kind ? KIND_LABEL[info.kind] ?? info.kind : null,
        category: info?.category ?? null,
        known: !!info,
      },
      enabled,
      params: ids.map((id) => paramView(id, values[id], defs.get(id))),
    };
  });
}

/** Options for the mock dev panel's virtual knob: every numeric / bool param of the tone. */
export function knobChoices(editBuffer) {
  const out = [];
  for (const b of buildBlocks(editBuffer)) {
    if (!b.present) continue;
    if (b.enabled !== null) out.push({ key: `${b.group}|@enabled`, label: `${b.label}: on/off`, group: b.group, paramId: '@enabled', kind: 'bool', min: 0, max: 1 });
    for (const p of b.params) {
      if (p.id === '@mic' || p.id === '@post' || p.id === '@mixtype' || p.id === 'SyncSelect') continue; // not knobs
      out.push({ key: `${b.group}|${p.id}`, label: `${b.label}: ${p.name}`, group: b.group, paramId: p.id, kind: p.kind, min: p.min ?? 0, max: p.max ?? 1 });
    }
  }
  return out;
}

/** "1A".."25D": banks of 4 like the amp's preset knob. */
export function presetLabel(index) {
  return `${Math.floor(index / 4) + 1}${'ABCD'[index % 4]}`;
}

/** Group preset rows into banks of 4. */
export function presetBanks(presets) {
  const banks = [];
  for (const p of presets) {
    const b = Math.floor(p.index / 4);
    (banks[b] ??= { bank: b + 1, presets: [] }).presets.push(p);
  }
  return banks.filter(Boolean);
}

/** SVG arc path (270° sweep, gap at the bottom) for a knob display at `fraction` 0..1. */
export function arcPath(fraction, r = 18, cx = 24, cy = 24) {
  const start = (135 * Math.PI) / 180;
  const sweep = (270 * Math.PI) / 180;
  const f = Math.min(1, Math.max(0, Number.isFinite(fraction) ? fraction : 0));
  const end = start + sweep * f;
  const p = (a) => `${(cx + r * Math.cos(a)).toFixed(2)} ${(cy + r * Math.sin(a)).toFixed(2)}`;
  if (f <= 0) return `M ${p(start)}`;
  const large = sweep * f > Math.PI ? 1 : 0;
  return `M ${p(start)} A ${r} ${r} 0 ${large} 1 ${p(end)}`;
}
