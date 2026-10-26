import Alpine from 'alpinejs';
import './styles.css';
import { createStore, logsAsText } from './store.js';
import { createController } from './controller.js';
import { resolveMode, setMode, serialSupport } from './transport.js';
import { metadataSummary } from './metadata.js';
import { buildBlocks, knobChoices, presetBanks, presetLabel, arcPath } from './blocks.js';

const mode = resolveMode();
const store = createStore({ reactive: Alpine.reactive });
store.patch({
  mode,
  metadata: { ...metadataSummary },
  support: mode === 'mock' ? { supported: true, reason: null, message: null } : serialSupport(),
});
const controller = createController(store, { mode });

const TABS = [
  { id: 'connect', label: 'Connect' },
  { id: 'device', label: 'Device' },
  { id: 'tone', label: 'Tone' },
  { id: 'presets', label: 'Presets' },
  { id: 'tuner', label: 'Tuner' },
  ...(mode === 'mock' ? [{ id: 'mock', label: 'Mock amp' }] : []),
];

const STEPS = [
  { id: 'sync', label: 'Link sync', phases: ['sync'] },
  { id: 'deviceInfo', label: 'Device info', phases: ['deviceInfo', 'channel'] },
  { id: 'handshake', label: 'Handshake', phases: ['handshake', 'tableDownload', 'librarian'] },
  { id: 'tone', label: 'Current tone', phases: ['editBuffer', 'tuner'] },
  { id: 'ready', label: 'Ready', phases: ['ready'] },
];

const hex32 = (n) => (n === null || n === undefined ? '—' : `0x${(n >>> 0).toString(16).padStart(8, '0').toUpperCase()}`);

function tabFromHash() {
  const id = (globalThis.location.hash || '').replace(/^#\/?/, '');
  return TABS.some((t) => t.id === id) ? id : 'connect';
}

Alpine.store('amp', store.state);

Alpine.data('app', () => ({
  tabs: TABS,
  steps: STEPS,
  hex32,
  presetLabel,
  arcPath,
  copied: false,
  stick: true, // log drawer follows new lines while scrolled to the bottom

  init() {
    store.patchIn('ui', { tab: tabFromHash() });
    globalThis.addEventListener('hashchange', () => store.patchIn('ui', { tab: tabFromHash() }));
    if (mode === 'serial' && store.state.support.supported) {
      controller.refreshRememberedPorts();
      navigator.serial.addEventListener?.('connect', () => controller.refreshRememberedPorts());
    }
    // a knob highlight fades after a moment
    setInterval(() => {
      const lp = store.state.lastParam;
      if (lp && Date.now() - lp.at > 1200) store.patch({ lastParam: null });
    }, 400);
  },

  // ------------------------------------------------------------------ derived state
  get amp() {
    return this.$store.amp;
  },
  get busy() {
    return ['picking', 'syncing', 'handshaking'].includes(this.amp.connection);
  },
  get ready() {
    return this.amp.connection === 'ready';
  },
  get blocks() {
    return buildBlocks(this.amp.editBuffer);
  },
  get banks() {
    return presetBanks(this.amp.presets);
  },
  get knobs() {
    return knobChoices(this.amp.editBuffer);
  },
  get selectedKnob() {
    return this.knobs.find((k) => k.key === this.amp.mock.knob.key) ?? this.knobs[0] ?? null;
  },
  get selectedKnobValue() {
    const k = this.selectedKnob;
    return k ? this.amp.editBuffer?.groups?.[k.group]?.[k.paramId] : undefined;
  },
  get statusText() {
    const c = this.amp.connection;
    if (c === 'ready') return `Connected to ${this.amp.deviceInfo?.productName ?? 'amp'}`;
    if (c === 'picking') return 'Choose the amp in the browser dialog…';
    if (c === 'syncing' || c === 'handshaking') return 'Connecting…';
    if (c === 'lost') return 'Link lost';
    return 'Not connected';
  },
  stepState(step) {
    const order = STEPS.findIndex((s) => s.phases.includes(this.amp.phase));
    const i = STEPS.indexOf(step);
    if (this.amp.connection === 'ready') return 'done';
    if (order < 0) return 'todo';
    if (i < order) return 'done';
    if (i === order) return this.busy ? 'active' : 'todo';
    return 'todo';
  },
  get downloadPercent() {
    const d = this.amp.tableDownload;
    return d && d.total ? Math.round((100 * d.received) / d.total) : 0;
  },
  isCurrentPreset(p) {
    return this.amp.currentPresetIndex === p.index;
  },
  isHot(group, paramId) {
    const lp = this.amp.lastParam;
    return !!lp && lp.group === group && (lp.paramId === paramId || paramId === '*');
  },
  get tunerNeedle() {
    // −50..+50 cents → −45..+45 degrees
    const c = Math.max(-50, Math.min(50, this.amp.tuner.cents || 0));
    return this.amp.tuner.note >= 0 ? (c / 50) * 45 : 0;
  },
  get tunerInTune() {
    return this.amp.tuner.note >= 0 && Math.abs(this.amp.tuner.cents) < 3;
  },
  get visibleLog() {
    return this.amp.log.slice(-400);
  },
  get visibleHex() {
    return this.amp.hexLog.slice(-300);
  },

  // ------------------------------------------------------------------ actions
  go(tab) {
    globalThis.location.hash = `#${tab}`;
  },
  connect() {
    controller.connect();
  },
  reconnect(i) {
    controller.connect({ remembered: i });
  },
  disconnect() {
    controller.disconnect();
  },
  toggleTuner() {
    controller.setTuner(!this.amp.tuner.enabled);
  },
  reloadPresets() {
    controller.reloadPresetNames();
  },
  switchMode() {
    setMode(mode === 'mock' ? 'serial' : 'mock');
  },
  toggleLog() {
    store.patchIn('ui', { logOpen: !this.amp.ui.logOpen });
  },
  setHex(on) {
    controller.resetDecoder();
    store.patchIn('ui', { hexEnabled: on });
  },
  clearLogs() {
    store.clearLogs();
  },
  async copyLog() {
    const text = logsAsText(store.state);
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.append(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    this.copied = true;
    setTimeout(() => (this.copied = false), 1500);
  },

  // mock dev panel (amp-side simulation; the app itself stays read-only)
  mockKnobInput(ev) {
    const k = this.selectedKnob;
    if (!k) return;
    const v = k.kind === 'bool' ? ev.target.checked : Number(ev.target.value);
    store.patchIn('mock', { knob: { key: k.key, value: v } });
    controller.mockTurnKnob(k.group, k.paramId, k.kind === 'int' ? Math.round(v) : v);
  },
  mockSelectPreset() {
    controller.mockSelectPreset(Number(this.amp.mock.presetOnAmp));
  },
  mockSaveOnAmp() {
    controller.mockSaveOnAmp(Number(this.amp.mock.presetOnAmp));
  },
  mockTap() {
    controller.mockTapTempo(Number(this.amp.mock.tapBpm));
  },
  mockTuner(on) {
    controller.mockTuner(on);
  },
  mockPitch(ev) {
    const v = Number(ev.target.value);
    store.patchIn('mock', { tunerPitch: v });
    controller.mockTunerPitch(v);
  },
  mockMaster(ev) {
    const v = Number(ev.target.value);
    store.patchIn('mock', { master: v });
    controller.mockMaster(v);
  },
  mockDropLink() {
    controller.mockDropLink();
  },
  mockGoSilent() {
    controller.mockGoSilent();
  },
}));

globalThis.reamplifi = { store, controller }; // for debugging in the console
Alpine.start();
