// Plain JS store (PLAN.md §3.3). Framework-agnostic: main.js passes Alpine.reactive so the UI
// re-renders on mutation; anything else can use subscribe(). All writes go through the store's
// methods so subscribers are notified.

/** Connection states shown in the UI. */
export const CONNECTION = Object.freeze(['idle', 'picking', 'syncing', 'handshaking', 'ready', 'lost']);

const LOG_MAX = 1500;
const HEX_MAX = 1500;

export function initialState() {
  return {
    mode: 'serial', // 'serial' | 'mock'
    support: { supported: false, reason: null, message: null },
    metadata: { present: false, models: 0, source: null },

    connection: 'idle',
    error: null, // { message, hint? }
    phase: null, // last AmpSession 'phase' name
    tableDownload: null, // { received, total }
    rememberedPorts: [], // [{ label }]

    deviceInfo: null, // { productName, model, serialNumber, firmwareString, firmwareRevision, correctedVersion, productId }
    channel: null, // { mtu, timeoutMs, heartbeatMs }
    versions: { editor: null, librarian: null },
    symbolTable: { status: 'none', source: null, crc: null, size: null }, // status: none | checking | downloading | accepted
    deviceSettings: {}, // Master / GuitOutputGain values seen in events
    fbvConnected: null,
    tempo: null,

    editBuffer: null, // { name, groups } (AmpSession.getEditBufferParams)
    dirty: null,
    lastParam: null, // { group, paramId, at } for a short highlight

    presetCount: null,
    presets: [], // [{ index, name }]
    presetsLoading: null, // { done, total }
    currentPresetIndex: null, // null until a patch event (U7)

    tuner: { enabled: false, onDevice: false, note: -1, name: null, cents: 0, at: 0, busy: false },

    commands: { total: 0, storageWrites: 0, last: null },

    log: [], // [{ id, t, level, text }]
    hexLog: [], // [{ id, t, dir, hex, size, lines: string[] }]

    mock: {
      latencyMs: 10,
      dropRate: 0,
      chunkSize: 0,
      forceTableDownload: false,
      firmwareVersion: '2.50.2',
      tunerPitch: 2.0,
      knob: { key: '', value: 0.5 },
      presetOnAmp: 0,
      tapBpm: 120,
      master: 0.5,
    },

    ui: { tab: 'connect', logOpen: false, logTab: 'connection', hexEnabled: false, showKeepalives: false },
  };
}

let nextId = 1;

/**
 * @param {{reactive?:(o:object)=>object, now?:()=>number}} [opts]
 */
export function createStore({ reactive = (o) => o, now = () => Date.now() } = {}) {
  const state = reactive(initialState());
  const subs = new Set();
  const notify = () => {
    for (const fn of [...subs]) fn(state);
  };

  const push = (arr, item, max) => {
    arr.push(item);
    if (arr.length > max) arr.splice(0, arr.length - max);
  };

  return {
    state,

    /** Subscribe to every change. Returns an unsubscribe function. */
    subscribe(fn) {
      subs.add(fn);
      return () => subs.delete(fn);
    },

    /** Shallow-merge `partial` into the state. */
    patch(partial) {
      Object.assign(state, partial);
      notify();
    },

    /** Shallow-merge into a nested object, e.g. patchIn('tuner', { note: 3 }). */
    patchIn(key, partial) {
      Object.assign(state[key], partial);
      notify();
    },

    log(level, text) {
      push(state.log, { id: nextId++, t: now(), level, text }, LOG_MAX);
      notify();
    },

    hex(entry) {
      push(state.hexLog, { id: nextId++, t: now(), ...entry }, HEX_MAX);
      notify();
    },

    clearLogs() {
      state.log.splice(0);
      state.hexLog.splice(0);
      notify();
    },

    countCommand(c) {
      state.commands.total++;
      if (c.writesStorage) state.commands.storageWrites++;
      state.commands.last = `${c.service}.${c.name}`;
      notify();
    },

    /** Reset everything that belongs to one amp connection. */
    resetConnection() {
      const fresh = initialState();
      for (const k of ['deviceInfo', 'channel', 'versions', 'symbolTable', 'deviceSettings', 'fbvConnected', 'tempo', 'editBuffer', 'dirty', 'lastParam', 'presetCount', 'presets', 'presetsLoading', 'currentPresetIndex', 'tuner', 'commands', 'tableDownload', 'phase', 'error']) {
        state[k] = fresh[k];
      }
      notify();
    },
  };
}

/** Plain-text export of both logs (for the "copy log" button). */
export function logsAsText(state) {
  const ts = (t) => new Date(t).toISOString().slice(11, 23);
  const lines = [`ReAmpliFi log, ${new Date().toISOString()}, mode ${state.mode}`];
  if (state.deviceInfo) lines.push(`device: ${state.deviceInfo.productName} fw ${state.deviceInfo.firmwareString} (0x${(state.deviceInfo.firmwareRevision >>> 0).toString(16).padStart(8, '0')})`);
  lines.push(`commands sent: ${state.commands.total}, storage writes: ${state.commands.storageWrites}`, '', '== connection log ==');
  for (const e of state.log) lines.push(`${ts(e.t)} ${e.level.padEnd(5)} ${e.text}`);
  if (state.hexLog.length) {
    lines.push('', '== byte log ==');
    for (const e of state.hexLog) {
      lines.push(`${ts(e.t)} ${e.dir} ${e.size}B ${e.hex}`);
      for (const l of e.lines) lines.push(`             ${l}`);
    }
  }
  return lines.join('\n');
}
