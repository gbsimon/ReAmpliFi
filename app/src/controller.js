// Session lifecycle: transport → AmpSession (read-only) → store. The UI calls these methods and
// reads the store; it never builds protocol bytes. Every amp request goes through AmpSession,
// whose guard.js allow-list runs before anything is encoded, and the session is opened with
// { readOnly: true } so P1 cannot send param edits, preset loads or storage writes.

import { AmpSession } from '@protocol/session.js';
import { TraceDecoder } from '@protocol/trace.js';
import { bytesToHex, hexToBytes } from '@protocol/values.js';
import { UnsupportedFirmwareError, FirmwareGuardError } from '@protocol/guard.js';
import { TimeoutError, ReadOnlyError } from '@protocol/errors.js';
import { openSerialTransport, rememberedPorts, createMockLink, MOCK_BUNDLED_TABLE } from './transport.js';

const SYMTAB_CACHE_KEY = 'reamplifi.symbolTable.v1';
const HEX_PREVIEW_BYTES = 48;

const CONNECTING_PHASES = { sync: 'syncing', deviceInfo: 'syncing', channel: 'syncing', handshake: 'handshaking', tableDownload: 'handshaking', librarian: 'handshaking', editBuffer: 'handshaking', tuner: 'handshaking' };

const PHASE_TEXT = {
  sync: 'IAP link sync (device-info channel)',
  deviceInfo: 'Reading device info',
  channel: 'Link sync (editor + librarian channel)',
  handshake: 'Editor handshake (symbol table check)',
  tableDownload: 'Downloading the symbol table from the amp',
  librarian: 'Librarian handshake',
  editBuffer: 'Reading the current tone (edit buffer)',
  tuner: 'Checking tuner state',
  ready: 'Ready',
};

const hex32 = (n) => `0x${(n >>> 0).toString(16).padStart(8, '0')}`;

function loadCachedTable() {
  try {
    const raw = globalThis.localStorage?.getItem(SYMTAB_CACHE_KEY);
    if (!raw) return null;
    const { hex } = JSON.parse(raw);
    return hex ? hexToBytes(hex) : null;
  } catch {
    return null;
  }
}

function saveCachedTable(bytes, crc) {
  try {
    globalThis.localStorage?.setItem(SYMTAB_CACHE_KEY, JSON.stringify({ crc, hex: bytesToHex(bytes) }));
  } catch {
    /* storage full or blocked: next connect downloads again */
  }
}

/** Human message + hint for a failed connect. */
export function explainError(e, mode) {
  const msg = e?.message ?? String(e);
  if (e?.name === 'NotFoundError') return { message: 'No port selected.', hint: 'Pick the amp in the browser dialog. It only lists devices already paired in your OS Bluetooth settings.' };
  if (e?.name === 'SecurityError') return { message: msg, hint: 'Web Serial needs a secure context (https:// or http://localhost) and a user gesture.' };
  if (e?.name === 'NetworkError' || /Failed to open/i.test(msg)) {
    return { message: msg, hint: 'Is the amp switched on and in range? Is another device (a phone with the official app) connected to it? Try toggling Bluetooth, or re-pair the amp.' };
  }
  if (e instanceof UnsupportedFirmwareError) return { message: msg, hint: 'ReAmpliFi never updates firmware. This amp cannot be used with it.' };
  if (e instanceof FirmwareGuardError) return { message: msg, hint: 'A command outside the allow-list was refused before anything was sent.' };
  if (e instanceof ReadOnlyError) return { message: msg, hint: 'This build is read-only (P1).' };
  if (e instanceof TimeoutError || /IAP sync/i.test(msg)) {
    return {
      message: msg,
      hint: mode === 'mock' ? 'The mock link dropped too much traffic; lower the drop rate.' : 'The port opened but the amp did not answer. Make sure no other device holds the amp’s Bluetooth link, then reconnect.',
    };
  }
  return { message: msg, hint: null };
}

export function createController(store, { mode }) {
  const s = store.state;
  let session = null;
  let transport = null;
  let link = null; // mock link { mock, ampSide, transport }
  let decoder = null;
  let offs = [];
  let tunerWatchdog = null;

  const log = (level, text) => store.log(level, text);

  function detach() {
    offs.forEach((f) => f());
    offs = [];
    if (tunerWatchdog) clearInterval(tunerWatchdog);
    tunerWatchdog = null;
  }

  function refreshEditBuffer() {
    if (!session?.editBuffer) {
      store.patch({ editBuffer: null });
      return;
    }
    // a fresh plain object each time keeps Alpine's reactivity simple
    store.patch({ editBuffer: JSON.parse(JSON.stringify(session.getEditBufferParams())) });
  }

  // rx arrives in arbitrary pieces: hold the bytes of a direction until a frame (or an IAP
  // string) completes, so one log entry = the bytes that made up those frames
  let held = { tx: [], rx: [] };

  function onTrace({ dir, bytes }) {
    if (!s.ui.hexEnabled) return;
    decoder ??= new TraceDecoder();
    const lines = decoder.push(dir, bytes);
    const parts = held[dir];
    parts.push(bytes);
    if (!lines.length) {
      if (parts.reduce((n, b) => n + b.length, 0) > 4096) parts.splice(0, parts.length - 1); // never grow without bound
      return;
    }
    held[dir] = [];
    if (!s.ui.showKeepalives && lines.every((l) => l.kind === 'rsmc' && l.keepalive)) return;
    const size = parts.reduce((n, b) => n + b.length, 0);
    const all = new Uint8Array(size);
    let o = 0;
    for (const b of parts) {
      all.set(b, o);
      o += b.length;
    }
    const shown = size > HEX_PREVIEW_BYTES ? `${bytesToHex(all.subarray(0, HEX_PREVIEW_BYTES), ' ')} …` : bytesToHex(all, ' ');
    store.hex({ dir, size, hex: shown, lines: lines.filter((l) => s.ui.showKeepalives || !l.keepalive).map((l) => l.text) });
  }

  function wire(sess) {
    const on = (ev, fn) => offs.push(sess.on(ev, fn));
    on('trace', onTrace);
    on('phase', (p) => {
      if (p.phase === 'tableDownload') {
        store.patch({ tableDownload: { received: p.received, total: p.total } });
        store.patchIn('symbolTable', { status: 'downloading', size: p.total });
        if (p.received === 0) log('info', `Symbol table not accepted from cache/bundle: downloading ${p.total} bytes from the amp`);
        return;
      }
      if (p.phase === 'handshake') store.patchIn('symbolTable', { status: 'checking' });
      store.patch({ phase: p.phase, ...(CONNECTING_PHASES[p.phase] ? { connection: CONNECTING_PHASES[p.phase] } : {}) });
      log('info', PHASE_TEXT[p.phase] ?? p.phase);
    });
    on('command', (c) => {
      store.countCommand(c);
      log(c.writesStorage ? 'warn' : 'debug', `→ ${c.service}.${c.name}${c.index !== undefined ? `(${c.index === 0xffffffff ? 'edit buffer' : c.index})` : ''}${c.writesStorage ? '  [STORAGE WRITE]' : ''}`);
    });
    on('symbolTable', ({ bytes, crc, source }) => {
      store.patchIn('symbolTable', { status: 'accepted', source, crc, size: bytes.length });
      log('info', `Symbol table accepted: ${source}, CRC ${hex32(crc)}, ${bytes.length} bytes`);
      if (mode === 'serial' && source === 'downloaded') saveCachedTable(bytes, crc);
    });
    on('editBuffer', () => refreshEditBuffer());
    on('paramChanged', (e) => {
      if (e.group === 'global') {
        if (e.paramId === '@tempo') store.patch({ tempo: e.value });
        return;
      }
      refreshEditBuffer();
      store.patch({ lastParam: { group: e.group, paramId: e.paramId, at: Date.now() } });
      log('debug', `amp ${e.onDevice ? '→' : '←'} ${e.group}/${e.paramId} = ${typeof e.value === 'number' ? e.value.toFixed(3) : e.value}`);
    });
    on('presetChanged', (e) => {
      store.patch({ currentPresetIndex: e.index });
      log('info', `Preset ${e.index === null ? '(edit buffer loaded)' : e.index + 1} selected ${e.onDevice ? 'on the amp' : 'from the app'}`);
    });
    on('presetSaved', async (e) => {
      log('info', `Preset ${e.index + 1} saved on the amp: refreshing its name`);
      try {
        const name = await session.getPresetName(e.index);
        const i = s.presets.findIndex((p) => p.index === e.index);
        if (i >= 0) s.presets.splice(i, 1, { index: e.index, name });
        store.patch({});
      } catch (err) {
        log('warn', `Could not refresh preset ${e.index + 1}: ${err.message}`);
      }
    });
    on('tuner', (t) => store.patchIn('tuner', { note: t.note, name: t.name, cents: t.cents, at: Date.now() }));
    on('tunerEnabled', (t) => {
      store.patchIn('tuner', { enabled: t.enabled, onDevice: t.onDevice, ...(t.enabled ? {} : { note: -1, name: null, cents: 0 }) });
      log('info', `Tuner ${t.enabled ? 'on' : 'off'}${t.onDevice ? ' (switched at the amp)' : ''}`);
    });
    on('tapTempo', ({ bpm }) => {
      store.patch({ tempo: bpm });
      log('info', `Tap tempo: ${bpm.toFixed(1)} BPM`);
    });
    on('deviceSettingChanged', (e) => {
      store.patch({ deviceSettings: { ...s.deviceSettings, [e.setting]: e.value } });
      log('debug', `Device setting ${e.setting} = ${typeof e.value === 'number' ? e.value.toFixed(3) : e.value}`);
    });
    on('fbvStatus', ({ connected }) => store.patch({ fbvConnected: connected }));
    on('error', (e) => log('warn', `Protocol warning: ${e.message}`));
    on('disconnect', (d) => {
      detach();
      if (d.reason === 'error') {
        store.patch({ connection: 'lost', error: { message: `Link lost: ${d.error?.message ?? 'unknown error'}`, hint: mode === 'serial' ? 'Check that the amp is on and in range, then reconnect.' : null } });
        log('error', `Link lost: ${d.error?.message ?? 'unknown error'}`);
      } else {
        store.patch({ connection: 'idle' });
        log('info', 'Disconnected');
      }
      link?.mock?.destroy();
      session = null;
      transport = null;
      link = null;
    });
  }

  async function loadPresetNames() {
    if (!session) return;
    store.patch({ presets: [], presetsLoading: { done: 0, total: session.presetCount } });
    try {
      await session.getPresetNames({
        onProgress: ({ index, name, done, total }) => {
          s.presets.push({ index, name });
          store.patch({ presetsLoading: { done, total } });
        },
      });
      log('info', `Read ${s.presets.length} preset names`);
    } catch (e) {
      log('warn', `Reading preset names stopped: ${e.message}`);
    } finally {
      store.patch({ presetsLoading: null });
    }
  }

  async function startSession(t) {
    transport = t;
    decoder = null;
    held = { tx: [], rx: [] };
    const opts = { readOnly: true };
    if (mode === 'mock') opts.symbolTable = MOCK_BUNDLED_TABLE;
    else {
      const cached = loadCachedTable();
      if (cached) opts.cachedSymbolTable = cached;
    }
    session = new AmpSession(t, opts);
    wire(session);
    store.patch({ connection: 'syncing' });
    const sum = await session.connect();
    const di = sum.deviceInfo;
    store.patch({
      connection: 'ready',
      phase: 'ready',
      tableDownload: null,
      deviceInfo: { productName: di.productName, model: di.model, serialNumber: di.serialNumber, firmwareString: di.firmwareString, firmwareRevision: di.firmwareRevision, correctedVersion: di.correctedVersion, productId: di.productId },
      channel: { mtu: sum.channel.mtu, timeoutMs: sum.channel.timeoutMs, heartbeatMs: Math.min(sum.channel.timeoutMs >> 2, 1000) },
      versions: { editor: sum.editorVersion, librarian: sum.librarianVersion },
      presetCount: sum.presetCount,
      dirty: sum.dirtyState,
    });
    store.patchIn('tuner', { enabled: sum.tunerEnabled });
    log('info', `Connected: ${di.productName}, firmware ${di.firmwareString} (${hex32(di.firmwareRevision)}), ${sum.presetCount} presets`);
    tunerWatchdog = setInterval(() => {
      // no Note event for a while → treat as no signal
      if (s.tuner.enabled && s.tuner.note >= 0 && Date.now() - s.tuner.at > 1500) store.patchIn('tuner', { note: -1, name: null, cents: 0 });
    }, 500);
    loadPresetNames();
  }

  async function failConnect(e) {
    const err = explainError(e, mode);
    log('error', `Connect failed: ${err.message}`);
    detach();
    try {
      await transport?.close?.();
    } catch {
      /* ignore */
    }
    link?.mock?.destroy();
    session = null;
    transport = null;
    link = null;
    store.patch({ connection: 'idle', error: e?.name === 'NotFoundError' ? null : err, phase: null, tableDownload: null });
  }

  return {
    get session() {
      return session;
    },
    get mock() {
      return link?.mock ?? null;
    },

    async refreshRememberedPorts() {
      if (mode !== 'serial') return;
      try {
        const ports = await rememberedPorts();
        this._ports = ports;
        store.patch({ rememberedPorts: ports.map((p) => ({ label: p.label })) });
      } catch (e) {
        log('warn', `Could not list remembered ports: ${e.message}`);
      }
    },

    /** Connect through the picker (or the mock). Must be called from a user gesture. */
    async connect({ remembered = null } = {}) {
      if (session) return;
      store.resetConnection();
      try {
        if (mode === 'mock') {
          link = createMockLink(s.mock);
          link.mock.on('guardViolation', ({ error }) => log('error', error.message));
          log('info', `Mock amp: firmware ${s.mock.firmwareVersion}, latency ${s.mock.latencyMs} ms, drop ${(s.mock.dropRate * 100).toFixed(1)} %, chunk ${s.mock.chunkSize || 'off'}${s.mock.forceTableDownload ? ', forced table download' : ''}`);
          await startSession(link.transport);
        } else {
          store.patch({ connection: 'picking' });
          const port = remembered !== null ? this._ports?.[remembered]?.port : undefined;
          const t = await openSerialTransport({
            port,
            onWarning: (e) => log('warn', `Serial: ${e.message}`),
            onPicked: () => log('info', 'Port selected: opening'),
          });
          t.onClose(({ reason, error }) => log(reason === 'closed' ? 'debug' : 'warn', `Serial port closed (${reason}${error ? `: ${error.message}` : ''})`));
          await startSession(t);
          this.refreshRememberedPorts();
        }
      } catch (e) {
        await failConnect(e);
      }
    },

    async disconnect() {
      if (!session) {
        store.patch({ connection: 'idle' });
        return;
      }
      const l = link;
      try {
        await session.disconnect();
      } catch (e) {
        log('warn', `Disconnect: ${e.message}`);
      }
      l?.mock?.destroy();
    },

    async setTuner(on) {
      if (!session || s.connection !== 'ready') return;
      store.patchIn('tuner', { busy: true });
      try {
        await session.setTuner(on);
      } catch (e) {
        log('error', `Tuner: ${e.message}`);
      } finally {
        store.patchIn('tuner', { busy: false });
      }
    },

    reloadPresetNames: () => loadPresetNames(),

    /** Reset the byte decoder (when the hex log is switched on mid-session). */
    resetDecoder() {
      decoder = null;
      held = { tx: [], rx: [] };
    },

    // ---------------------------------------------------------------- mock dev panel (amp side)
    mockTurnKnob(group, paramId, value) {
      link?.mock?.turnKnob(group, paramId, value);
    },
    mockSelectPreset(n) {
      link?.mock?.selectPresetOnAmp(n);
    },
    mockTapTempo(bpm) {
      link?.mock?.tapTempo(bpm);
    },
    mockTuner(on) {
      link?.mock?.setTunerOnAmp(on);
    },
    mockTunerPitch(v) {
      // a little wobble, like a real string
      link?.mock?.setTunerInput([v, v + 0.01, v - 0.008, v + 0.004]);
    },
    mockMaster(v) {
      link?.mock?.setMasterVolume(v);
    },
    mockSaveOnAmp(n) {
      link?.mock?.saveOnAmp(n);
    },
    mockDropLink() {
      log('warn', 'Mock: the amp side dropped the link');
      link?.ampSide?.close();
    },
    mockGoSilent() {
      log('warn', 'Mock: the amp stopped answering (heartbeat timeout expected)');
      link?.mock?.destroy();
    },
  };
}
