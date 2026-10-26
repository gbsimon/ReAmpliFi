// High-level AmpSession: the phone side of the whole stack over an abstract byte transport.
//
//   transport = { write(Uint8Array), onData(cb) → unsubscribe?, close(), onClose?(cb) }
//
// (Web Serial, a Capacitor SPP plugin, a WebSocket bridge, or mock/memoryTransport.js.)
//
// Connect sequence (native_transport.md §7, native_messages.md §6):
//  1. Device-info phase: IAP sync → RSMC start (MTU 240) → stream 0x2003→0x03EF (T 4000) →
//     service-mode word 2 + echo → read 200-byte record → FIN → IAP x STOP.
//  2. Refuse firmware < 0x01000000 (guard.js). Pick MTU / heartbeat T (setupMessageChannelParameters).
//  3. New channel: IAP sync again, RSMC seq restarts at 0. Editor stream 0x2002→0x03ED,
//     librarian stream 0x2003→0x03EF + service-mode word 1 + echo.
//  4. Editor: GetVersion, Handshake(cached CRC) → Handshake(bundled CRC) → download table
//     (cmds 2, 3) and Handshake(its CRC).
//  5. Librarian: GetVersion, GetNumPresets, Handshake (same CRC).
//  6. Editor GetDirtyState, librarian GetPresetFile(edit buffer) → decode the current tone.
//  7. Event registration is local only (nothing sent). Editor GetDspModelParam(Tuner, Enable);
//     if the tuner is on, RegisterDspEvent(Tuner, Note).
//
// Every request goes through guard.assertCommandAllowed() BEFORE it is encoded.

import { Emitter } from './emitter.js';
import { realClock } from './clock.js';
import { IapSync, LinkEndpoint, IAP_STATE, DEFAULT_MTU, HEADER_LEN } from './link.js';
import { Router, ADDR } from './router.js';
import { StreamEndpoint } from './stream.js';
import { RpcClient } from './rpc.js';
import { u32words, readU32, typedValueToJs, TV, tvInt, bytesEqual } from './values.js';
import { SymbolTable, tableCrc } from './symtab.js';
import * as ed from './editor.js';
import * as lib from './librarian.js';
import { EDIT_BUFFER } from './librarian.js';
import {
  assertCommandAllowed,
  assertFirmwareSupported,
  assertServiceModeAllowed,
  assertStreamAllowed,
  SERVICE_MODE,
} from './guard.js';
import { parseDeviceInfo, channelParametersFor, DEVICE_INFO_SIZE } from './deviceInfo.js';
import {
  planSetParam,
  planDeviceSetting,
  dspAddress,
  groupForDspAddress,
  paramDefFor,
  GROUP_TO_SLOT,
  GUITARPROC_SLOT,
  TUNER,
  PS_KEYS,
  ROOT_DEVICE_SETTINGS,
  FW_GATE,
  DEVICE_SETTING_ALIASES,
  SYS_PARAM_KEYS,
  parseStudioCabSymbol,
  enabledFromTypedValue,
  editorCommandForParam,
  editorCommandForDeviceSetting,
} from './mapping.js';
import { blobToPreset, findSlot, getPresetState, setPresetState, presetToEditorParams } from './presetBlob.js';
import { AmpProtocolError, RpcStatusError, FirmwareGateError, MappingError } from './errors.js';

const isAmplifiFamily = (pid) => pid != null && pid - 0x200001 >= 0 && pid - 0x200001 < 7 && ((1 << (pid - 0x200001)) & 0x57) !== 0;

/**
 * Phone-side channel: IAP sync + RSMC link + router, all advanced by one 200 ms tick
 * (AndroidSppMsgChannel::execTasks 0xa35ac runs the sync state machine, then RSMC ExecTasks).
 */
export class Channel {
  constructor({ transport, clock = realClock, mtu = DEFAULT_MTU, tickMs = 200, onTrace }) {
    this.transport = transport;
    this.clock = clock;
    this.mtu = mtu;
    this.tickMs = tickMs;
    this.onTrace = onTrace;
    this.iap = new IapSync((b) => this._rawWrite(b));
    this.link = new LinkEndpoint({
      mtu,
      clock,
      autoTick: false,
      // AndroidSppMsgChannel_write: RSMC bytes are dropped (but reported as success) unless RUNNING
      write: (b) => {
        if (this.iap.state === IAP_STATE.RUNNING) this._rawWrite(b);
      },
      onPacket: (p) => this.router.handlePacket(p),
    });
    this.router = new Router({ send: (m) => this.link.queueMessage(m), mss: mtu - HEADER_LEN, backlog: () => this.link.backlog });
    this._interval = null;
    this._runningWaiters = [];
  }

  _rawWrite(b) {
    this.onTrace?.('tx', b);
    this.transport.write(b);
  }

  /** Raw bytes from the transport. Nothing is parsed as ASCII (§2). */
  receive(bytes) {
    this.link.receive(bytes);
  }

  /** Start IAP sync + RSMC; resolves once RUNNING (~2.2 s). */
  open({ timeoutMs = 5000 } = {}) {
    this.link.start();
    this._interval = this.clock.setInterval(() => this._tick(), this.tickMs);
    return new Promise((resolve, reject) => {
      const timer = this.clock.setTimeout(() => reject(new AmpProtocolError('IAP sync did not reach RUNNING')), timeoutMs);
      this._runningWaiters.push(() => {
        this.clock.clearTimeout(timer);
        resolve();
      });
    });
  }

  _tick() {
    const before = this.iap.state;
    if (this.iap.state === IAP_STATE.STOPPING) {
      this.iap.state = IAP_STATE.STOPPED;
      this._shutdown();
      return;
    }
    this.iap.tick();
    if (before !== IAP_STATE.RUNNING && this.iap.running) {
      const w = this._runningWaiters;
      this._runningWaiters = [];
      w.forEach((f) => f());
    }
    this.link.tick();
  }

  /** New stream on this channel (allow-listed address pair only). */
  createStream({ local, remote, timeoutMs, heartbeatIntervalMs, name }) {
    assertStreamAllowed(local, remote);
    return new StreamEndpoint({ local, remote, router: this.router, mss: this.mtu - HEADER_LEN, clock: this.clock, timeoutMs, heartbeatIntervalMs, name });
  }

  _shutdown() {
    if (this._interval != null) this.clock.clearInterval(this._interval);
    this._interval = null;
    this.link.stop();
  }

  /** Close: write IAP x STOP, then the channel goes down on the next tick (§2 state 6/7). */
  close() {
    this.iap.stop();
    return new Promise((resolve) => {
      if (this._interval == null) return resolve();
      const t = this.clock.setTimeout(() => {
        this._shutdown();
        resolve();
      }, this.tickMs + 1);
    });
  }
}

/**
 * The main entry point for an app.
 *
 * Events: 'connected' {deviceInfo, …}, 'paramChanged' {group, paramId, value, onDevice},
 * 'deviceSettingChanged' {setting, value, onDevice}, 'presetChanged' {index, onDevice},
 * 'presetSaved' {index, onDevice}, 'tuner' {note, cents, name, value}, 'tunerEnabled' {enabled, onDevice},
 * 'tapTempo' {bpm}, 'fbvStatus' {connected}, 'symbolTable' {bytes, crc, source},
 * 'disconnect' {reason, error?}, 'error' (Error), 'trace' {dir, bytes}.
 */
export class AmpSession extends Emitter {
  /**
   * @param {{write:(b:Uint8Array)=>void, onData:(cb:(b:Uint8Array)=>void)=>any, close:()=>void, onClose?:(cb:()=>void)=>any}} transport
   * @param {object} [opts]
   * @param {object} [opts.clock]               injectable clock (FakeClock in tests)
   * @param {Uint8Array} [opts.symbolTable]     bundled table bytes (e.g. the user's own defaultSymbolTable.bin)
   * @param {Uint8Array} [opts.cachedSymbolTable] table saved from a previous successful session
   * @param {Record<string,object>} [opts.models] model definitions for value coercion (mapping.indexModels)
   * @param {number} [opts.heartbeatIntervalMs=1000] stream heartbeat cadence; native uses T>>2, which
   *        can be 4 s and may trip an amp-side 4 s timeout (native_transport.md §5.4) — 1 s is safer
   * @param {number} [opts.mtu]                 force the phase-2 MTU instead of the firmware rule
   * @param {number} [opts.requestTimeoutMs]
   * @param {boolean} [opts.closeTransportOnDisconnect=true]
   */
  constructor(transport, opts = {}) {
    super();
    this.transport = transport;
    this.opts = { heartbeatIntervalMs: 1000, closeTransportOnDisconnect: true, ...opts };
    this.clock = opts.clock ?? realClock;
    this.models = opts.models ?? null;
    this.state = 'idle';
    this.deviceInfo = null;
    this.symtab = null;
    this.presetCount = null;
    this.currentPresetIndex = null; // UNKNOWN until a patch event or selectPreset (§6 step 3)
    this.editBuffer = null;
    this.editBufferBlob = null;
    this.tunerEnabled = false;
    this.dirtyState = null;
    this._channel = null;
    this._streams = [];
    this.editor = null;
    this.librarian = null;
  }

  _trace(dir, bytes) {
    this.emit('trace', { dir, bytes });
  }

  // -------------------------------------------------------------------------- connect

  /** Run the full connect sequence. Resolves with a summary. */
  async connect() {
    if (this.state !== 'idle' && this.state !== 'disconnected') throw new AmpProtocolError(`connect() in state ${this.state}`);
    this.state = 'connecting';
    this._unsubData = this.transport.onData((b) => {
      this._trace('rx', b);
      this._channel?.receive(b);
    });
    this.transport.onClose?.(() => this._onFatal(new AmpProtocolError('transport closed')));
    try {
      // ---- phase 1: device info
      this.deviceInfo = await this._readDeviceInfo();
      assertFirmwareSupported(this.deviceInfo.firmwareRevision);
      const params = channelParametersFor(this.deviceInfo);
      if (this.opts.mtu) params.mtu = this.opts.mtu;
      this.channelParams = params;

      // ---- phase 2: editor + librarian
      const ch = new Channel({ transport: this.transport, clock: this.clock, mtu: params.mtu, onTrace: (d, b) => this._trace(d, b) });
      this._channel = ch;
      await ch.open();
      const hb = Math.min(params.timeoutMs >> 2, this.opts.heartbeatIntervalMs ?? Infinity);
      const es = ch.createStream({ local: ADDR.EDITOR_LOCAL, remote: ADDR.EDITOR_REMOTE, timeoutMs: params.timeoutMs, heartbeatIntervalMs: hb, name: 'editor' });
      const ls = ch.createStream({ local: ADDR.LIBRARIAN_LOCAL, remote: ADDR.LIBRARIAN_REMOTE, timeoutMs: params.timeoutMs, heartbeatIntervalMs: hb, name: 'librarian' });
      this._streams = [es, ls];
      for (const s of this._streams) s.on('error', (e) => this._onFatal(e));
      await es.connect();
      await ls.connect();
      await this._changeMode(ls, SERVICE_MODE.LIBRARIAN);
      this.editor = new RpcClient({
        stream: es,
        name: 'editor',
        service: 'editor',
        allowEvents: true,
        clock: this.clock,
        onEvent: (ev) => this._onEditorEvent(ev),
        onError: (e) => this._onFatal(e),
      });
      this.librarian = new RpcClient({ stream: ls, name: 'librarian', service: 'librarian', clock: this.clock, onError: (e) => this._onFatal(e) });

      await this._editorHandshake();
      await this._librarianHandshake();

      this.dirtyState = (await this._ed(15, () => ed.encodeGetDirtyState())).value;
      await this._refreshEditBuffer();

      const tq = await this._ed(9, () => ed.encodeGetDspModelParam(this.symtab.lookup(TUNER.slot), this.symtab.lookup(TUNER.enable)));
      if (tq.status >= 0 && tq.value && tq.value.bits !== 0) {
        await this._registerTunerEvents(true);
        this.tunerEnabled = true;
      }
      this.state = 'connected';
      const summary = {
        deviceInfo: this.deviceInfo,
        channel: params,
        editorVersion: this.editorVersion,
        librarianVersion: this.librarianVersion,
        symbolTableCrc: this.symtab.crc32,
        symbolTableSource: this.symbolTableSource,
        presetCount: this.presetCount,
        tunerEnabled: this.tunerEnabled,
      };
      this.emit('connected', summary);
      return summary;
    } catch (e) {
      await this._teardown();
      this.state = 'disconnected';
      throw e;
    }
  }

  async _readDeviceInfo() {
    const ch = new Channel({ transport: this.transport, clock: this.clock, mtu: DEFAULT_MTU, onTrace: (d, b) => this._trace(d, b) });
    this._channel = ch;
    await ch.open();
    const s = ch.createStream({ local: ADDR.LIBRARIAN_LOCAL, remote: ADDR.LIBRARIAN_REMOTE, timeoutMs: 4000, name: 'deviceinfo' });
    try {
      await s.connect();
      await this._changeMode(s, SERVICE_MODE.DEVICE_INFO);
      const info = parseDeviceInfo(await s.read(DEVICE_INFO_SIZE));
      await s.close();
      return info;
    } finally {
      s.destroy();
      await ch.close();
      this._channel = null;
    }
  }

  /** Service-mode word + 4-byte echo (changeMode 0xa1d5e). Guarded: only words 1 and 2. */
  async _changeMode(stream, word) {
    assertServiceModeAllowed(word);
    const out = u32words(word);
    stream.write(out);
    const echo = await stream.read(4);
    if (!bytesEqual(echo, out)) throw new AmpProtocolError(`service-mode echo mismatch (sent ${word}, got ${readU32(echo, 0)})`, -2006);
  }

  async _editorHandshake() {
    this.editorVersion = (await this._ed(1, () => ed.encodeGetVersion())).value;
    const candidates = [];
    if (this.opts.cachedSymbolTable) candidates.push(['cached', this.opts.cachedSymbolTable]);
    if (this.opts.symbolTable) candidates.push(['bundled', this.opts.symbolTable]);
    let accepted = null;
    for (const [source, bytes] of candidates) {
      const st = (await this._ed(4, () => ed.encodeHandshake(tableCrc(bytes)))).status;
      if (st >= 0) {
        accepted = { source, bytes };
        break;
      }
    }
    if (!accepted) {
      // choice 3: download the amp's own table (editor cmds 2 and 3)
      const size = (await this._ed(2, () => ed.encodeGetSymbolTableSize())).value;
      const bytes = (await this._ed(3, () => ed.encodeGetSymbolTable(), { timeoutMs: null })).table;
      if (bytes.length !== size) throw new AmpProtocolError(`downloaded symbol table is ${bytes.length} bytes, expected ${size}`);
      const st = (await this._ed(4, () => ed.encodeHandshake(tableCrc(bytes)))).status;
      if (st < 0) throw new RpcStatusError(`editor Handshake rejected even the amp's own table (status ${st})`, st);
      accepted = { source: 'downloaded', bytes };
    }
    this.symtab = new SymbolTable(accepted.bytes);
    this.symbolTableSource = accepted.source;
    this.emit('symbolTable', { bytes: accepted.bytes, crc: this.symtab.crc32, source: accepted.source });
  }

  async _librarianHandshake() {
    this.librarianVersion = (await this._lib(1, () => lib.encodeGetVersion())).value;
    this.presetCount = (await this._lib(5, () => lib.encodeGetNumPresets())).value;
    const st = (await this._lib(4, () => lib.encodeHandshake(this.symtab.crc32))).status;
    if (st < 0) throw new RpcStatusError(`librarian Handshake rejected (status ${st})`, st);
  }

  // -------------------------------------------------------------------------- RPC helpers

  /** Editor request: allow-list check → encode → send → decode. */
  async _ed(cmdId, encode, { confirmWrite, timeoutMs } = {}) {
    assertCommandAllowed('editor', cmdId, { confirmWrite });
    const info = ed.EDITOR_COMMANDS_BY_ID[cmdId];
    const body = await this.editor.request(encode(), { timeoutMs: timeoutMs !== undefined ? timeoutMs : (this.opts.requestTimeoutMs ?? info.timeoutMs), label: `editor ${info.name}`, confirmWrite });
    return ed.decodeEditorResponse(cmdId, body);
  }

  /** Librarian request: allow-list check → encode → send → decode. */
  async _lib(cmdId, encode, { index, confirmWrite, timeoutMs } = {}) {
    assertCommandAllowed('librarian', cmdId, { index, confirmWrite });
    const info = lib.LIBRARIAN_COMMANDS_BY_ID[cmdId];
    const body = await this.librarian.request(encode(), { timeoutMs: timeoutMs !== undefined ? timeoutMs : (this.opts.requestTimeoutMs ?? info.timeoutMs), label: `librarian ${info.name}`, confirmWrite });
    return lib.decodeLibrarianResponse(cmdId, body);
  }

  _requireConnected() {
    if (this.state !== 'connected') throw new AmpProtocolError(`not connected (state ${this.state})`);
  }

  static _ok(r, what) {
    if (r.status !== undefined && r.status < 0) throw new RpcStatusError(`${what} failed with status ${r.status}`, r.status);
    return r;
  }

  get _fw() {
    return this.deviceInfo?.firmwareRevision ?? 0;
  }

  _fwGate(min, what) {
    if (isAmplifiFamily(this.deviceInfo?.productId) && this._fw < min) {
      throw new FirmwareGateError(`${what} needs amp firmware ≥ 0x${min.toString(16)} (native gate)`);
    }
  }

  // -------------------------------------------------------------------------- edit buffer

  async _refreshEditBuffer() {
    const r = AmpSession._ok(await this._lib(11, () => lib.encodeGetPresetFile(EDIT_BUFFER), { index: EDIT_BUFFER }), 'GetPresetFile(edit buffer)');
    this._setEditBuffer(r.blob);
  }

  _setEditBuffer(blob) {
    this.editBufferBlob = blob;
    try {
      this.editBuffer = blobToPreset(blob, this.symtab);
    } catch (e) {
      this.editBuffer = null;
      this.emit('error', e);
    }
  }

  /** Editor-level view of the current tone: { name, groups: { amp: { '@model', Drive, … }, … } }. */
  getEditBufferParams() {
    return presetToEditorParams(this.editBuffer);
  }

  /** Current model symbol of an editor group, from the edit-buffer mirror. */
  modelOf(group) {
    if (group === 'cab') {
      const a = findSlot(this.editBuffer, 'StudioCab')?.asset;
      return a ? parseStudioCabSymbol(a).cab : undefined;
    }
    return findSlot(this.editBuffer, GROUP_TO_SLOT[group])?.asset ?? undefined;
  }

  /** Read a param from the local edit-buffer mirror (no wire traffic). */
  getParam(group, paramId) {
    if (paramId === '@model') return this.modelOf(group);
    if (group === 'cab' && paramId === '@mic') {
      const a = findSlot(this.editBuffer, 'StudioCab')?.asset;
      return a ? parseStudioCabSymbol(a).mic : undefined;
    }
    if (group === 'global') return this._globals?.[paramId];
    const a = dspAddress(group, paramId);
    return getPresetState(this.editBuffer, a.slot, a.param);
  }

  _paramDef(group, paramId) {
    if (!this.models) return null;
    const model = group === 'global' ? '@global_params' : this.modelOf(group);
    return model ? paramDefFor(this.models, model, paramId) : null;
  }

  /**
   * Set one edit-buffer parameter (nativeSetEditBufferParam). Not a storage write, except the
   * global PS keys (@tweakmin/@tweakmax/@pedal2assign), which need { confirmWrite: true }.
   * @param {string} group      amp, cab, fx1..fx3, reverb, gate, wah, volume, compressor, eq, global
   * @param {string} paramId    e.g. 'Drive', '@enabled', '@mix', '@temposync', '@mic', '@tempo'
   * @param {*} value
   * @param {{type?:'float'|'int'|'bool', confirmWrite?:boolean, tweak?:{group:string,param:string}}} [opts]
   */
  async setParam(group, paramId, value, opts = {}) {
    this._requireConnected();
    if (group === 'global' && paramId in PS_KEYS && paramId !== '@tempo') this._fwGate(FW_GATE.PS_KEYS, `global/${paramId}`);
    // guard.js allow-list check BEFORE any bytes are encoded
    assertCommandAllowed('editor', editorCommandForParam(group, paramId), { confirmWrite: opts.confirmWrite });
    const syncSelect = paramId === '@temposync' && value ? getPresetState(this.editBuffer, GROUP_TO_SLOT[group], 'SyncSelect') ?? 1 : undefined;
    const plan = planSetParam({
      group,
      paramId,
      value,
      symtab: this.symtab,
      paramDef: this._paramDef(group, paramId),
      type: opts.type,
      syncSelect,
      cabModel: group === 'cab' ? this.modelOf('cab') : undefined,
      tweak: opts.tweak,
      confirmWrite: opts.confirmWrite,
    });
    const cmdId = ed.EDITOR_CMD[plan.command];
    const r = await this._ed(cmdId, () => plan.request, { confirmWrite: opts.confirmWrite });
    AmpSession._ok(r, `${plan.command} ${group}/${paramId}`);
    this._applyLocal(group, paramId, plan);
    const jsValue = plan.value ? typedValueToJs(plan.value) : value;
    this.emit('paramChanged', { group, paramId, value: paramId === '@temposync' ? Boolean(value) : jsValue, onDevice: false });
    return r;
  }

  _applyLocal(group, paramId, plan) {
    if (!this.editBuffer) return;
    if (plan.command === 'LoadDspModel') {
      const s = findSlot(this.editBuffer, 'StudioCab');
      if (s) s.asset = plan.address.param;
    } else if (plan.command === 'SetDspModelParam') {
      setPresetState(this.editBuffer, plan.address.slot, plan.address.param, plan.value, this.symtab);
    } else if (group === 'global') {
      (this._globals ??= {})[paramId] = plan.value ? typedValueToJs(plan.value) : undefined;
    }
  }

  /** Bind the amp's TWEAK knob to (group, param) (cmd 13). */
  bindTweak(group, param) {
    return this.setParam('global', '@tweakparam', param, { tweak: { group, param } });
  }

  /** Global tempo in BPM (cmd 14). */
  setTempo(bpm) {
    return this.setParam('global', '@tempo', bpm);
  }

  // -------------------------------------------------------------------------- device settings

  /**
   * nativeSetDeviceSetting: Master / GuitOutputGain (root-slot float, not a storage write),
   * or a persistent sys param such as TapTempoLED (cmd 18: needs { confirmWrite: true }).
   */
  async setDeviceSetting(name, value, opts = {}) {
    this._requireConnected();
    const n = DEVICE_SETTING_ALIASES[name] ?? name;
    if (n in SYS_PARAM_KEYS) this._fwGate(FW_GATE.PERSISTENT_SYS_PARAMS, `device setting ${n}`);
    assertCommandAllowed('editor', editorCommandForDeviceSetting(n), { confirmWrite: opts.confirmWrite });
    const plan = planDeviceSetting({ name: n, value, symtab: this.symtab, type: opts.type, confirmWrite: opts.confirmWrite });
    const r = AmpSession._ok(await this._ed(ed.EDITOR_CMD[plan.command], () => plan.request, { confirmWrite: opts.confirmWrite }), `setDeviceSetting ${n}`);
    this.emit('deviceSettingChanged', { setting: n, value: typedValueToJs(plan.value), onDevice: false });
    return r;
  }

  /** nativeGetDeviceSetting (getDeviceSetting 0xe192c). */
  async getDeviceSetting(name) {
    this._requireConnected();
    const n = DEVICE_SETTING_ALIASES[name] ?? name;
    if (n === 'FBVConnected') return (await this._ed(16, () => ed.encodeGetFbvConnectivityStatus())).value !== 0;
    if (n in SYS_PARAM_KEYS) {
      this._fwGate(FW_GATE.PERSISTENT_SYS_PARAMS, `device setting ${n}`);
      const r = AmpSession._ok(await this._ed(17, () => ed.encodeGetPersistentSysParam(SYS_PARAM_KEYS[n])), `get ${n}`);
      return typedValueToJs(r.value);
    }
    const r = AmpSession._ok(await this._ed(9, () => ed.encodeGetDspModelParam(0xffffffff, this.symtab.lookup(n))), `get ${n}`);
    return typedValueToJs(r.value);
  }

  // -------------------------------------------------------------------------- presets

  /**
   * Select preset slot n (0-based): read slot → write the blob to the edit buffer (pass-through),
   * exactly like loadPresetFromDevice 0xd5444. Does not write any slot.
   */
  async selectPreset(n) {
    this._requireConnected();
    const r = AmpSession._ok(await this._lib(11, () => lib.encodeGetPresetFile(n), { index: n }), `GetPresetFile(${n})`);
    await this.writeEditBuffer(r.blob, { emit: false });
    this.currentPresetIndex = n;
    this.emit('presetChanged', { index: n, onDevice: false });
    return r.blob;
  }

  /** Replace the edit buffer with `blob` (SetPresetFile 0xFFFFFFFF): tone load, model change. */
  async writeEditBuffer(blob, { emit = true } = {}) {
    this._requireConnected();
    AmpSession._ok(await this._lib(12, () => lib.encodeSetPresetFile(EDIT_BUFFER, blob), { index: EDIT_BUFFER }), 'SetPresetFile(edit buffer)');
    this._setEditBuffer(blob);
    if (emit) this.emit('presetChanged', { index: null, onDevice: false });
  }

  /** Read the raw blob of slot n (or EDIT_BUFFER). */
  async getPresetFile(n) {
    this._requireConnected();
    return AmpSession._ok(await this._lib(11, () => lib.encodeGetPresetFile(n), { index: n }), `GetPresetFile(${n})`).blob;
  }

  /**
   * Save `blob` into preset slot n. WRITES THE AMP'S STORAGE: requires { confirmWrite: true }.
   */
  async savePreset(n, blob, opts = {}) {
    this._requireConnected();
    if (n >>> 0 === EDIT_BUFFER) throw new AmpProtocolError('savePreset targets a slot; use writeEditBuffer for the edit buffer');
    AmpSession._ok(await this._lib(12, () => lib.encodeSetPresetFile(n, blob, opts), { index: n, confirmWrite: opts.confirmWrite }), `SetPresetFile(${n})`);
    this.emit('presetSaved', { index: n, onDevice: false });
  }

  /** Move a preset (cmd 9 {dst, src}). WRITES STORAGE: requires { confirmWrite: true }. Amp semantics INFERRED. */
  async movePreset(dst, src, opts = {}) {
    this._requireConnected();
    AmpSession._ok(await this._lib(9, () => lib.encodeMovePresetFiles(dst, src, opts), { confirmWrite: opts.confirmWrite }), 'MovePresetFiles');
  }

  /** Name of slot n (cmd 6). */
  async getPresetName(n) {
    this._requireConnected();
    return AmpSession._ok(await this._lib(6, () => lib.encodeGetPresetName(n)), `GetPresetName(${n})`).name;
  }

  /** {uuid, checksum, size, name} of slot n (cmd 14, librarian V2). */
  async getPresetInfo(n) {
    this._requireConnected();
    return AmpSession._ok(await this._lib(14, () => lib.encodeGetPresetInfo(n)), `GetPresetInfo(${n})`);
  }

  /** Names of all slots. */
  async getPresetNames() {
    const out = [];
    for (let i = 0; i < this.presetCount; i++) out.push(await this.getPresetName(i));
    return out;
  }

  // -------------------------------------------------------------------------- tuner

  /** Engage / disengage the tuner (engageTunerInternal 0xe7240). */
  async setTuner(on) {
    this._requireConnected();
    const slot = this.symtab.lookup(TUNER.slot);
    const enable = this.symtab.lookup(TUNER.enable);
    // L6Variant(uint) → TV int, not bool; synchronous
    AmpSession._ok(await this._ed(10, () => ed.encodeSetDspModelParam(slot, enable, tvInt(on ? 1 : 0))), 'tuner enable');
    await this._registerTunerEvents(on);
    this.tunerEnabled = !!on;
    this.emit('tunerEnabled', { enabled: !!on, onDevice: false });
  }

  tunerOn() {
    return this.setTuner(true);
  }

  tunerOff() {
    return this.setTuner(false);
  }

  async _registerTunerEvents(on) {
    const slot = this.symtab.lookup(TUNER.slot);
    const note = this.symtab.lookup(TUNER.note);
    if (on) AmpSession._ok(await this._ed(11, () => ed.encodeRegisterDspEvent(slot, note)), 'RegisterDspEvent');
    else AmpSession._ok(await this._ed(12, () => ed.encodeUnregisterDspEvent(slot, note)), 'UnregisterDspEvent');
  }

  // -------------------------------------------------------------------------- inbound events

  _onEditorEvent({ type, body }) {
    let ev;
    try {
      ev = ed.decodeEditorEvent(type, body);
    } catch (e) {
      this.emit('error', e);
      return;
    }
    const name = (i) => this.symtab?.nameOf(i);
    switch (ev.name) {
      case 'dsp': {
        if (name(ev.slot) === TUNER.slot && name(ev.param) === TUNER.note && ev.value.tag === TV.FLOAT) {
          const v = typedValueToJs(ev.value);
          this.emit('tuner', { value: v, ...ed.tunerValueToNoteCents(v) });
        }
        break;
      }
      case 'param': {
        const slot = name(ev.slot);
        const param = name(ev.param);
        const value = typedValueToJs(ev.value);
        if (slot === '') {
          if (ROOT_DEVICE_SETTINGS.includes(param)) this.emit('deviceSettingChanged', { setting: param, value, onDevice: true });
          break;
        }
        if (slot === TUNER.slot && param === TUNER.enable) {
          const on = ev.value.bits !== 0;
          this.tunerEnabled = on;
          this.emit('tunerEnabled', { enabled: on, onDevice: true });
          // engageTunerInternal(on, onDevice=true) only (un)registers the Note event
          this._registerTunerEvents(on).catch((e) => this.emit('error', e));
          break;
        }
        const m = slot !== undefined && param !== undefined ? groupForDspAddress(slot, param) : null;
        if (!m) break;
        if (this.editBuffer) setPresetState(this.editBuffer, slot, param, ev.value, this.symtab);
        const v = m.paramId === '@enabled' ? enabledFromTypedValue(ev.value) : value;
        this.emit('paramChanged', { group: m.group, paramId: m.paramId, value: v, onDevice: true });
        break;
      }
      case 'patch': {
        const index = typedValueToJs(ev.presetIndex);
        const isSave = ev.isSave.bits !== 0;
        if (isSave) {
          this.emit('presetSaved', { index, onDevice: true });
        } else {
          this.currentPresetIndex = index;
          // resync: the edit buffer was replaced on the amp
          this._refreshEditBuffer()
            .then(() => this.emit('presetChanged', { index, onDevice: true }))
            .catch((e) => this.emit('error', e));
        }
        break;
      }
      case 'tapTempo': {
        const bpm = typedValueToJs(ev.value);
        (this._globals ??= {})['@tempo'] = bpm;
        this.emit('tapTempo', { bpm });
        this.emit('paramChanged', { group: 'global', paramId: '@tempo', value: bpm, onDevice: true });
        break;
      }
      case 'fbvStatus':
        this.emit('fbvStatus', { connected: typedValueToJs(ev.value) > 0 });
        break;
      case 'psKeyChange': {
        const pid = Object.keys(PS_KEYS).find((k) => PS_KEYS[k] === ev.key);
        const value = typedValueToJs(ev.value);
        if (pid) {
          (this._globals ??= {})[pid] = value;
          this.emit('paramChanged', { group: 'global', paramId: pid, value, onDevice: true });
        }
        break;
      }
      default:
        this.emit('event', ev);
    }
  }

  // -------------------------------------------------------------------------- teardown

  _onFatal(err) {
    if (this.state === 'disconnected' || this.state === 'disconnecting') return;
    const wasConnected = this.state === 'connected';
    this._teardown().then(() => {
      this.state = 'disconnected';
      if (wasConnected) this.emit('disconnect', { reason: 'error', error: err });
    });
  }

  async _teardown({ graceful = false } = {}) {
    this.editor?.close();
    this.librarian?.close();
    if (graceful) {
      await Promise.all(this._streams.map((s) => (s.isOpen ? s.close({ timeoutMs: 2000 }) : Promise.resolve())));
    }
    for (const s of this._streams) s.destroy();
    this._streams = [];
    if (this._channel) await this._channel.close();
    this._channel = null;
    if (typeof this._unsubData === 'function') this._unsubData();
    this._unsubData = null;
    if (this.opts.closeTransportOnDisconnect) {
      try {
        this.transport.close();
      } catch {
        /* ignore */
      }
    }
  }

  /** Graceful disconnect: FIN both streams, IAP x STOP, stop RSMC, close the transport. */
  async disconnect() {
    if (this.state !== 'connected') return;
    this.state = 'disconnecting';
    await this._teardown({ graceful: true });
    this.state = 'disconnected';
    this.emit('disconnect', { reason: 'user' });
  }
}

export { MappingError };
