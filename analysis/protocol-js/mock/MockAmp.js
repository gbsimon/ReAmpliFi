// MockAmp: a software AMPLIFi peer implementing the AMP side of every layer
// (IAP detection → RSMC → McBsp router → stream listeners → device info / editor / librarian),
// so the protocol library can be exercised without hardware.
//
// Everything amp-side that the static analysis could not observe is a MOCK CHOICE, not a
// finding: status codes (0 ok, −1 refused, −4 unknown command), tuner event rate, the reaction
// to IAP x START/STOP (reset), MovePresetFiles semantics (remove src, insert at dst), etc.
//
// All presets are synthetic, built with presetBlob.presetToBlob from made-up values. No Line 6
// demo tones or table files are included.
//
// Firmware update / updater paths are NOT implemented: service-mode word 0 is treated as a
// guard violation (emits 'guardViolation'; throws asynchronously when nobody listens).

import { Emitter } from '../src/emitter.js';
import { realClock } from '../src/clock.js';
import { IapDetector, LinkEndpoint, HEADER_LEN } from '../src/link.js';
import { Router, ADDR } from '../src/router.js';
import { StreamEndpoint } from '../src/stream.js';
import { RpcParser } from '../src/rpc.js';
import { crc32 } from '../src/crc.js';
import { buildSymbolTable, parseSymbolTable, ROOT_SLOT_INDEX } from '../src/symtab.js';
import { u32words, readU32, tvFloat, tvInt, tvBool, typedValueToJs, TV } from '../src/values.js';
import * as ed from '../src/editor.js';
import * as lib from '../src/librarian.js';
import { EDIT_BUFFER } from '../src/librarian.js';
import { encodeDeviceInfo, parseFirmwareString } from '../src/deviceInfo.js';
import { blobToPreset, presetToBlob, findSlot, setPresetState, blobStateToTypedValue } from '../src/presetBlob.js';
import { dspAddress, coerceValue, MIC_SUFFIXES, TUNER, GUITARPROC_SLOT, GUITARPROC_ASSET } from '../src/mapping.js';
import { MOCK_SYMBOL_NAMES } from './mockSymbols.js';

const r3 = (x) => Math.round(x * 1000) / 1000;

/**
 * Deterministic synthetic preset #i (structured form, see presetBlob.js).
 * Model names are public identifiers; every value is made up.
 */
export function makeSyntheticPreset(i) {
  const r = (k) => r3(((i * 37 + k * 11) % 97) / 97);
  const f = (param, value) => ({ name: `${param}State`, param, type: 'float', value: Math.fround(value) });
  const b = (param, value) => ({ name: `${param}State`, param, type: 'bool', value });
  const n = (param, value) => ({ name: `${param}State`, param, type: 'int', value });
  const slot = (s, asset, states = []) => ({ slot: s, asset, states, children: [] });
  const amps = ['BritGainJ800', 'BlackfaceLux', 'ClassA30Fawn'];
  return {
    name: `Mock Tone ${i + 1}`,
    psKeys: [{ key: 3, type: 'float', value: 100 + i * 5 }],
    root: {
      slot: GUITARPROC_SLOT,
      asset: GUITARPROC_ASSET,
      states: [
        b('CabEnable', true), b('GateEnable', i % 2 === 0), b('PostCompEnable', true), b('PostEQEnable', false),
        b('WahEnable', false), b('VolumePedalEnable', true), b('FX1Enable', i % 3 === 0), b('FX2Enable', false),
        b('FX3Enable', true), b('FX4Enable', true), b('VolumePost', true), b('FX1Post', false), b('FX2Post', true),
        b('FX3Post', true), b('FX4Post', true), f('FX1Mix', 1), f('FX2Mix', 0.5), f('FX3Mix', r(1)), f('FX4Mix', r(2)),
        n('FX1MixType', 0), n('FX2MixType', 1), n('FX3MixType', 0), f('ChannelVolume', r(3)),
      ],
      children: [
        slot('Gate', 'Gate', [f('Thresh', -50 + i), f('Decay', r(4))]),
        slot('VolumePedal', 'VolumePedal', [f('MaxVol', 1), f('MinVol', 0)]),
        slot('Wah', 'Line6Vetta', [f('Pedal', r(5))]),
        slot('FX1', 'Screamer', [f('Drive', r(6)), f('Gain', r(7)), f('Tone', r(8))]),
        slot('FX2', 'UVibe', [f('Depth', r(9)), f('Speed', r(10)), n('SyncSelect', 0)]),
        slot('FX3', 'StereoDelay', [f('Time', r(11)), f('FbackL', r(12)), f('FbackR', r(13)), n('SyncSelect', 6)]),
        slot('FX4', 'DarkHall1', [f('Decay', r(14)), f('PreDelay', r(15)), f('Tone', r(16))]),
        slot('Amp', amps[i % amps.length], [f('Drive', r(17)), f('Bass', r(18)), f('Mid', r(19)), f('Treble', r(20)), f('Presence', r(21))]),
        slot('Air', 'TNGAIRReflections', [f('Level', 0.5)]),
        slot('StudioCab', `4x12BritT75Studio${MIC_SUFFIXES[i % 4]}`),
        slot('LiveCab', '4x12BritT75Live2x12'),
        slot('PostComp', 'SharcPodFixedComp', [f('Gain', 0)]),
        slot('PostEQ', 'ParaGraphic4_band', [f('Low', r(22))]),
      ],
    },
  };
}

/**
 * Software amp.
 *
 * Options:
 *  - clock                 injectable clock (share the FakeClock with the session in tests)
 *  - firmwareVersion       '2.50.2' (string) or raw u32 firmwareRevision (default '2.50.2')
 *  - productName / model / serialNumber
 *  - symbolTable           table bytes the amp "owns" (default: synthetic table from MOCK_SYMBOL_NAMES)
 *  - forceTableDownload    reject every Handshake until the client downloaded the table (cmd 3)
 *  - acceptCrcs            extra CRCs the Handshake accepts (simulate an amp that accepts a bundled table)
 *  - mtu                   amp-side TX MTU (default 240: never send a frame the phone could reject;
 *                          a frame longer than the receiver's MTU−12 is dropped as a length error)
 *  - rxMtu                 largest frame accepted (default 256: accepts both phone MTUs)
 *  - presetCount           number of synthetic presets (default 8)
 *  - tunerIntervalMs       tuner Note event cadence (default 100 ms; real rate UNKNOWN)
 *  - tunerValues           values cycled by the tuner simulator (semitones above A)
 *  - editorVersion / librarianVersion
 *  - maxDataFramesPerTick  RSMC frames per 200 ms tick (default 1 = native)
 */
export class MockAmp extends Emitter {
  constructor(transport, opts = {}) {
    super();
    this.transport = transport;
    this.clock = opts.clock ?? realClock;
    this.opts = {
      firmwareVersion: '2.50.2',
      productName: 'AMPLIFi 150',
      model: 'AMPLIFi 150',
      serialNumber: 'MOCK-0001',
      forceTableDownload: false,
      acceptCrcs: [],
      mtu: 240,
      rxMtu: 256,
      presetCount: 8,
      tunerIntervalMs: 100,
      tunerValues: [2.1, 2.05, 1.98, 2.0, 7.3, 11.8],
      editorVersion: 1,
      librarianVersion: 1,
      maxDataFramesPerTick: 1,
      ...opts,
    };
    this.firmwareRevision = typeof this.opts.firmwareVersion === 'number' ? this.opts.firmwareVersion >>> 0 : parseFirmwareString(this.opts.firmwareVersion);
    this.tableBytes = this.opts.symbolTable ?? buildSymbolTable(MOCK_SYMBOL_NAMES);
    this.symtab = parseSymbolTable(this.tableBytes);
    this.presets = [];
    for (let i = 0; i < this.opts.presetCount; i++) {
      const p = this.opts.presets?.[i] ?? makeSyntheticPreset(i);
      this.presets.push({ name: p.name, blob: presetToBlob(p, this.symtab), uuid: BigInt(i + 1) });
    }
    this.currentPreset = 0;
    this.editBuffer = blobToPreset(this.presets[0].blob, this.symtab);
    this.dirty = false;
    this.deviceSettings = { Master: 0.5, GuitOutputGain: 0.7 };
    this.sysParams = new Map([[7, tvBool(true)]]);
    this.psKeys = new Map();
    this.tempo = 120;
    this.tweak = null;
    this.tableDownloaded = false;
    this.tuner = { enabled: false, registered: false, timer: null, i: 0 };
    /** Every request received: { service, cmd, name, args } */
    this.requests = [];
    this.unknownCommands = [];
    this.guardViolations = [];
    this.channelStarts = 0;
    this.deviceInfoReads = 0;
    this.link = null;
    this.router = null;
    this.editorStream = null;
    this.librarianStream = null;
    this.iap = new IapDetector((cmd) => this._onIap(cmd));
    this._unsub = transport.onData((b) => this._onRaw(b));
  }

  // ------------------------------------------------------------------ link layer

  _onRaw(bytes) {
    this.iap.push(bytes);
    this.link?.receive(bytes);
  }

  _onIap(cmd) {
    this.emit('iap', cmd);
    if (cmd === 'START') this._startChannel();
    else if (cmd === 'STOP') this._stopChannel();
  }

  /** Mock choice (INFERRED amp behaviour): IAP x START resets the RSMC endpoint and all streams. */
  _startChannel() {
    this._stopChannel();
    this.channelStarts++;
    const mtu = this.opts.mtu;
    this.link = new LinkEndpoint({
      mtu,
      rxMtu: this.opts.rxMtu,
      clock: this.clock,
      maxDataFramesPerTick: this.opts.maxDataFramesPerTick,
      write: (b) => this.transport.write(b),
      onPacket: (p) => this.router.handlePacket(p),
    });
    this.router = new Router({ send: (m) => this.link.queueMessage(m), mss: mtu - HEADER_LEN, backlog: () => this.link.backlog });
    this.link.start();
    this._listenEditor();
    this._listenLibrarian();
  }

  _stopChannel() {
    this._stopTunerSim();
    this.editorStream?.destroy();
    this.librarianStream?.destroy();
    this.editorStream = null;
    this.librarianStream = null;
    this.link?.stop();
    this.link = null;
  }

  _newListener(local, remote, name) {
    const s = new StreamEndpoint({ local, remote, router: this.router, mss: this.opts.mtu - HEADER_LEN, clock: this.clock, requestHeartbeat: false, name });
    s.listen();
    s.on('peerClose', () => s.close());
    s.on('error', (e) => this.emit('streamError', { name, error: e }));
    return s;
  }

  _listenEditor() {
    const s = this._newListener(ADDR.EDITOR_REMOTE, ADDR.EDITOR_LOCAL, 'mock-editor');
    this.editorStream = s;
    s.once('established', () => {
      const parser = new RpcParser(({ id, body }) => this._handleEditor(id, body));
      s.setDataHandler((b) => parser.push(b));
    });
    s.once('closed', () => this.link && this._listenEditor());
    s.once('error', () => this.link && this._listenEditor());
  }

  _listenLibrarian() {
    const s = this._newListener(ADDR.LIBRARIAN_REMOTE, ADDR.LIBRARIAN_LOCAL, 'mock-librarian');
    this.librarianStream = s;
    s.once('established', async () => {
      let word;
      try {
        word = readU32(await s.read(4, { timeoutMs: 60_000 }), 0);
      } catch {
        return;
      }
      if (word === 2) {
        // DEVICE_INFO: echo + 200-byte record
        this.deviceInfoReads++;
        s.write(u32words(2));
        s.write(encodeDeviceInfo({ productName: this.opts.productName, model: this.opts.model, serialNumber: this.opts.serialNumber, firmwareRevision: this.firmwareRevision }));
      } else if (word === 1) {
        // LIBRARIAN
        s.write(u32words(1));
        const parser = new RpcParser(({ id, body }) => this._handleLibrarian(id, body));
        s.setDataHandler((b) => parser.push(b));
      } else {
        // word 0 is the UPDATER service mode: deliberately not implemented. Fail loudly.
        const err = new Error(`MockAmp: refused service-mode word ${word} (not LIBRARIAN/DEVICE_INFO); guard regression in the client`);
        this.guardViolations.push({ word, error: err });
        s.close();
        if (this._listeners.get('guardViolation')?.size) this.emit('guardViolation', { word, error: err });
        else
          queueMicrotask(() => {
            throw err;
          });
      }
    });
    s.once('closed', () => this.link && this._listenLibrarian());
    s.once('error', () => this.link && this._listenLibrarian());
  }

  _write(stream, bytes) {
    if (stream?.isOpen) stream.write(bytes);
  }

  // ------------------------------------------------------------------ editor service

  _acceptsCrc(crc) {
    if (this.opts.acceptCrcs.includes(crc >>> 0)) return true;
    if (crc >>> 0 !== this.symtab.crc32) return false;
    return !this.opts.forceTableDownload || this.tableDownloaded;
  }

  _getParam(slotIdx, paramIdx) {
    const slot = this.symtab.nameOf(slotIdx);
    const param = this.symtab.nameOf(paramIdx);
    if (slot === undefined || param === undefined) return null;
    if (slotIdx >>> 0 === ROOT_SLOT_INDEX) return param in this.deviceSettings ? tvFloat(this.deviceSettings[param]) : null;
    if (slot === TUNER.slot && param === TUNER.enable) return tvInt(this.tuner.enabled ? 1 : 0);
    const st = findSlot(this.editBuffer, slot)?.states.find((s) => s.param === param);
    return st ? blobStateToTypedValue(st, this.symtab) : null;
  }

  _setParam(slotIdx, paramIdx, tv) {
    const slot = this.symtab.nameOf(slotIdx);
    const param = this.symtab.nameOf(paramIdx);
    if (slot === undefined || param === undefined) return -1;
    if (slotIdx >>> 0 === ROOT_SLOT_INDEX) {
      if (!(param in this.deviceSettings)) return -1;
      this.deviceSettings[param] = typedValueToJs(tv);
      return 0;
    }
    if (slot === TUNER.slot && param === TUNER.enable) {
      this.tuner.enabled = tv.bits !== 0;
      this._updateTunerSim();
      return 0;
    }
    if (!setPresetState(this.editBuffer, slot, param, tv, this.symtab)) return -1;
    this.dirty = true;
    return 0;
  }

  _handleEditor(cmd, payload) {
    const info = ed.EDITOR_COMMANDS_BY_ID[cmd];
    const args = info ? ed.decodeEditorRequest(cmd, payload) : {};
    this.requests.push({ service: 'editor', cmd, name: info?.name ?? `?${cmd}`, args });
    this.emit('request', { service: 'editor', cmd, args });
    const out = (bytes) => this._write(this.editorStream, bytes);
    switch (cmd) {
      case 1: return out(ed.encodeU32Response(this.opts.editorVersion));
      case 2: return out(ed.encodeU32Response(this.tableBytes.length));
      case 3:
        this.tableDownloaded = true;
        return out(ed.encodeRawResponse(this.tableBytes));
      case 4: return out(ed.encodeStatusResponse(this._acceptsCrc(args.crc) ? 0 : -1));
      case 5: return out(ed.encodeU32Response(this.editBuffer.root.children.length + 1));
      case 6: return out(ed.encodeRawResponse(u32words(this.symtab.lookup(GUITARPROC_SLOT), ...this.editBuffer.root.children.map((c) => this.symtab.lookup(c.slot)))));
      case 7: {
        const s = findSlot(this.editBuffer, this.symtab.nameOf(args.slot));
        return out(ed.encodeRawResponse(s ? u32words(0, this.symtab.indexOf(s.asset)) : u32words(-1, 0)));
      }
      case 8: {
        const s = findSlot(this.editBuffer, this.symtab.nameOf(args.slot));
        const model = this.symtab.nameOf(args.model);
        if (!s || model === undefined) return out(ed.encodeStatusResponse(-1));
        s.asset = model;
        this.dirty = true;
        return out(ed.encodeStatusResponse(0));
      }
      case 9: {
        const tv = this._getParam(args.slot, args.param);
        return out(tv ? ed.encodeStatusValueResponse(0, tv) : ed.encodeStatusResponse(-1));
      }
      case 10: return out(ed.encodeStatusResponse(this._setParam(args.slot, args.param, args.value)));
      case 11:
      case 12: {
        const isTunerNote = this.symtab.nameOf(args.slot) === TUNER.slot && this.symtab.nameOf(args.param) === TUNER.note;
        if (isTunerNote) {
          this.tuner.registered = cmd === 11;
          this._updateTunerSim();
        }
        return out(ed.encodeStatusResponse(0));
      }
      case 13:
        this.tweak = { slot: this.symtab.nameOf(args.slot), param: this.symtab.nameOf(args.param) };
        return out(ed.encodeStatusResponse(0));
      case 14:
        this.tempo = args.bpm;
        return out(ed.encodeStatusResponse(0));
      case 15: return out(ed.encodeU32Response(this.dirty ? 1 : 0));
      case 16: return out(ed.encodeU32Response(0));
      case 17:
      case 20: {
        const tv = (cmd === 17 ? this.sysParams : this.psKeys).get(args.key);
        return out(tv ? ed.encodeStatusValueResponse(0, tv) : ed.encodeStatusResponse(-1));
      }
      case 18:
        this.sysParams.set(args.key, args.value);
        return out(ed.encodeStatusResponse(0));
      case 19:
        this.psKeys.set(args.key, args.value);
        return out(ed.encodeStatusResponse(0));
      default:
        // 21/22 are AEON only; anything else is unknown. Mock choice: reply status −4.
        if (!info || cmd > 20) this.unknownCommands.push({ service: 'editor', cmd });
        return out(ed.encodeStatusResponse(-4));
    }
  }

  // ------------------------------------------------------------------ librarian service

  _presetAt(idx) {
    return idx >>> 0 === EDIT_BUFFER ? null : this.presets[idx];
  }

  editBufferBlob() {
    return presetToBlob(this.editBuffer, this.symtab);
  }

  _handleLibrarian(cmd, payload) {
    const info = lib.LIBRARIAN_COMMANDS_BY_ID[cmd];
    const args = info ? lib.decodeLibrarianRequest(cmd, payload) : {};
    this.requests.push({ service: 'librarian', cmd, name: info?.name ?? `?${cmd}`, args });
    this.emit('request', { service: 'librarian', cmd, args });
    const out = (bytes) => this._write(this.librarianStream, bytes);
    const bad = () => out(lib.encodeLibStatusResponse(-1));
    switch (cmd) {
      case 1: return out(lib.encodeLibU32Response(this.opts.librarianVersion));
      case 2: return out(lib.encodeLibU32Response(this.tableBytes.length));
      case 3: return out(ed.encodeRawResponse(this.tableBytes));
      case 4: return out(lib.encodeLibStatusResponse(this._acceptsCrc(args.crc) ? 0 : -1));
      case 5: return out(lib.encodeLibU32Response(this.presets.length));
      case 6: {
        const p = this._presetAt(args.index);
        return p ? out(lib.encodeLibPresetNameResponse(0, p.name)) : bad();
      }
      case 7: {
        const p = this._presetAt(args.index);
        return p ? out(lib.encodeLibUuidResponse(0, p.uuid)) : bad();
      }
      case 8: {
        const p = this._presetAt(args.index);
        return p ? out(lib.encodeLibStatusU32Response(0, crc32(p.blob))) : bad();
      }
      case 9: {
        const { dst, src } = args;
        if (src >= this.presets.length || dst >= this.presets.length) return bad();
        const [p] = this.presets.splice(src, 1); // mock choice: move = remove + insert
        this.presets.splice(dst, 0, p);
        return out(lib.encodeLibStatusResponse(0));
      }
      case 10: {
        const p = this._presetAt(args.index);
        return p ? out(lib.encodeLibStatusU32Response(0, p.blob.length)) : bad();
      }
      case 11: {
        if (args.index >>> 0 === EDIT_BUFFER) return out(lib.encodeLibPresetFileResponse(0, this.editBufferBlob()));
        const p = this._presetAt(args.index);
        return p ? out(lib.encodeLibPresetFileResponse(0, p.blob)) : bad();
      }
      case 12: {
        let decoded;
        try {
          decoded = blobToPreset(args.blob, this.symtab);
        } catch {
          return bad();
        }
        if (args.index >>> 0 === EDIT_BUFFER) {
          this.editBuffer = decoded;
          this.dirty = false;
          return out(lib.encodeLibStatusResponse(0));
        }
        if (args.index >= this.presets.length) return bad();
        this.presets[args.index] = { ...this.presets[args.index], name: decoded.name ?? this.presets[args.index].name, blob: args.blob.slice() };
        return out(lib.encodeLibStatusResponse(0));
      }
      case 14: {
        const p = this._presetAt(args.index);
        return p ? out(lib.encodeLibPresetInfoResponse(0, { uuid: p.uuid, checksum: crc32(p.blob), size: p.blob.length, name: p.name })) : bad();
      }
      default:
        this.unknownCommands.push({ service: 'librarian', cmd });
        return out(lib.encodeLibStatusResponse(-4));
    }
  }

  // ------------------------------------------------------------------ tuner simulator

  /** Replace the values the tuner simulator cycles through. */
  setTunerInput(values) {
    this.opts.tunerValues = Array.isArray(values) ? values : [values];
    this.tuner.i = 0;
  }

  _updateTunerSim() {
    if (this.tuner.enabled && this.tuner.registered) {
      if (this.tuner.timer == null) {
        this.tuner.timer = this.clock.setInterval(() => {
          const vals = this.opts.tunerValues;
          const v = vals[this.tuner.i++ % vals.length];
          this._write(this.editorStream, ed.encodeDspEvent(this.symtab.lookup(TUNER.slot), this.symtab.lookup(TUNER.note), tvFloat(v)));
        }, this.opts.tunerIntervalMs);
      }
    } else this._stopTunerSim();
  }

  _stopTunerSim() {
    if (this.tuner.timer != null) this.clock.clearInterval(this.tuner.timer);
    this.tuner.timer = null;
  }

  // ------------------------------------------------------------------ amp-side "physical" actions

  /**
   * Simulate turning a knob / pressing a switch on the amp: updates the edit buffer and sends a
   * type-4 param event, e.g. turnKnob('amp', 'Drive', 0.7) or turnKnob('fx1', '@enabled', true).
   */
  turnKnob(group, paramId, value, { type } = {}) {
    const a = dspAddress(group, paramId);
    const tv = coerceValue(value, { type, paramId });
    const slotIdx = this.symtab.lookup(a.slot);
    const paramIdx = this.symtab.lookup(a.param);
    setPresetState(this.editBuffer, a.slot, a.param, tv, this.symtab);
    this.dirty = true;
    this._write(this.editorStream, ed.encodeParamEvent(slotIdx, paramIdx, tv));
  }

  /** Master volume knob on the amp: root-slot param event. */
  setMasterVolume(v) {
    this.deviceSettings.Master = v;
    this._write(this.editorStream, ed.encodeParamEvent(ROOT_SLOT_INDEX, this.symtab.lookup('Master'), tvFloat(v)));
  }

  /** Preset selected with the amp's buttons: load slot n, send a patch event (isSave 0). */
  selectPresetOnAmp(n) {
    this.currentPreset = n;
    this.editBuffer = blobToPreset(this.presets[n].blob, this.symtab);
    this.dirty = false;
    this._write(this.editorStream, ed.encodePatchEvent(n, false));
  }

  /** Save on the amp: store the edit buffer in slot n, patch event with isSave 1. */
  saveOnAmp(n) {
    this.presets[n] = { ...this.presets[n], blob: this.editBufferBlob() };
    this._write(this.editorStream, ed.encodePatchEvent(n, true));
  }

  /** Tap-tempo button: type-5 event. */
  tapTempo(bpm) {
    this.tempo = bpm;
    this._write(this.editorStream, ed.encodeTapTempoEvent(bpm));
  }

  /** Tuner switched on/off at the amp: (Tuner, Enable) param event. */
  setTunerOnAmp(on) {
    this.tuner.enabled = !!on;
    this._updateTunerSim();
    this._write(this.editorStream, ed.encodeParamEvent(this.symtab.lookup(TUNER.slot), this.symtab.lookup(TUNER.enable), tvInt(on ? 1 : 0)));
  }

  /** FBV pedal plugged / unplugged: type-6 event. */
  setFbvConnected(connected) {
    this._write(this.editorStream, ed.encodeFbvStatusEvent(connected));
  }

  /** Current editor-level value in the mock's edit buffer. */
  getParam(group, paramId) {
    const a = dspAddress(group, paramId);
    return findSlot(this.editBuffer, a.slot)?.states.find((s) => s.param === a.param)?.value;
  }

  /** Stop timers and detach from the transport. */
  destroy() {
    this._stopChannel();
    if (typeof this._unsub === 'function') this._unsub();
  }
}

export { TV };
