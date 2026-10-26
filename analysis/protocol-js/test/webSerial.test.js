// WebSerialTransport against a fake navigator.serial / SerialPort (Node's WHATWG streams).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  WebSerialTransport,
  webSerialSupport,
  requestSppPort,
  getRememberedSppPorts,
  isSppPort,
  isSppServiceClassId,
  sppRequestOptions,
  SPP_SERVICE_CLASS_ID,
  UNSUPPORTED_BROWSER_MESSAGE,
  INSECURE_CONTEXT_MESSAGE,
} from '../src/transports/webSerial.js';
import { AmpSession } from '../src/session.js';
import { FakeClock } from '../src/clock.js';
import { MockAmp } from '../mock/MockAmp.js';

const tick = (n = 20) => new Promise((r) => setTimeout(r, n));

/** Minimal SerialPort stand-in: readable is fed with push(), writes are recorded. */
class FakePort extends EventTarget {
  constructor(info = { bluetoothServiceClassId: SPP_SERVICE_CLASS_ID }) {
    super();
    this.info = info;
    this.openedWith = null;
    this.written = [];
    this.readable = null;
    this.writable = null;
    this.closeCalls = 0;
    this.onWrite = null;
  }
  getInfo() {
    return this.info;
  }
  _newReadable() {
    this.readable = new ReadableStream({
      start: (c) => {
        this.ctrl = c;
      },
    });
  }
  async open(opts) {
    this.openedWith = opts;
    this._newReadable();
    this.writable = new WritableStream({
      write: (chunk) => {
        this.written.push(chunk);
        this.onWrite?.(chunk);
      },
    });
  }
  push(bytes) {
    this.ctrl.enqueue(bytes);
  }
  /** Fatal error (link lost): the readable goes away. */
  failFatal(err = new Error('NetworkError: link lost')) {
    this.ctrl.error(err);
    this.readable = null;
  }
  /** Non-fatal error (framing/overrun): a fresh readable replaces the old one. */
  failSoft(err = new Error('FramingError')) {
    const old = this.ctrl;
    this._newReadable();
    old.error(err);
  }
  async close() {
    this.closeCalls++;
    this.readable = null;
    this.writable = null;
  }
}

class FakeSerial extends EventTarget {
  constructor(ports = []) {
    super();
    this.ports = ports;
    this.requested = [];
  }
  async requestPort(opts) {
    this.requested.push(opts);
    return this.ports[0];
  }
  async getPorts() {
    return this.ports;
  }
}

test('webSerialSupport: clear messages for missing API and insecure context', () => {
  assert.deepEqual(webSerialSupport({ navigator: undefined }).reason, 'no-navigator');
  const none = webSerialSupport({ navigator: {}, isSecureContext: true });
  assert.equal(none.supported, false);
  assert.equal(none.reason, 'no-web-serial');
  assert.equal(none.message, UNSUPPORTED_BROWSER_MESSAGE);
  assert.match(none.message, /Chrome or Edge on desktop/);
  assert.match(none.message, /Chrome 138\+ on Android/);
  const insecure = webSerialSupport({ navigator: { serial: new FakeSerial() }, isSecureContext: false });
  assert.equal(insecure.reason, 'insecure-context');
  assert.equal(insecure.message, INSECURE_CONTEXT_MESSAGE);
  assert.deepEqual(webSerialSupport({ navigator: { serial: new FakeSerial() }, isSecureContext: true }), { supported: true, reason: null, message: null });
});

test('requestSppPort asks for SPP only; getRememberedSppPorts filters non-SPP ports', async () => {
  const spp = new FakePort();
  const usb = new FakePort({ usbVendorId: 0x1234 });
  const other = new FakePort({ bluetoothServiceClassId: '0000110a-0000-1000-8000-00805f9b34fb' });
  const serial = new FakeSerial([spp, usb, other]);
  assert.equal(await requestSppPort({ serial }), spp);
  assert.deepEqual(serial.requested[0], sppRequestOptions());
  assert.deepEqual(serial.requested[0], {
    filters: [{ bluetoothServiceClassId: '00001101-0000-1000-8000-00805f9b34fb' }],
    allowedBluetoothServiceClassIds: ['00001101-0000-1000-8000-00805f9b34fb'],
  });
  assert.deepEqual(await getRememberedSppPorts({ serial }), [spp]);
  assert.ok(isSppPort(spp) && !isSppPort(usb) && !isSppPort(other));
  assert.ok(isSppServiceClassId(0x1101) && isSppServiceClassId(SPP_SERVICE_CLASS_ID.toUpperCase()));
});

test('open at 115200, data in order to every listener, writes serialised, unsubscribe works', async () => {
  const port = new FakePort();
  const t = new WebSerialTransport(port, { serial: new FakeSerial([port]) });
  await t.open();
  assert.deepEqual(port.openedWith, { baudRate: 115200 });
  const a = [];
  const b = [];
  t.onData((x) => a.push([...x]));
  const offB = t.onData((x) => b.push([...x]));
  port.push(new Uint8Array([1, 2]));
  port.push(new Uint8Array([3]));
  await tick();
  offB();
  port.push(new Uint8Array([4]));
  await tick();
  assert.deepEqual(a, [[1, 2], [3], [4]]);
  assert.deepEqual(b, [[1, 2], [3]]);
  const src = new Uint8Array([9, 9]);
  t.write(src);
  src[0] = 0; // the transport copied the bytes
  t.write(new Uint8Array([8]));
  await tick();
  assert.deepEqual(port.written.map((x) => [...x]), [[9, 9], [8]]);
  assert.equal(t.stats.rxBytes, 4);
  assert.equal(t.stats.txBytes, 3);
  await t.close();
});

test('fatal read error → onClose(read-error) once, port closed', async () => {
  const port = new FakePort();
  const t = new WebSerialTransport(port, { serial: new FakeSerial([port]), onWarning: () => {} });
  const closes = [];
  t.onClose((e) => closes.push(e));
  await t.open();
  port.failFatal();
  await tick();
  assert.equal(closes.length, 1);
  assert.equal(closes[0].reason, 'read-error');
  assert.match(String(closes[0].error), /link lost/);
  assert.equal(port.closeCalls, 1);
  t.write(new Uint8Array([1])); // ignored after close
  await t.close(); // idempotent
  assert.equal(closes.length, 1);
});

test('non-fatal read error: the loop takes a new reader and keeps going', async () => {
  const port = new FakePort();
  const warnings = [];
  const t = new WebSerialTransport(port, { serial: new FakeSerial([port]), onWarning: (e) => warnings.push(e) });
  const got = [];
  const closes = [];
  t.onData((x) => got.push(...x));
  t.onClose((e) => closes.push(e));
  await t.open();
  port.push(new Uint8Array([1]));
  await tick();
  port.failSoft();
  await tick();
  port.push(new Uint8Array([2]));
  await tick();
  assert.deepEqual(got, [1, 2]);
  assert.equal(closes.length, 0);
  assert.equal(warnings.length, 1);
  await t.close();
  assert.deepEqual(closes, [{ reason: 'closed' }]);
});

test("'disconnect' event for this port → onClose(disconnected); other ports are ignored", async () => {
  const port = new FakePort();
  const otherPort = new FakePort();
  const serial = new FakeSerial([port, otherPort]);
  const t = new WebSerialTransport(port, { serial });
  const closes = [];
  t.onClose((e) => closes.push(e));
  await t.open();
  const other = new Event('disconnect');
  Object.defineProperty(other, 'port', { value: otherPort });
  serial.dispatchEvent(other);
  await tick();
  assert.equal(closes.length, 0);
  port.dispatchEvent(new Event('disconnect')); // target === port (Chrome fires it at the port)
  await tick();
  assert.deepEqual(closes, [{ reason: 'disconnected' }]);
  assert.equal(port.closeCalls, 1);
});

test('close(): onClose(closed), reader cancelled, locks released, port.close() called', async () => {
  const port = new FakePort();
  const t = new WebSerialTransport(port, { serial: new FakeSerial([port]) });
  const closes = [];
  t.onClose((e) => closes.push(e));
  await t.open();
  t.write(new Uint8Array([5]));
  await t.close();
  assert.deepEqual(closes, [{ reason: 'closed' }]);
  assert.equal(port.closeCalls, 1);
  assert.deepEqual(port.written.map((x) => [...x]), [[5]], 'queued write flushed before close');
  await assert.rejects(t.open(), /already closed/);
});

test('AmpSession connects to MockAmp through WebSerialTransport (fake port bridged to the mock)', async () => {
  // FakeClock drives the protocol timers; the transport's reader loop and write chain run on
  // real WHATWG streams (microtasks), so this exercises them end to end.
  const clock = new FakeClock();
  const port = new FakePort();
  const t = new WebSerialTransport(port, { serial: new FakeSerial([port]) });
  await t.open();
  const ampListeners = new Set();
  const ampSide = {
    write: (b) => clock.setTimeout(() => port.push(b.slice()), 2),
    onData: (cb) => (ampListeners.add(cb), () => ampListeners.delete(cb)),
    close() {},
  };
  port.onWrite = (chunk) => clock.setTimeout(() => ampListeners.forEach((cb) => cb(chunk)), 2);
  const m = new MockAmp(ampSide, { clock });
  const s = new AmpSession(t, { clock, readOnly: true });
  const phases = [];
  s.on('phase', (p) => phases.push(p.phase));
  const sum = await clock.runUntil(s.connect());
  assert.equal(sum.deviceInfo.productName, 'AMPLIFi 150');
  assert.equal(sum.symbolTableSource, 'downloaded');
  assert.equal(s.editBuffer.name, 'Mock Tone 1');
  assert.ok(phases.includes('tableDownload') && phases.at(-1) === 'ready');
  await clock.runUntil(s.disconnect());
  await t.close();
  assert.equal(t.closed, true);
  assert.equal(port.closeCalls, 1);
  m.destroy();
});
