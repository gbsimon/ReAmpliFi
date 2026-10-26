// RSMC framing, parser resync / corruption, ARQ timing (retransmit 1000 ms, 200 ms keepalive),
// IAP sync timeline. Example frames E1-E4, E6 from native_transport.md §8.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeFrame, decodeHeader, FrameParser, LinkEndpoint, IapSync, IapDetector, IAP_OK, IAP_START, IAP_STOP, IAP_STATE } from '../src/link.js';
import { FakeClock } from '../src/clock.js';
import { hexToBytes, bytesToHex, concatBytes } from '../src/values.js';

const E5 = hexToBytes('0C000028 0320EF03 0000E400 00010021 00100000');

test('E1-E3: IAP ASCII strings', () => {
  assert.equal(bytesToHex(IAP_OK, ' '), '49 41 50 20 78 20 4f 4b');
  assert.equal(bytesToHex(IAP_START, ' '), '49 41 50 20 78 20 53 54 41 52 54');
  assert.equal(bytesToHex(IAP_STOP, ' '), '49 41 50 20 78 20 53 54 4f 50');
});

test('E4: header-only frame of a fresh channel (seq 0, ack 0, limit 8)', () => {
  assert.equal(bytesToHex(encodeFrame({ seq: 0, ack: 0, rxLimit: 8 }), ' '), '55 55 00 00 00 08 00 00 00 00 03 6b');
});

test('E6: device-info SYN inside RSMC data packet seq 1 (ack 0, limit 8)', () => {
  const f = encodeFrame({ seq: 1, ack: 0, rxLimit: 8, payload: E5 });
  assert.equal(bytesToHex(f.subarray(0, 12), ' '), '55 55 00 01 00 08 14 00 b1 bd ce a7');
  assert.equal(bytesToHex(f.subarray(12)), bytesToHex(E5));
  const h = decodeHeader(f);
  assert.deepEqual({ seq: h.seq, ack: h.ack, rxLimit: h.rxLimit, len: h.len }, { seq: 1, ack: 0, rxLimit: 8, len: 20 });
});

test('decodeHeader rejects a bad header CRC', () => {
  const f = encodeFrame({ seq: 3, ack: 2, rxLimit: 9 });
  f[4] ^= 1;
  assert.equal(decodeHeader(f), null);
});

function collect(maxPayload = 244) {
  const frames = [];
  const p = new FrameParser({ maxPayload, onFrame: (h, payload) => frames.push({ h, payload }) });
  return { p, frames };
}

test('parser: resyncs on 55 55 after garbage, handles byte-by-byte delivery', () => {
  const { p, frames } = collect();
  const f1 = encodeFrame({ seq: 0, ack: 0, rxLimit: 8 });
  const f2 = encodeFrame({ seq: 1, ack: 0, rxLimit: 8, payload: E5 });
  const stream = concatBytes(hexToBytes('00 55 13 37 49 41 50'), f1, hexToBytes('ff ee'), f2);
  for (const b of stream) p.push(Uint8Array.of(b));
  assert.equal(frames.length, 2);
  assert.equal(bytesToHex(frames[1].payload), bytesToHex(E5));
  assert.ok(p.stats.skippedBytes >= 9);
});

test('parser: 55 55 inside a payload does not break framing (no escaping)', () => {
  const { p, frames } = collect();
  const payload = hexToBytes('55 55 55 55 00 00 00 00');
  p.push(concatBytes(encodeFrame({ seq: 1, payload }), encodeFrame({ seq: 2, payload })));
  assert.equal(frames.length, 2);
  assert.equal(bytesToHex(frames[0].payload), bytesToHex(payload));
});

test('parser: bad header CRC drops those 12 bytes and the next frame is still parsed', () => {
  const { p, frames } = collect();
  const bad = encodeFrame({ seq: 5, payload: E5 });
  bad[3] ^= 0xff; // corrupt seq → header CRC mismatch
  const good = encodeFrame({ seq: 6, payload: E5 });
  p.push(concatBytes(bad, good));
  assert.equal(p.stats.headerErrors, 1);
  assert.equal(frames.length, 1);
  assert.equal(frames[0].h.seq, 6);
});

test('parser: bad payload CRC drops the frame', () => {
  const { p, frames } = collect();
  const f = encodeFrame({ seq: 1, payload: E5 });
  f[20] ^= 0x40;
  p.push(concatBytes(f, encodeFrame({ seq: 2, payload: E5 })));
  assert.equal(p.stats.payloadErrors, 1);
  assert.deepEqual(frames.map((x) => x.h.seq), [2]);
});

test('parser: len > MTU-12 is a length error', () => {
  const { p, frames } = collect(16);
  p.push(concatBytes(encodeFrame({ seq: 1, payload: E5 }), encodeFrame({ seq: 2, payload: new Uint8Array(8) })));
  assert.equal(p.stats.lengthErrors, 1);
  assert.deepEqual(frames.map((x) => x.h.seq), [2]);
});

/** Two LinkEndpoints wired together through a lossy pipe. */
function linkPair(clock, { dropAtoB = () => false } = {}) {
  const got = { a: [], b: [] };
  const wires = { ab: [], ba: [] };
  let a;
  let b;
  let n = 0;
  a = new LinkEndpoint({
    clock,
    write: (f) => {
      wires.ab.push(f);
      if (!dropAtoB(f, n++)) clock.setTimeout(() => b.receive(f), 1);
    },
    onPacket: (p) => got.a.push(p), // packets received by a
  });
  b = new LinkEndpoint({ clock, write: (f) => (wires.ba.push(f), clock.setTimeout(() => a.receive(f), 1)), onPacket: (p) => got.b.push(p) });
  return { a, b, got, wires };
}

test('link: idle endpoints emit a 12-byte header-only frame every 200 ms', async () => {
  const clock = new FakeClock();
  const { a, b, wires } = linkPair(clock);
  a.start();
  b.start();
  await clock.advance(1000);
  assert.equal(wires.ab.length, 5);
  assert.ok(wires.ab.every((f) => f.length === 12));
  assert.equal(bytesToHex(wires.ab[0]), bytesToHex(encodeFrame({ seq: 0, ack: 0, rxLimit: 8 })));
  a.stop();
  b.stop();
});

test('link: nothing is sent before the peer advertised rx_limit > 0', async () => {
  const clock = new FakeClock();
  const frames = [];
  const a = new LinkEndpoint({ clock, write: (f) => frames.push(decodeHeader(f)), onPacket: () => {} });
  a.start();
  a.queueMessage(new Uint8Array(8));
  await clock.advance(600);
  assert.ok(frames.every((h) => h.len === 0), 'only header-only frames while peerRxLimit = 0');
  a.stop();
});

test('link: data delivery, packing of several messages, cumulative ack', async () => {
  const clock = new FakeClock();
  const { a, b, got } = linkPair(clock);
  a.start();
  b.start();
  await clock.advance(400); // exchange credits
  a.queueMessage(new Uint8Array(8).fill(1));
  a.queueMessage(new Uint8Array(12).fill(2));
  await clock.advance(600); // data at the next tick, ack on the peer's following tick
  assert.equal(got.b.length, 1, 'both messages packed into one packet');
  assert.equal(got.b[0].length, 20);
  assert.equal(a.lastAcked, 1);
  assert.equal(a.inflight.size, 0);
  a.stop();
  b.stop();
});

test('link: a dropped data frame is retransmitted after 1000 ms (same seq), then delivered', async () => {
  const clock = new FakeClock();
  let dropped = 0;
  const { a, b, got, wires } = linkPair(clock, {
    dropAtoB: (f) => {
      if (decodeHeader(f).len > 0 && dropped === 0) {
        dropped++;
        return true;
      }
      return false;
    },
  });
  a.start();
  b.start();
  await clock.advance(400);
  a.queueMessage(new Uint8Array(8).fill(7));
  const sentAt = clock.now();
  await clock.advance(200); // data frame goes out (and is dropped)
  assert.equal(got.b.length, 0);
  await clock.advance(600);
  assert.equal(a.stats.retransmits, 0, 'no retransmit before 1000 ms');
  await clock.advance(600);
  assert.equal(a.stats.retransmits, 1);
  assert.equal(got.b.length, 1);
  const dataFrames = wires.ab.map((f) => decodeHeader(f)).filter((h) => h.len > 0);
  assert.equal(dataFrames.length, 2);
  assert.equal(dataFrames[0].seq, dataFrames[1].seq, 'retransmission keeps the seq');
  assert.ok(clock.now() - sentAt >= 1000);
  a.stop();
  b.stop();
});

test('link: send window of 8 unacked packets, then out-of-order buffering at the receiver', async () => {
  const clock = new FakeClock();
  const sent = [];
  const a = new LinkEndpoint({ clock, write: (f) => sent.push(decodeHeader(f)), onPacket: () => {}, maxDataFramesPerTick: 20 });
  a.start();
  // fake peer: grant lots of credit but never ack
  a.receive(encodeFrame({ seq: 0, ack: 0, rxLimit: 100 })); // credit far ahead (signed 8-bit compare)
  for (let i = 0; i < 12; i++) a.queueMessage(new Uint8Array(240 - 12));
  a.tick();
  assert.equal(sent.filter((h) => h.len > 0).length, 8, 'TX window = 8');
  a.stop();

  const delivered = [];
  const b = new LinkEndpoint({ clock, write: () => {}, onPacket: (p) => delivered.push(p[0]) });
  b.start();
  const pkt = (seq) => encodeFrame({ seq, ack: 0, rxLimit: 8, payload: Uint8Array.of(seq, 0, 0, 0) });
  b.receive(pkt(2));
  b.receive(pkt(3));
  assert.deepEqual(delivered, []);
  b.receive(pkt(1));
  assert.deepEqual(delivered, [1, 2, 3]);
  b.receive(pkt(2)); // duplicate
  b.receive(pkt(20)); // out of window
  assert.deepEqual(delivered, [1, 2, 3]);
  assert.equal(b.stats.duplicates, 1);
  assert.equal(b.stats.outOfWindow, 1);
  assert.equal(b.rxLimit, 11, 'credit grows by one per completed packet');
  b.stop();
});

test('link: message larger than MTU-12 is rejected with -36', () => {
  const a = new LinkEndpoint({ clock: new FakeClock(), write: () => {}, onPacket: () => {}, autoTick: false });
  a.start();
  assert.throws(() => a.queueMessage(new Uint8Array(232)), (e) => e.code === -36);
  assert.throws(() => a.queueMessage(new Uint8Array(6)), /aligned/);
});

test('IAP sync timeline: OK at 0.2 s, START at 1.2 s, RUNNING at 2.2 s', async () => {
  const clock = new FakeClock();
  const writes = [];
  const sync = new IapSync((b) => writes.push({ t: clock.now(), s: String.fromCharCode(...b) }));
  let runningAt = null;
  const id = clock.setInterval(() => {
    sync.tick();
    if (sync.running && runningAt === null) runningAt = clock.now();
  }, 200);
  await clock.advance(3000);
  clock.clearInterval(id);
  assert.deepEqual(writes, [
    { t: 200, s: 'IAP x OK' },
    { t: 1200, s: 'IAP x START' },
  ]);
  assert.equal(runningAt, 2200);
  sync.stop();
  assert.equal(sync.state, IAP_STATE.STOPPING);
  assert.equal(writes.at(-1).s, 'IAP x STOP');
});

test('IapDetector finds commands split across chunks', () => {
  const seen = [];
  const d = new IapDetector((c) => seen.push(c));
  d.push(hexToBytes('55 55 00'));
  d.push(IAP_START.subarray(0, 5));
  d.push(IAP_START.subarray(5));
  d.push(IAP_STOP);
  assert.deepEqual(seen, ['START', 'STOP']);
});
