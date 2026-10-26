// McBsp router + MsgPort stream: E5, E7, E11, packing, option rewrite, seq abort rule,
// heartbeat / timeout, flow-control window, FIN handshake.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { encodeTransportHeader, decodeTransportHeader, encodeMessage, splitPayload, packMessages, rewriteInboundOption, Router, ADDR, messageSize } from '../src/router.js';
import { encodeStreamMessage, decodeStreamSegment, StreamEndpoint, STREAM_FLAG, STREAM_STATE } from '../src/stream.js';
import { FakeClock } from '../src/clock.js';
import { hexToBytes, bytesToHex, concatBytes, u32words } from '../src/values.js';
import { encodeGetVersion } from '../src/editor.js';

const E5 = '0c000028 0320ef03 0000e400 00010021 00100000';
const E7 = '0c000028 0220ed03 0000e400 00010021 00100000';
const clean = (s) => s.replace(/ /g, '');

test('E5: device-info stream SYN 0x2003→0x03EF, MSS 228, flags SYN|HB-enable, seq 1, window 4096', () => {
  const m = encodeStreamMessage({ src: ADDR.LIBRARIAN_LOCAL, dst: ADDR.LIBRARIAN_REMOTE, flags: STREAM_FLAG.SYN | STREAM_FLAG.HB_ENABLE, seq: 1, window: 4096, mss: 228 });
  assert.equal(bytesToHex(m), clean(E5));
});

test('E7: editor SYN (MTU 240; with MTU 256 bytes 10-11 become f4 00)', () => {
  const m = encodeStreamMessage({ src: ADDR.EDITOR_LOCAL, dst: ADDR.EDITOR_REMOTE, flags: 0x21, seq: 1, window: 4096, mss: 228 });
  assert.equal(bytesToHex(m), clean(E7));
  const m256 = encodeStreamMessage({ src: ADDR.EDITOR_LOCAL, dst: ADDR.EDITOR_REMOTE, flags: 0x21, seq: 1, window: 4096, mss: 244 });
  assert.equal(bytesToHex(m256.subarray(10, 12)), 'f400');
});

test('E11: data segment carrying E9 (editor GetVersion), seq 2', () => {
  const m = encodeStreamMessage({ src: 0x2002, dst: 0x03ed, flags: STREAM_FLAG.DATA, seq: 2, window: 0x1000, data: encodeGetVersion() });
  assert.equal(bytesToHex(m.subarray(0, 12)), '100000180220ed0300020004');
  assert.equal(bytesToHex(m.subarray(16)), '0100000000000000');
});

test('transport header layout: len_lo len_hi 00 T, src, dst', () => {
  const h = encodeTransportHeader({ type: 1, length: 0x10, src: 0x2002, dst: 0x03ed });
  assert.equal(bytesToHex(h), '100000180220ed03');
  assert.deepEqual(decodeTransportHeader(h), { type: 1, version: 2, length: 16, src: 0x2002, dst: 0x03ed });
});

test('4-byte padding, several messages per payload, split/pack round trip', () => {
  const a = encodeMessage({ src: 1, dst: 2, body: hexToBytes('aabbcc') });
  assert.equal(a.length, messageSize(3));
  assert.equal(a.length, 12);
  const b = encodeMessage({ src: 3, dst: 4, body: hexToBytes('01020304 05060708'), option: 0x00e40000 });
  const payloads = packMessages([a, b, a], 32); // a=12, b=20 → [a,b] [a]
  assert.equal(payloads.length, 2);
  const msgs = splitPayload(concatBytes(...payloads));
  assert.equal(msgs.length, 3);
  assert.equal(bytesToHex(msgs[0].body), 'aabbcc');
  assert.equal(msgs[1].option, 0x00e40000);
  assert.equal(bytesToHex(msgs[1].body), '0102030405060708');
});

test('router inbound option rewrite: clamp MSS, hop+1, clear bits 8-15', () => {
  assert.equal(rewriteInboundOption((244 << 16) | 0xff00, 228) >>> 0, ((228 << 16) | 1) >>> 0);
  assert.equal(rewriteInboundOption(200 << 16, 228), ((200 << 16) | 1) >>> 0);
});

/** Two routers connected directly (no RSMC), both ticking on a FakeClock. */
function pair(clock, { phoneTimeout = 4000, phoneHb, latency = 1 } = {}) {
  let rp;
  let ra;
  rp = new Router({ send: (m) => clock.setTimeout(() => ra.handlePacket(m), latency), mss: 228 });
  ra = new Router({ send: (m) => clock.setTimeout(() => rp.handlePacket(m), latency), mss: 244 });
  const phone = new StreamEndpoint({ local: 0x2002, remote: 0x03ed, router: rp, mss: 228, clock, timeoutMs: phoneTimeout, heartbeatIntervalMs: phoneHb, name: 'phone' });
  const amp = new StreamEndpoint({ local: 0x03ed, remote: 0x2002, router: ra, mss: 244, clock, requestHeartbeat: false, name: 'amp' });
  return { phone, amp, rp, ra };
}

test('stream: 2-way SYN handshake; listener takes 4000/1000 from flag 0x20; MSS clamped by router', async () => {
  const clock = new FakeClock();
  const { phone, amp } = pair(clock);
  amp.listen();
  await clock.runUntil(phone.connect());
  assert.equal(phone.state, STREAM_STATE.ESTABLISHED);
  assert.equal(amp.state, STREAM_STATE.ESTABLISHED);
  assert.equal(amp.timeoutMs, 4000);
  assert.equal(amp.heartbeatIntervalMs, 1000);
  assert.equal(phone.peerMss, 228, 'amp advertised 244, phone router clamps to its own 228');
  phone.destroy();
  amp.destroy();
});

test('stream: data both ways, split into ≤ peerMSS−16 segments, read() exact bytes', async () => {
  const clock = new FakeClock();
  const { phone, amp } = pair(clock);
  amp.listen();
  await clock.runUntil(phone.connect());
  const big = Uint8Array.from({ length: 1000 }, (_, i) => i & 0xff);
  phone.write(big);
  const got = await clock.runUntil(amp.read(1000));
  assert.equal(bytesToHex(got), bytesToHex(big));
  assert.ok(phone.stats.segmentsSent >= 1 + Math.ceil(1000 / (228 - 16)));
  amp.write(hexToBytes('deadbeef'));
  assert.equal(bytesToHex(await clock.runUntil(phone.read(4))), 'deadbeef');
  phone.destroy();
  amp.destroy();
});

test('stream: sender respects the peer window edge (4096 + consumed)', async () => {
  const clock = new FakeClock();
  const { phone, amp } = pair(clock);
  amp.listen();
  await clock.runUntil(phone.connect());
  phone.write(new Uint8Array(6000));
  await clock.advance(1000);
  assert.equal(phone.bytesSent, 4096, 'amp has not consumed anything yet');
  await clock.runUntil(amp.read(4096)); // consuming opens the window
  await clock.runUntil(amp.read(6000 - 4096));
  assert.equal(phone.bytesSent, 6000);
  phone.destroy();
  amp.destroy();
});

test('stream: seq abort rule — a non-SYN segment with seq ≠ last+1 aborts with −4', async () => {
  const clock = new FakeClock();
  const { phone, amp, rp } = pair(clock);
  amp.listen();
  await clock.runUntil(phone.connect());
  const errors = [];
  phone.on('error', (e) => errors.push(e));
  const bogus = encodeStreamMessage({ src: 0x03ed, dst: 0x2002, flags: STREAM_FLAG.DATA, seq: (phone.rxSeq + 2) & 0xff, window: 4096, data: u32words(1) });
  rp.handlePacket(bogus);
  assert.equal(errors.length, 1);
  assert.equal(errors[0].code, -4);
  assert.equal(phone.state, -4);
  amp.destroy();
});

test('stream: heartbeats every T>>2 of TX silence keep the peer alive', async () => {
  const clock = new FakeClock();
  const { phone, amp } = pair(clock, { phoneTimeout: 4000 });
  amp.listen();
  await clock.runUntil(phone.connect());
  await clock.advance(10_000);
  assert.equal(phone.state, STREAM_STATE.ESTABLISHED);
  assert.equal(amp.state, STREAM_STATE.ESTABLISHED);
  assert.ok(phone.stats.heartbeatsSent >= 9, `phone heartbeats ${phone.stats.heartbeatsSent}`);
  phone.destroy();
  amp.destroy();
});

test('stream: native T=16000 gives a 4 s heartbeat = the listener 4 s timeout; one tick of jitter kills it (§5.4 caveat)', async () => {
  assert.equal(16000 >> 2, 4000);
  const clock = new FakeClock();
  const { phone, amp } = pair(clock, { phoneTimeout: 16000, phoneHb: 4200 });
  amp.listen();
  const errs = [];
  amp.on('error', (e) => errs.push(e));
  await clock.runUntil(phone.connect());
  await clock.advance(6000);
  assert.equal(errs[0]?.code, -28, 'amp side timed out');
  phone.destroy();
});

test('stream: RX silence → −28', async () => {
  const clock = new FakeClock();
  const { phone, amp } = pair(clock);
  amp.listen();
  await clock.runUntil(phone.connect());
  amp.destroy(); // amp goes silent
  const errs = [];
  phone.on('error', (e) => errs.push(e));
  await clock.advance(5000);
  assert.equal(errs[0]?.code, -28);
});

test('stream: FIN close handshake', async () => {
  const clock = new FakeClock();
  const { phone, amp } = pair(clock);
  amp.listen();
  amp.on('peerClose', () => amp.close());
  await clock.runUntil(phone.connect());
  const ok = await clock.runUntil(phone.close());
  assert.equal(ok, true);
  assert.equal(phone.state, STREAM_STATE.IDLE);
  assert.equal(clock.pendingTimers, 0, 'no timers left behind');
});

test('decodeStreamSegment of a SYN reports mss and hop', () => {
  const m = splitPayload(hexToBytes(E5))[0];
  const seg = decodeStreamSegment(m);
  assert.deepEqual({ flags: seg.flags, seq: seg.seq, window: seg.window, mss: seg.mss, hop: seg.hop }, { flags: 0x21, seq: 1, window: 4096, mss: 228, hop: 0 });
});
