// TraceDecoder: layer-decoded byte log lines for the app's hex log.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TraceDecoder, describeRsmcPayload, streamFlagNames } from '../src/trace.js';
import { encodeFrame, IAP_OK, IAP_START } from '../src/link.js';
import { encodeStreamMessage, STREAM_FLAG } from '../src/stream.js';
import { ADDR } from '../src/router.js';
import { concatBytes } from '../src/values.js';
import { AmpSession } from '../src/session.js';
import { FakeClock } from '../src/clock.js';
import { MockAmp } from '../mock/MockAmp.js';
import { createMemoryTransportPair } from '../mock/memoryTransport.js';

test('IAP strings, keepalives and data frames are named', () => {
  const d = new TraceDecoder();
  assert.deepEqual(d.push('tx', IAP_OK), [{ dir: 'tx', kind: 'iap', text: 'IAP x OK' }]);
  assert.equal(d.push('tx', IAP_START)[0].text, 'IAP x START');
  const ka = d.push('tx', encodeFrame({ seq: 3, ack: 2, rxLimit: 10 }));
  assert.equal(ka.length, 1);
  assert.equal(ka[0].keepalive, true);
  assert.match(ka[0].text, /RSMC seq=3 ack=2 credit=10 len=0 \(keepalive\)/);
  const syn = encodeStreamMessage({ src: ADDR.EDITOR_LOCAL, dst: ADDR.EDITOR_REMOTE, flags: STREAM_FLAG.SYN | STREAM_FLAG.HB_ENABLE, seq: 1, window: 4096, mss: 228 });
  const data = encodeStreamMessage({ src: ADDR.EDITOR_LOCAL, dst: ADDR.EDITOR_REMOTE, flags: STREAM_FLAG.DATA, seq: 2, window: 4096, data: new Uint8Array(12) });
  const f = d.push('tx', encodeFrame({ seq: 4, ack: 2, rxLimit: 10, payload: concatBytes(syn, data) }));
  assert.equal(f[0].kind, 'rsmc');
  assert.equal(f[0].keepalive, false);
  assert.match(f[0].text, /phone\.editor→amp\.editor SYN\|HB_ENABLE seq=1 mss=228 ; phone\.editor→amp\.editor DATA seq=2 data=12B/);
});

test('rx chunks split anywhere are reassembled; junk bytes are reported', () => {
  const d = new TraceDecoder();
  const frame = encodeFrame({ seq: 1, ack: 0, rxLimit: 8 });
  assert.deepEqual(d.push('rx', frame.slice(0, 5)), []);
  const out = d.push('rx', concatBytes(frame.slice(5), frame));
  assert.equal(out.length, 2);
  assert.ok(out.every((e) => e.dir === 'rx' && e.kind === 'rsmc'));
  const junk = d.push('rx', new Uint8Array([1, 2, 3]));
  assert.deepEqual(junk, [{ dir: 'rx', kind: 'raw', text: '3 byte(s) outside RSMC frames' }]);
});

test('helpers never throw on bad input', () => {
  assert.match(describeRsmcPayload(new Uint8Array([0xff, 0xff, 0, 0x18, 0, 0, 0, 0]))[0], /undecodable/);
  assert.equal(streamFlagNames(0), '0');
  assert.equal(streamFlagNames(STREAM_FLAG.FIN | STREAM_FLAG.WND), 'FIN|WND');
});

test('decodes a whole mock session without raw leftovers', async () => {
  const clock = new FakeClock();
  const { phone, amp } = createMemoryTransportPair({ clock, latencyMs: 5, chunkSize: 7 });
  const m = new MockAmp(amp, { clock });
  const s = new AmpSession(phone, { clock });
  const d = new TraceDecoder();
  const lines = [];
  s.on('trace', ({ dir, bytes }) => lines.push(...d.push(dir, bytes)));
  await clock.runUntil(s.connect());
  await clock.runUntil(s.disconnect());
  m.destroy();
  assert.ok(lines.filter((l) => l.kind === 'iap').length >= 5);
  assert.ok(lines.some((l) => l.dir === 'rx' && l.kind === 'rsmc' && !l.keepalive));
  assert.equal(lines.filter((l) => l.kind === 'raw').length, 0);
});
