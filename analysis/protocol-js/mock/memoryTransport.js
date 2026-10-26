// Paired in-memory transport for tests and offline UI work.
//
//   const { phone, amp, stats } = createMemoryTransportPair({ clock, latencyMs: 5 });
//   new AmpSession(phone, …); new MockAmp(amp, …);
//
// Each side implements the transport interface { write, onData, close, onClose }.
// Fault injection: `dropFilter(bytes, direction, index)` returns true to drop a write
// (one write = one RSMC frame or one IAP string), `dropRate` with a seeded PRNG, `chunkSize`
// to split deliveries into small pieces, `corrupt(bytes, direction, index)` to mutate bytes.

import { realClock } from '../src/clock.js';

/** Small deterministic PRNG (mulberry32). */
export function seededRandom(seed = 1) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/**
 * @param {object} [o]
 * @param {object} [o.clock=realClock]
 * @param {number} [o.latencyMs=0]
 * @param {(bytes:Uint8Array, dir:'phone→amp'|'amp→phone', index:number)=>boolean} [o.dropFilter]
 * @param {number} [o.dropRate=0]   probability of dropping a write (seeded)
 * @param {number} [o.seed=1]
 * @param {number} [o.chunkSize]    deliver in pieces of at most this many bytes
 * @param {(bytes:Uint8Array, dir:string, index:number)=>Uint8Array} [o.corrupt]
 */
export function createMemoryTransportPair({ clock = realClock, latencyMs = 0, dropFilter, dropRate = 0, seed = 1, chunkSize, corrupt } = {}) {
  const rand = seededRandom(seed);
  const stats = { 'phone→amp': { writes: 0, bytes: 0, dropped: 0 }, 'amp→phone': { writes: 0, bytes: 0, dropped: 0 } };
  const log = [];

  function makeSide(dir) {
    const side = {
      _listeners: new Set(),
      _closeListeners: new Set(),
      closed: false,
      peer: null,
      write(bytes) {
        if (side.closed) return;
        const s = stats[dir];
        const index = s.writes++;
        s.bytes += bytes.length;
        let data = bytes.slice();
        if ((dropFilter && dropFilter(data, dir, index)) || (dropRate > 0 && rand() < dropRate)) {
          s.dropped++;
          log.push({ dir, index, dropped: true, bytes: data });
          return;
        }
        if (corrupt) data = corrupt(data, dir, index) ?? data;
        log.push({ dir, index, dropped: false, bytes: data });
        const pieces = [];
        if (chunkSize) for (let o = 0; o < data.length; o += chunkSize) pieces.push(data.slice(o, o + chunkSize));
        else pieces.push(data);
        clock.setTimeout(() => {
          if (side.peer.closed) return;
          for (const p of pieces) for (const cb of [...side.peer._listeners]) cb(p);
        }, latencyMs);
      },
      onData(cb) {
        side._listeners.add(cb);
        return () => side._listeners.delete(cb);
      },
      onClose(cb) {
        side._closeListeners.add(cb);
        return () => side._closeListeners.delete(cb);
      },
      close() {
        if (side.closed) return;
        side.closed = true;
        for (const s of [side, side.peer]) {
          s.closed = true;
          for (const cb of [...s._closeListeners]) cb();
        }
      },
    };
    return side;
  }

  const phone = makeSide('phone→amp');
  const amp = makeSide('amp→phone');
  phone.peer = amp;
  amp.peer = phone;
  return { phone, amp, stats, log };
}
