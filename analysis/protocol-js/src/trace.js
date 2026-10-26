// Byte-log decoder for UIs and debugging: turns the raw tx / rx byte chunks reported by
// AmpSession's 'trace' event into layer-decoded lines (IAP strings, RSMC frames, McBsp
// messages, stream segments). Read-only: it never builds or sends bytes.
//
//   const dec = new TraceDecoder();
//   session.on('trace', ({ dir, bytes }) => dec.push(dir, bytes).forEach(show));
//
// tx writes are whole frames; rx chunks are arbitrary (Web Serial splits and joins reads), so
// each direction keeps its own FrameParser.

import { FrameParser, HEADER_LEN, IAP_OK, IAP_START, IAP_STOP } from './link.js';
import { splitPayload, ADDR } from './router.js';
import { STREAM_FLAG, STREAM_HEADER_LEN } from './stream.js';
import { bytesEqual, readU32 } from './values.js';

const IAP_STRINGS = [
  ['IAP x OK', IAP_OK],
  ['IAP x START', IAP_START],
  ['IAP x STOP', IAP_STOP],
];

const ADDR_NAMES = Object.freeze({
  [ADDR.EDITOR_LOCAL]: 'phone.editor',
  [ADDR.EDITOR_REMOTE]: 'amp.editor',
  [ADDR.LIBRARIAN_LOCAL]: 'phone.librarian',
  [ADDR.LIBRARIAN_REMOTE]: 'amp.librarian',
});

const addrName = (a) => ADDR_NAMES[a] ?? `0x${a.toString(16).padStart(4, '0')}`;

/** Stream flag byte → "SYN|DATA" etc. */
export function streamFlagNames(flags) {
  const out = [];
  for (const [k, v] of Object.entries(STREAM_FLAG)) if (flags & v) out.push(k);
  return out.length ? out.join('|') : '0';
}

/**
 * Describe the McBsp messages inside one RSMC payload. Never throws: an undecodable payload is
 * reported as such.
 * @param {Uint8Array} payload
 * @returns {string[]}
 */
export function describeRsmcPayload(payload) {
  let msgs;
  try {
    msgs = splitPayload(payload);
  } catch (e) {
    return [`(undecodable McBsp payload: ${e.message})`];
  }
  return msgs.map((m) => {
    let s = `${addrName(m.src)}→${addrName(m.dst)}`;
    if (m.body.length >= STREAM_HEADER_LEN) {
      const a = readU32(m.body, 0);
      const flags = a >>> 24;
      const seq = (a >>> 8) & 0xff;
      const data = m.body.length - STREAM_HEADER_LEN;
      s += ` ${streamFlagNames(flags)} seq=${seq}`;
      if (m.option !== null) s += ` mss=${m.option >>> 16}`;
      if (data) s += ` data=${data}B`;
    } else {
      s += ` body=${m.body.length}B`;
    }
    return s;
  });
}

/**
 * Stateful per-direction decoder.
 * push(dir, bytes) returns zero or more entries (the caller keeps the raw chunk for a hex view):
 *   { dir, kind: 'iap', text }
 *   { dir, kind: 'rsmc', seq, ack, rxLimit, len, keepalive, text }
 *   { dir, kind: 'raw', text }   (bytes that are not part of a valid frame)
 */
export class TraceDecoder {
  constructor({ maxPayload = 1024 } = {}) {
    this._parsers = {};
    this._pending = [];
    this.maxPayload = maxPayload;
  }

  _parser(dir) {
    if (!this._parsers[dir]) {
      this._parsers[dir] = new FrameParser({
        maxPayload: this.maxPayload,
        onFrame: (hdr, payload) => this._pending.push(this._frameEntry(dir, hdr, payload)),
      });
    }
    return this._parsers[dir];
  }

  _frameEntry(dir, hdr, payload) {
    const keepalive = hdr.len === 0;
    const head = `RSMC seq=${hdr.seq} ack=${hdr.ack} credit=${hdr.rxLimit} len=${hdr.len}`;
    const text = keepalive ? `${head} (keepalive)` : `${head} | ${describeRsmcPayload(payload).join(' ; ')}`;
    return { dir, kind: 'rsmc', seq: hdr.seq, ack: hdr.ack, rxLimit: hdr.rxLimit, len: hdr.len, keepalive, text };
  }

  /**
   * @param {'tx'|'rx'} dir
   * @param {Uint8Array} bytes
   * @returns {object[]}
   */
  push(dir, bytes) {
    for (const [text, pat] of IAP_STRINGS) {
      if (bytesEqual(bytes, pat)) return [{ dir, kind: 'iap', text }];
    }
    const p = this._parser(dir);
    const before = p.stats.skippedBytes + p.stats.headerErrors * HEADER_LEN;
    this._pending = [];
    p.push(bytes);
    const out = this._pending;
    this._pending = [];
    const skipped = p.stats.skippedBytes + p.stats.headerErrors * HEADER_LEN - before;
    if (skipped > 0) out.push({ dir, kind: 'raw', text: `${skipped} byte(s) outside RSMC frames` });
    return out;
  }
}
