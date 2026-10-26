// McBsp message layer: 8-byte transport header, 4-byte padding, several messages per RSMC
// payload, and routing by destination address.
//
// Spec: native_transport.md §4. Source: MsgTransportHeader_Pack 0x1122b0 / _Unpack 0x112280,
// MsgPort_PrepareTransportHeader 0x1101e0, router task 0x110300, MsgRouter_AddRoutingEntry 0x110720.

import { concatBytes, readU32, u32words } from './values.js';
import { AmpProtocolError } from './errors.js';

/** Addresses = node << 8 | port. CONFIRMED (§4.2). */
export const ADDR = Object.freeze({
  PHONE_NODE: 0x20, // McBspMessaging_Init(0x2000)
  AMP_NODE: 0x03,
  EDITOR_LOCAL: 0x2002, // phone side of the editor service stream
  EDITOR_REMOTE: 0x03ed, // amp side
  LIBRARIAN_LOCAL: 0x2003, // phone side of the librarian / device-info stream
  LIBRARIAN_REMOTE: 0x03ef,
});

/** Transport message types (word0 bits 28-31). CONFIRMED. */
export const MSG_TYPE = Object.freeze({
  PLAIN: 1, // no option word
  OPTION: 2, // + 4-byte option word (stream SYN carries MSS)
});

/** word0 bits 26-27, always 2. CONFIRMED. */
export const MSG_VERSION = 2;
export const TRANSPORT_HEADER_LEN = 8;

/**
 * Transport header (8 bytes, §4.1):
 *   word0 u32 LE: bits 0-15 length (bytes after this header), 16-25 zero, 26-27 version=2, 28-31 type
 *   word1 u32 LE: bits 0-15 src address, 16-31 dst address
 * On the wire: len_lo len_hi 00 T(0x18|0x28)  src_lo src_hi dst_lo dst_hi
 */
export function encodeTransportHeader({ type, length, src, dst }) {
  const w0 = (((type & 0xf) << 28) | ((MSG_VERSION & 3) << 26) | (length & 0xffff)) >>> 0;
  const w1 = ((src & 0xffff) | ((dst & 0xffff) << 16)) >>> 0;
  return u32words(w0, w1);
}

/** Decode the 8-byte transport header at `off`. */
export function decodeTransportHeader(bytes, off = 0) {
  const w0 = readU32(bytes, off);
  const w1 = readU32(bytes, off + 4);
  return {
    type: w0 >>> 28,
    version: (w0 >>> 26) & 3,
    length: w0 & 0xffff,
    src: w1 & 0xffff,
    dst: w1 >>> 16,
  };
}

/** Padded size a message occupies inside the RSMC payload: (len + 8 + 3) & ~3. CONFIRMED. */
export const messageSize = (length) => (length + TRANSPORT_HEADER_LEN + 3) & ~3;

/**
 * Build one McBsp message, zero-padded to a multiple of 4 bytes.
 * Pass `option` (u32) to produce a type-2 message; the option word counts in `length`.
 * @param {{src:number, dst:number, body:Uint8Array, option?:number}} m
 */
export function encodeMessage({ src, dst, body, option }) {
  const hasOpt = option !== undefined && option !== null;
  const inner = hasOpt ? concatBytes(u32words(option), body) : body;
  const hdr = encodeTransportHeader({ type: hasOpt ? MSG_TYPE.OPTION : MSG_TYPE.PLAIN, length: inner.length, src, dst });
  const out = new Uint8Array(messageSize(inner.length));
  out.set(hdr, 0);
  out.set(inner, TRANSPORT_HEADER_LEN);
  return out;
}

/**
 * Split an RSMC payload into messages (router task 0x110300): walk while ≥ 8 bytes remain,
 * each message takes (len + 8 + 3) & ~3 bytes.
 * @returns {Array<{type:number, version:number, length:number, src:number, dst:number, option:number|null, body:Uint8Array}>}
 */
export function splitPayload(payload) {
  const out = [];
  let o = 0;
  while (payload.length - o >= TRANSPORT_HEADER_LEN) {
    const h = decodeTransportHeader(payload, o);
    const start = o + TRANSPORT_HEADER_LEN;
    if (start + h.length > payload.length) throw new AmpProtocolError('McBsp message runs past the RSMC payload');
    let body = payload.slice(start, start + h.length);
    let option = null;
    if (h.type === MSG_TYPE.OPTION) {
      if (body.length < 4) throw new AmpProtocolError('type-2 message without option word');
      option = readU32(body, 0);
      body = body.slice(4);
    }
    out.push({ ...h, option, body });
    o += messageSize(h.length);
  }
  return out;
}

/**
 * Greedy packing of already-encoded (padded) messages into RSMC payloads of ≤ maxPayload bytes,
 * the way ExecTasks fills a packet with as many queued messages as fit.
 * @param {Uint8Array[]} messages
 * @param {number} maxPayload
 * @returns {Uint8Array[]}
 */
export function packMessages(messages, maxPayload) {
  const payloads = [];
  let cur = [];
  let size = 0;
  for (const m of messages) {
    if (m.length > maxPayload) throw new AmpProtocolError(`message of ${m.length} bytes exceeds ${maxPayload}`);
    if (size + m.length > maxPayload) {
      payloads.push(concatBytes(...cur));
      cur = [];
      size = 0;
    }
    cur.push(m);
    size += m.length;
  }
  if (cur.length) payloads.push(concatBytes(...cur));
  return payloads;
}

/**
 * Inbound type-2 option rewrite done by the router (CONFIRMED §4.1): clamp the MSS (bits 16-31)
 * to our own channel MSS, increment the hop count (bits 0-7), clear bits 8-15.
 */
export function rewriteInboundOption(option, ownMss) {
  const mss = Math.min(option >>> 16, ownMss);
  const hop = ((option & 0xff) + 1) & 0xff;
  return ((mss << 16) | hop) >>> 0;
}

/**
 * Minimal router: hands each inbound message to the port bound at its destination address,
 * and queues outbound messages on the link.
 */
export class Router {
  /**
   * @param {{send:(msg:Uint8Array)=>void, mss:number, backlog?:()=>number}} opts
   *   send: queue an encoded message on the link; mss: own channel MSS (MTU − 12);
   *   backlog: number of messages waiting in the link queue (lets streams apply back-pressure)
   */
  constructor({ send, mss, backlog }) {
    this.send = send;
    this.mss = mss;
    this.backlog = backlog ?? (() => 0);
    /** @type {Map<number, (msg:object)=>void>} */
    this.ports = new Map();
    this.stats = { routed: 0, unroutable: 0 };
  }

  /** Bind a handler for messages whose dst equals `addr`. */
  bind(addr, handler) {
    const a = addr & 0xffff;
    this.ports.set(a, handler);
    // only unbind if nobody re-bound the address in the meantime
    return () => {
      if (this.ports.get(a) === handler) this.ports.delete(a);
    };
  }

  /** Called with each in-order RSMC payload. */
  handlePacket(payload) {
    for (const msg of splitPayload(payload)) {
      if (msg.option !== null) msg.option = rewriteInboundOption(msg.option, this.mss);
      const h = this.ports.get(msg.dst);
      if (!h) {
        this.stats.unroutable++;
        continue;
      }
      this.stats.routed++;
      h(msg);
    }
  }

  /** Encode and queue a message. */
  sendMessage(m) {
    this.send(encodeMessage(m));
  }
}

