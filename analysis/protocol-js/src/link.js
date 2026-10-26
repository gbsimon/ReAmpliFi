// Link layer: IAP ASCII sync + RobustSerialMsgChannel (RSMC) framing and ARQ.
//
// Spec: native_transport.md §2 (IAP sync, AndroidSppMsgChannel) and §3 (RSMC).
// Source functions: RobustSerialMsgChannel_ExecTasks 0x112950 (TX), _HandleRxData 0x112440 (RX),
// CRC16_Process 0x113b10, AndroidSppMsgChannel::execTasks 0xa35ac / write 0xa2ed0.

import { crc16CcittFalse } from './crc.js';
import { realClock } from './clock.js';
import { asciiBytes, concatBytes, EMPTY, readU16, viewOf } from './values.js';
import { AmpProtocolError, NATIVE_ERR } from './errors.js';

// ------------------------------------------------------------------------------ IAP sync

/** "IAP x OK" (8 bytes, no NUL). Written ~200 ms after open. CONFIRMED (§2, E1). */
export const IAP_OK = asciiBytes('IAP x OK');
/** "IAP x START" (11 bytes). Written ~1 s after IAP_OK. CONFIRMED (§2, E2). */
export const IAP_START = asciiBytes('IAP x START');
/** "IAP x STOP" (10 bytes). Written by Close. CONFIRMED (§2, E3). */
export const IAP_STOP = asciiBytes('IAP x STOP');

/** AndroidSppMsgChannel states (§2). CONFIRMED. */
export const IAP_STATE = Object.freeze({
  SYNCHING_STAGE1: 2,
  SYNCHING_STAGE2: 3,
  SYNCHING_STAGE3: 4,
  RUNNING: 5,
  STOPPING: 6,
  STOPPED: 7,
});

/**
 * Phone-side IAP link-sync state machine, advanced by the 200 ms channel tick.
 * Timeline (CONFIRMED §2): tick 1 writes IAP_OK, 5 ticks later IAP_START, 5 ticks later RUNNING
 * (≈0.2 s / 1.2 s / 2.2 s). Nothing received is parsed as ASCII.
 */
export class IapSync {
  /** @param {(bytes:Uint8Array)=>void} write raw transport write */
  constructor(write) {
    this.write = write;
    this.state = IAP_STATE.SYNCHING_STAGE1;
    this.counter = 0;
  }

  get running() {
    return this.state === IAP_STATE.RUNNING;
  }

  /** One 200 ms tick. Returns the state after the tick. */
  tick() {
    switch (this.state) {
      case IAP_STATE.SYNCHING_STAGE1:
        this.write(IAP_OK);
        this.counter = 5;
        this.state = IAP_STATE.SYNCHING_STAGE2;
        break;
      case IAP_STATE.SYNCHING_STAGE2:
        if (--this.counter <= 0) {
          this.write(IAP_START);
          this.counter = 5;
          this.state = IAP_STATE.SYNCHING_STAGE3;
        }
        break;
      case IAP_STATE.SYNCHING_STAGE3:
        if (--this.counter <= 0) this.state = IAP_STATE.RUNNING;
        break;
      default:
        break;
    }
    return this.state;
  }

  /** Close: write IAP_STOP and go to STOPPING (next tick → STOPPED). */
  stop() {
    if (this.state === IAP_STATE.STOPPED || this.state === IAP_STATE.STOPPING) return;
    this.write(IAP_STOP);
    this.state = IAP_STATE.STOPPING;
  }
}

/**
 * Scans a raw byte stream for the IAP ASCII commands (used by the amp side / mock, which has
 * to notice IAP_START / IAP_STOP). INFERRED: the amp resets its RSMC endpoint on these.
 */
export class IapDetector {
  /** @param {(cmd:'OK'|'START'|'STOP')=>void} onCommand */
  constructor(onCommand) {
    this.onCommand = onCommand;
    this.tail = EMPTY;
  }

  push(chunk) {
    const buf = concatBytes(this.tail, chunk);
    const text = String.fromCharCode(...buf);
    const re = /IAP x (OK|START|STOP)/g;
    let m;
    let last = 0;
    while ((m = re.exec(text))) {
      this.onCommand(m[1]);
      last = m.index + m[0].length;
    }
    // keep up to 10 trailing bytes (a command may be split across chunks)
    this.tail = buf.slice(Math.max(last, buf.length - 10));
  }
}

// ------------------------------------------------------------------------------ framing

export const SYNC_BYTE = 0x55;
export const HEADER_LEN = 12;
/** Default whole-frame MTU before device info is known (AmplifiRemoteManager::OpenOnLine passes 0xF0). */
export const DEFAULT_MTU = 240;

/**
 * Build one RSMC frame (§3.1, CONFIRMED in ExecTasks 0x112950):
 *
 *   off size  field
 *    0   2    sync 55 55
 *    2   1    reserved (0)
 *    3   1    seq        (data packets start at 1; header-only frames carry the last sent seq)
 *    4   1    ack        (cumulative: last peer seq delivered in order)
 *    5   1    rx_limit   (credit: highest peer seq we accept)
 *    6   2    len  u16   payload length (0 = header-only)
 *    8   2    pcrc u16   CRC16 over payload, 0 when len == 0
 *   10   2    hcrc u16   CRC16 over the 12 header bytes with hcrc = 0
 *
 * @param {{seq?:number, ack?:number, rxLimit?:number, payload?:Uint8Array, reserved?:number}} f
 * @returns {Uint8Array}
 */
export function encodeFrame({ seq = 0, ack = 0, rxLimit = 0, payload = EMPTY, reserved = 0 } = {}) {
  const out = new Uint8Array(HEADER_LEN + payload.length);
  const v = viewOf(out);
  out[0] = SYNC_BYTE;
  out[1] = SYNC_BYTE;
  out[2] = reserved & 0xff;
  out[3] = seq & 0xff;
  out[4] = ack & 0xff;
  out[5] = rxLimit & 0xff;
  v.setUint16(6, payload.length, true);
  v.setUint16(8, payload.length ? crc16CcittFalse(payload) : 0, true);
  v.setUint16(10, 0, true);
  v.setUint16(10, crc16CcittFalse(out.subarray(0, HEADER_LEN)), true); // header CRC covers 12 bytes incl. two zeros
  out.set(payload, HEADER_LEN);
  return out;
}

/**
 * Parse + validate a 12-byte header. Returns null when sync or header CRC is wrong.
 * @returns {{reserved:number, seq:number, ack:number, rxLimit:number, len:number, pcrc:number, hcrc:number}|null}
 */
export function decodeHeader(bytes, off = 0) {
  if (bytes.length < off + HEADER_LEN) return null;
  if (bytes[off] !== SYNC_BYTE || bytes[off + 1] !== SYNC_BYTE) return null;
  const hdr = bytes.slice(off, off + HEADER_LEN);
  const hcrc = readU16(hdr, 10);
  hdr[10] = 0;
  hdr[11] = 0;
  if (crc16CcittFalse(hdr) !== hcrc) return null;
  return {
    reserved: hdr[2],
    seq: hdr[3],
    ack: hdr[4],
    rxLimit: hdr[5],
    len: readU16(hdr, 6),
    pcrc: readU16(hdr, 8),
    hcrc,
  };
}

/**
 * Streaming RSMC frame parser mirroring HandleRxData 0x112440 (CONFIRMED):
 * - hunts for 55 55 with a sliding 2-byte window;
 * - bad header CRC or len > maxPayload: count an error and resume hunting *after* those 12 bytes
 *   (not at sync+1);
 * - bad payload CRC: drop the frame.
 * No escaping exists; `55 55` inside a payload is harmless because frames are length-delimited.
 */
export class FrameParser {
  /**
   * @param {{maxPayload?:number, onFrame:(hdr:object, payload:Uint8Array)=>void}} opts
   */
  constructor({ maxPayload = DEFAULT_MTU - HEADER_LEN, onFrame }) {
    this.maxPayload = maxPayload;
    this.onFrame = onFrame;
    this.buf = EMPTY;
    this.stats = { frames: 0, headerErrors: 0, lengthErrors: 0, payloadErrors: 0, skippedBytes: 0 };
  }

  reset() {
    this.buf = EMPTY;
  }

  /** Feed raw bytes from the transport. */
  push(chunk) {
    let buf = this.buf.length ? concatBytes(this.buf, chunk) : chunk;
    let i = 0;
    for (;;) {
      // hunt for the sync word
      let j = i;
      while (j + 1 < buf.length && !(buf[j] === SYNC_BYTE && buf[j + 1] === SYNC_BYTE)) j++;
      if (j + 1 >= buf.length) {
        // keep a trailing 0x55: it may be the first half of the next sync word
        const keepFrom = buf.length && buf[buf.length - 1] === SYNC_BYTE ? buf.length - 1 : buf.length;
        this.stats.skippedBytes += keepFrom - i;
        i = keepFrom;
        break;
      }
      this.stats.skippedBytes += j - i;
      i = j;
      if (buf.length - i < HEADER_LEN) break; // wait for more
      const hdr = decodeHeader(buf, i);
      if (!hdr) {
        this.stats.headerErrors++;
        i += HEADER_LEN; // native: drop the 12 bytes and resume hunting after them
        continue;
      }
      if (hdr.len > this.maxPayload) {
        this.stats.lengthErrors++;
        i += HEADER_LEN;
        continue;
      }
      if (buf.length - i < HEADER_LEN + hdr.len) break; // wait for the payload
      const payload = buf.slice(i + HEADER_LEN, i + HEADER_LEN + hdr.len);
      i += HEADER_LEN + hdr.len;
      if (hdr.len && crc16CcittFalse(payload) !== hdr.pcrc) {
        this.stats.payloadErrors++;
        continue;
      }
      this.stats.frames++;
      this.onFrame(hdr, payload);
    }
    this.buf = i < buf.length ? buf.slice(i) : EMPTY;
  }
}

// ------------------------------------------------------------------------------ ARQ endpoint

/** signed 8-bit difference, as the native code compares seq numbers */
const s8 = (x) => (((x & 0xff) ^ 0x80) - 0x80);

/**
 * One side of an RSMC link: selective-repeat ARQ with 8-bit seq, cumulative ACK and a credit
 * window (§3.3, CONFIRMED in ExecTasks / HandleRxData):
 *
 * - send rule: a new packet goes out only if (lastAcked + txWindow − lastSent) ≥ 1 and
 *   (peerRxLimit − lastSent) ≥ 1 (signed 8-bit) and messages are queued; it takes as many queued
 *   messages as fit in MTU − 12 bytes;
 * - at most one data frame per tick (ExecTasks runs every 200 ms);
 * - on a tick with nothing new to send, the oldest unacked packet is resent once it has waited
 *   ≥ retransmitMs (1000 ms); no retry limit, no NAK;
 * - otherwise a 12-byte header-only frame is sent every tick (de-facto keepalive / ACK carrier);
 * - peerRxLimit starts at 0, so nothing is sent before the peer advertised credit.
 *
 * Timers come from the injectable `clock`. With `autoTick:false` the owner calls tick().
 */
export class LinkEndpoint {
  /**
   * @param {object} opts
   * @param {(bytes:Uint8Array)=>void} opts.write  raw transport write (one call per frame)
   * @param {(payload:Uint8Array)=>void} opts.onPacket  in-order payload delivery (to the router)
   * @param {number} [opts.mtu=240]  whole-frame MTU for sending; max payload = mtu − 12
   * @param {number} [opts.rxMtu=mtu] largest frame accepted on receive (longer = length error, dropped)
   * @param {number} [opts.txWindow=8]
   * @param {number} [opts.rxWindow=8]
   * @param {number} [opts.retransmitMs=1000]
   * @param {number} [opts.tickMs=200]
   * @param {object} [opts.clock=realClock]
   * @param {boolean} [opts.autoTick=true]
   * @param {number} [opts.maxDataFramesPerTick=1]  native = 1
   */
  constructor({
    write,
    onPacket,
    mtu = DEFAULT_MTU,
    rxMtu,
    txWindow = 8,
    rxWindow = 8,
    retransmitMs = 1000,
    tickMs = 200,
    clock = realClock,
    autoTick = true,
    maxDataFramesPerTick = 1,
  }) {
    this.write = write;
    this.onPacket = onPacket;
    this.mtu = mtu;
    this.rxMtu = rxMtu ?? mtu;
    this.txWindow = txWindow;
    this.rxWindow = rxWindow;
    this.retransmitMs = retransmitMs;
    this.tickMs = tickMs;
    this.clock = clock;
    this.autoTick = autoTick;
    this.maxDataFramesPerTick = maxDataFramesPerTick;
    this.running = false;
    this.parser = new FrameParser({ maxPayload: this.rxMtu - HEADER_LEN, onFrame: (h, p) => this._onFrame(h, p) });
    this.stats = { dataSent: 0, headerOnlySent: 0, retransmits: 0, delivered: 0, duplicates: 0, outOfWindow: 0 };
    this._interval = null;
    this._resetState();
  }

  /** Largest payload (sum of 4-byte-aligned messages) per frame. */
  get maxPayload() {
    return this.mtu - HEADER_LEN;
  }

  _resetState() {
    this.lastSent = 0; // seq of the last data packet sent
    this.lastAcked = 0; // highest seq the peer acknowledged
    this.peerRxLimit = 0; // peer's credit; 0 until the first valid header arrives
    this.lastDelivered = 0; // last peer seq delivered in order (our ack)
    this.rxLimit = this.rxWindow; // our credit, +1 per packet the upper layer completed
    this.queue = []; // pending messages (Uint8Array, 4-byte aligned)
    this.inflight = new Map(); // seq -> { payload, sentAt }
    this.rxSlots = new Map(); // seq -> payload (out-of-order buffer)
    this.parser?.reset();
  }

  /** Start (or restart) the channel: sequence numbers restart from 0 (§10). */
  start() {
    this.stop();
    this._resetState();
    this.running = true;
    if (this.autoTick) this._interval = this.clock.setInterval(() => this.tick(), this.tickMs);
  }

  /** Stop the channel. Queued and in-flight messages are dropped (native completes them with −35). */
  stop() {
    if (this._interval != null) this.clock.clearInterval(this._interval);
    this._interval = null;
    const dropped = this.queue.length + this.inflight.size;
    this.running = false;
    this.queue = [];
    this.inflight.clear();
    this.rxSlots.clear();
    return dropped;
  }

  /** Messages queued but not yet put in a packet (back-pressure signal for the streams). */
  get backlog() {
    return this.queue.length;
  }

  /** Number of messages waiting or unacknowledged. */
  get pending() {
    return this.queue.length + this.inflight.size;
  }

  /**
   * Queue one upper-layer (McBsp) message. It must be 4-byte aligned and fit in one frame.
   * Throws AmpProtocolError(-36) when too big, (-35) when stopped.
   */
  queueMessage(msg) {
    if (!this.running) throw new AmpProtocolError('link not running', NATIVE_ERR.CHANNEL_STOPPED);
    if (msg.length % 4) throw new AmpProtocolError('RSMC messages must be 4-byte aligned');
    if (msg.length > this.maxPayload) {
      throw new AmpProtocolError(`message of ${msg.length} bytes exceeds max payload ${this.maxPayload}`, NATIVE_ERR.MESSAGE_TOO_BIG);
    }
    this.queue.push(msg);
  }

  /** Feed raw bytes received from the transport. */
  receive(chunk) {
    if (!this.running) return;
    this.parser.push(chunk);
  }

  _canSendNew() {
    return (
      this.queue.length > 0 &&
      s8(this.lastAcked + this.txWindow - this.lastSent) >= 1 &&
      s8(this.peerRxLimit - this.lastSent) >= 1
    );
  }

  _sendFrame(seq, payload) {
    this.write(encodeFrame({ seq, ack: this.lastDelivered, rxLimit: this.rxLimit, payload }));
  }

  /** One ExecTasks pass (normally every 200 ms). */
  tick() {
    if (!this.running) return;
    let sent = 0;
    while (sent < this.maxDataFramesPerTick && this._canSendNew()) {
      const parts = [];
      let size = 0;
      while (this.queue.length && size + this.queue[0].length <= this.maxPayload) {
        size += this.queue[0].length;
        parts.push(this.queue.shift());
      }
      const seq = (this.lastSent + 1) & 0xff;
      const payload = concatBytes(...parts);
      this.inflight.set(seq, { payload, sentAt: this.clock.now() });
      this.lastSent = seq;
      this._sendFrame(seq, payload);
      this.stats.dataSent++;
      sent++;
    }
    if (sent) return;
    const oldest = (this.lastAcked + 1) & 0xff;
    const pkt = this.lastSent !== this.lastAcked ? this.inflight.get(oldest) : undefined;
    if (pkt && this.clock.now() - pkt.sentAt >= this.retransmitMs) {
      pkt.sentAt = this.clock.now();
      this._sendFrame(oldest, pkt.payload); // same seq + payload, refreshed ack / limit
      this.stats.retransmits++;
      return;
    }
    this._sendFrame(this.lastSent, EMPTY); // header-only keepalive / ACK
    this.stats.headerOnlySent++;
  }

  _onFrame(hdr, payload) {
    // ACK processing on every valid header (header-only frames included)
    const d = s8(hdr.ack - this.lastAcked);
    if (d > 0 && d <= this.txWindow) {
      for (let k = 1; k <= d; k++) this.inflight.delete((this.lastAcked + k) & 0xff);
      this.lastAcked = hdr.ack;
    }
    this.peerRxLimit = hdr.rxLimit;
    if (hdr.len === 0) return; // seq of header-only frames is ignored
    const r = s8(hdr.seq - this.lastDelivered);
    if (r <= 0) {
      this.stats.duplicates++;
      return;
    }
    if (r > this.rxWindow) {
      this.stats.outOfWindow++;
      return;
    }
    if (!this.rxSlots.has(hdr.seq)) this.rxSlots.set(hdr.seq, payload);
    for (;;) {
      const next = (this.lastDelivered + 1) & 0xff;
      const p = this.rxSlots.get(next);
      if (!p) break;
      this.rxSlots.delete(next);
      this.lastDelivered = next;
      this.stats.delivered++;
      try {
        this.onPacket(p);
      } finally {
        // CompleteInPacket: credit grows once the router is done with the packet
        this.rxLimit = (this.rxLimit + 1) & 0xff;
      }
    }
  }
}
