// MsgPort_Stream: a small TCP-like byte stream over McBsp messages.
//
// Spec: native_transport.md §5. Source: stream TX task 0x110880, RX handler 0x1112e0,
// MsgPort_Stream_Connect 0x111d60 / Accept 0x111ba0 / Close 0x1120c0,
// MsgPort_Stream_SetHeartbeatTimeout 0x112080.
//
// Segment (inside a McBsp message):
//   [type 2 only] option u32: bits 16-31 MSS, bits 0-7 hop count
//   word A u32: bits 24-31 flags, bits 8-15 seq (u8)
//   word B u32: window edge (cumulative byte count the peer may send up to)
//   data

import { Emitter } from './emitter.js';
import { realClock } from './clock.js';
import { concatBytes, EMPTY, readU32, u32words } from './values.js';
import { encodeMessage, MSG_TYPE } from './router.js';
import { AmpProtocolError, NATIVE_ERR, TimeoutError } from './errors.js';

/** Segment flags (word A bits 24-31). CONFIRMED (§5.1). */
export const STREAM_FLAG = Object.freeze({
  SYN: 0x01,
  FIN: 0x02,
  DATA: 0x04,
  WND: 0x08, // window update / ACK of consumed bytes
  HB: 0x10, // heartbeat
  HB_ENABLE: 0x20, // SYN only: asks the listener to use 4000 ms timeout / 1000 ms interval
});

/** Stream states (+0x1b8). CONFIRMED (§5.1). Negative values = error code. */
export const STREAM_STATE = Object.freeze({
  IDLE: 0,
  LISTEN: 1, // (library-local marker for an acceptor waiting for SYN; native uses 0)
  SYN_SENT: 2,
  ESTABLISHED: 3,
  PEER_CLOSED: 7,
  CLOSING: 0x0b,
});

export const STREAM_HEADER_LEN = 8; // word A + word B
/** Initial free RX buffer advertised as window edge. CONFIRMED (§5.1). */
export const DEFAULT_RX_BUFFER = 4096;
/** Max data per segment = peerMSS − 16 (transport header 8 + stream words 8). CONFIRMED. */
export const SEGMENT_OVERHEAD = 16;

/**
 * Encode the segment body (word A, word B, data) without the transport header.
 */
export function encodeSegment({ flags, seq, window, data = EMPTY }) {
  return concatBytes(u32words((((flags & 0xff) << 24) | ((seq & 0xff) << 8)) >>> 0, window >>> 0), data);
}

/**
 * Encode a full stream segment as a padded McBsp message. Passing `mss` produces a type-2
 * message whose option word is `mss << 16` (hop count 0), as a SYN does.
 */
export function encodeStreamMessage({ src, dst, flags, seq, window, data = EMPTY, mss }) {
  const body = encodeSegment({ flags, seq, window, data });
  const option = mss !== undefined && mss !== null ? ((mss & 0xffff) << 16) >>> 0 : undefined;
  return encodeMessage({ src, dst, body, option });
}

/**
 * Decode a stream segment from a message produced by splitPayload().
 * @returns {{flags:number, seq:number, window:number, data:Uint8Array, mss:number|null, hop:number|null, src:number, dst:number}}
 */
export function decodeStreamSegment(msg) {
  if (msg.body.length < STREAM_HEADER_LEN) throw new AmpProtocolError('stream segment shorter than 8 bytes', NATIVE_ERR.PROTOCOL);
  const a = readU32(msg.body, 0);
  return {
    flags: a >>> 24,
    seq: (a >>> 8) & 0xff,
    window: readU32(msg.body, 4),
    data: msg.body.slice(STREAM_HEADER_LEN),
    mss: msg.type === MSG_TYPE.OPTION && msg.option !== null ? msg.option >>> 16 : null,
    hop: msg.type === MSG_TYPE.OPTION && msg.option !== null ? msg.option & 0xff : null,
    src: msg.src,
    dst: msg.dst,
  };
}

/**
 * One end of a stream. The phone is the connector; the mock amp uses listen().
 *
 * Rules implemented (CONFIRMED §5):
 * - seq starts at 1 with the SYN and increments on every segment (data, window update, heartbeat);
 *   a non-SYN segment whose seq is not exactly last+1 aborts the stream with −4;
 * - 2-way handshake: SYN → SYN; no third ACK;
 * - data per segment ≤ peerMSS − 16 and ≤ windowEdge − bytesSent;
 * - SetHeartbeatTimeout(T): RX-silence timeout T, TX-idle heartbeat every T >> 2
 *   (overridable with heartbeatIntervalMs; see README "heartbeat caveat");
 * - a listener receiving SYN with flag 0x20 uses 4000 / 1000 ms, without it heartbeats are off.
 *
 * Events: 'established', 'data' (Uint8Array, only without a data handler... see setDataHandler),
 * 'peerClose', 'closed', 'error' (AmpProtocolError with .code).
 */
export class StreamEndpoint extends Emitter {
  /**
   * @param {object} o
   * @param {number} o.local   local address (e.g. 0x2002)
   * @param {number} o.remote  remote address (e.g. 0x03ED)
   * @param {import('./router.js').Router} o.router
   * @param {number} o.mss     own channel MSS (MTU − 12), advertised in our SYN
   * @param {object} [o.clock]
   * @param {number} [o.timeoutMs=4000]   RX-silence timeout T (0 disables)
   * @param {number} [o.heartbeatIntervalMs]  default T >> 2
   * @param {number} [o.rxBuffer=4096]
   * @param {number} [o.tickMs=200]       MsgPortManager tick
   * @param {boolean} [o.autoTick=true]
   * @param {boolean} [o.requestHeartbeat=true]  set flag 0x20 in our SYN (phone always does)
   * @param {number} [o.maxBacklog=2]  only queue new DATA while the link backlog is below this
   *        (INFERRED stand-in for the native RSMC's limited TX slots; keeps heartbeats of other
   *        streams from starving behind a bulk transfer)
   * @param {string} [o.name]
   */
  constructor({
    local,
    remote,
    router,
    mss,
    clock = realClock,
    timeoutMs = 4000,
    heartbeatIntervalMs,
    rxBuffer = DEFAULT_RX_BUFFER,
    tickMs = 200,
    autoTick = true,
    requestHeartbeat = true,
    maxBacklog = 2,
    name = `stream ${local.toString(16)}`,
  }) {
    super();
    Object.assign(this, { local, remote, router, mss, clock, rxBuffer, tickMs, autoTick, requestHeartbeat, maxBacklog, name });
    this.state = STREAM_STATE.IDLE;
    this.txSeq = 0;
    this.rxSeq = 0;
    this.peerMss = 0;
    this.peerWindow = 0;
    this.bytesSent = 0;
    this.consumed = 0;
    this._txChunks = [];
    this._txLen = 0;
    this._rxChunks = [];
    this._rxLen = 0;
    this._readers = [];
    this._dataHandler = null;
    this._pendingSyn = false;
    this._pendingFin = false;
    this._pendingWnd = false;
    this._isConnector = false;
    this.lastRx = clock.now();
    this.lastTx = clock.now();
    this.stats = { segmentsSent: 0, segmentsReceived: 0, heartbeatsSent: 0 };
    this.setHeartbeatTimeout(timeoutMs, heartbeatIntervalMs);
    this._unbind = router.bind(local, (msg) => this.handleMessage(msg));
    this._interval = null;
  }

  /** MsgPort_Stream_SetHeartbeatTimeout: timeout T, heartbeat interval T >> 2 (unless overridden). */
  setHeartbeatTimeout(timeoutMs, heartbeatIntervalMs) {
    this.timeoutMs = timeoutMs;
    this.heartbeatIntervalMs = heartbeatIntervalMs ?? timeoutMs >> 2;
    this._hbOverride = heartbeatIntervalMs;
  }

  /** Our current window edge: free buffer + bytes the application consumed. */
  get windowEdge() {
    return (this.rxBuffer + this.consumed) >>> 0;
  }

  get isOpen() {
    return this.state === STREAM_STATE.ESTABLISHED || this.state === STREAM_STATE.PEER_CLOSED;
  }

  _startTicking() {
    if (this.autoTick && this._interval == null) this._interval = this.clock.setInterval(() => this.tick(), this.tickMs);
  }

  _stopTicking() {
    if (this._interval != null) this.clock.clearInterval(this._interval);
    this._interval = null;
  }

  /**
   * Connect (phone side): SYN with option MSS<<16, flags 0x21 (SYN|HB_ENABLE), seq 1, window 4096.
   * Resolves when the peer's SYN arrives.
   */
  connect({ timeoutMs = 10_000 } = {}) {
    if (this.state !== STREAM_STATE.IDLE) return Promise.reject(new AmpProtocolError(`${this.name}: connect in state ${this.state}`));
    this._isConnector = true;
    this._pendingSyn = true;
    this.state = STREAM_STATE.SYN_SENT;
    this.lastRx = this.clock.now();
    this._startTicking();
    return new Promise((resolve, reject) => {
      const timer = this.clock.setTimeout(() => {
        offE();
        offF();
        this._fail(NATIVE_ERR.TIMEOUT, 'connect timed out');
        reject(new TimeoutError(`${this.name}: connect timed out`));
      }, timeoutMs);
      const offE = this.once('established', () => {
        this.clock.clearTimeout(timer);
        offF();
        resolve();
      });
      const offF = this.once('error', (e) => {
        this.clock.clearTimeout(timer);
        offE();
        reject(e);
      });
    });
  }

  /** Acceptor side (mock amp): wait for a SYN; answers with a SYN on the next tick. */
  listen() {
    this._isConnector = false;
    this.state = STREAM_STATE.LISTEN;
    this._startTicking();
  }

  /**
   * Route received data to `fn` instead of buffering it for read(). Already-buffered bytes are
   * flushed to the handler immediately. Pass null to go back to buffering.
   */
  setDataHandler(fn) {
    this._dataHandler = fn;
    if (fn && this._rxLen) {
      const data = concatBytes(...this._rxChunks);
      this._rxChunks = [];
      this._rxLen = 0;
      this._consume(data.length);
      fn(data);
    }
  }

  /** Read exactly `n` bytes (only while no data handler is set). */
  read(n, { timeoutMs = 5000 } = {}) {
    return new Promise((resolve, reject) => {
      const reader = { n, resolve, reject, timer: null };
      reader.timer = this.clock.setTimeout(() => {
        this._readers = this._readers.filter((r) => r !== reader);
        reject(new TimeoutError(`${this.name}: read(${n}) timed out`));
      }, timeoutMs);
      this._readers.push(reader);
      this._serveReaders();
    });
  }

  _serveReaders() {
    while (this._readers.length && this._rxLen >= this._readers[0].n) {
      const r = this._readers.shift();
      const all = concatBytes(...this._rxChunks);
      const out = all.slice(0, r.n);
      const rest = all.slice(r.n);
      this._rxChunks = rest.length ? [rest] : [];
      this._rxLen = rest.length;
      this._consume(r.n);
      this.clock.clearTimeout(r.timer);
      r.resolve(out);
    }
  }

  _consume(n) {
    this.consumed += n;
    this._pendingWnd = true;
  }

  /** Queue bytes for sending (auto-flushed on the next tick). */
  write(bytes) {
    if (!this.isOpen) throw new AmpProtocolError(`${this.name}: write on a stream that is not open (state ${this.state})`);
    if (bytes.length) {
      this._txChunks.push(bytes);
      this._txLen += bytes.length;
    }
  }

  /**
   * Close: flush, send FIN (state 3 → 0xB), resolve when the peer's FIN arrives
   * (or after timeoutMs, resolving with false).
   */
  close({ timeoutMs = 3000 } = {}) {
    if (this.state === STREAM_STATE.IDLE || this.state === STREAM_STATE.LISTEN || this.state < 0) {
      this.destroy();
      return Promise.resolve(true);
    }
    this._pendingFin = true;
    return new Promise((resolve) => {
      const timer = this.clock.setTimeout(() => {
        off();
        this.destroy();
        resolve(false);
      }, timeoutMs);
      const off = this.once('closed', () => {
        this.clock.clearTimeout(timer);
        resolve(true);
      });
    });
  }

  /** Stop timers and unbind from the router. */
  destroy() {
    this._stopTicking();
    this._unbind?.();
    this._unbind = null;
    for (const r of this._readers) {
      this.clock.clearTimeout(r.timer);
      r.reject(new AmpProtocolError(`${this.name}: stream destroyed`));
    }
    this._readers = [];
  }

  _fail(code, message) {
    if (this.state < 0) return;
    this.state = code;
    const err = new AmpProtocolError(`${this.name}: ${message}`, code);
    this.destroy();
    this.emit('error', err);
  }

  _send(flags, data = EMPTY, withMss = false) {
    this.txSeq = (this.txSeq + 1) & 0xff;
    this.router.sendMessage({
      src: this.local,
      dst: this.remote,
      body: encodeSegment({ flags, seq: this.txSeq, window: this.windowEdge, data }),
      option: withMss ? ((this.mss & 0xffff) << 16) >>> 0 : undefined,
    });
    this.lastTx = this.clock.now();
    this.stats.segmentsSent++;
  }

  /** One MsgPortManager tick (normally every 200 ms). */
  tick() {
    if (this.state < 0) return;
    const now = this.clock.now();
    const live = this.isOpen || this.state === STREAM_STATE.CLOSING;
    if (live && this.timeoutMs > 0 && now - this.lastRx >= this.timeoutMs) {
      this._fail(NATIVE_ERR.TIMEOUT, `heartbeat timeout: no segment received for ${now - this.lastRx} ms`);
      return;
    }
    if (this._pendingSyn) {
      this._pendingSyn = false;
      const flags = STREAM_FLAG.SYN | (this._isConnector && this.requestHeartbeat ? STREAM_FLAG.HB_ENABLE : 0);
      this._send(flags, EMPTY, true);
      return;
    }
    if (!this.isOpen) return;
    let sent = false;
    while (this._txLen > 0 && this.router.backlog() < this.maxBacklog) {
      const avail = (this.peerWindow - this.bytesSent) | 0;
      const n = Math.min(this._txLen, this.peerMss - SEGMENT_OVERHEAD, avail);
      if (n <= 0) break;
      const all = this._txChunks.length === 1 ? this._txChunks[0] : concatBytes(...this._txChunks);
      const data = all.slice(0, n);
      const rest = all.slice(n);
      this._txChunks = rest.length ? [rest] : [];
      this._txLen = rest.length;
      const flags = STREAM_FLAG.DATA | (this._pendingWnd ? STREAM_FLAG.WND : 0);
      this._pendingWnd = false;
      this._send(flags, data);
      this.bytesSent = (this.bytesSent + n) >>> 0;
      sent = true;
    }
    if (!sent && this._pendingWnd) {
      this._pendingWnd = false;
      this._send(STREAM_FLAG.WND);
      sent = true;
    }
    if (!sent && this.heartbeatIntervalMs > 0 && now - this.lastTx >= this.heartbeatIntervalMs) {
      this._send(STREAM_FLAG.HB);
      this.stats.heartbeatsSent++;
      sent = true;
    }
    if (this._pendingFin && this._txLen === 0) {
      this._pendingFin = false;
      this._send(STREAM_FLAG.FIN);
      if (this.state === STREAM_STATE.PEER_CLOSED) {
        this.state = STREAM_STATE.IDLE;
        this.destroy();
        this.emit('closed');
      } else {
        this.state = STREAM_STATE.CLOSING;
      }
    }
  }

  /** Router callback for every message addressed to `local`. */
  handleMessage(msg) {
    if (this.state < 0) return;
    if (msg.src !== this.remote) return;
    let seg;
    try {
      seg = decodeStreamSegment(msg);
    } catch (e) {
      this._fail(NATIVE_ERR.PROTOCOL, e.message);
      return;
    }
    this.stats.segmentsReceived++;
    this.lastRx = this.clock.now();
    if (seg.flags & STREAM_FLAG.SYN) {
      if (this.state === STREAM_STATE.SYN_SENT) {
        this.peerMss = seg.mss ?? this.mss;
        this.rxSeq = seg.seq;
        this.peerWindow = seg.window;
        this.state = STREAM_STATE.ESTABLISHED;
        // SetHeartbeatTimeout is applied again: the connector keeps its own values (§5.2 step 4)
        this.emit('established');
      } else if (this.state === STREAM_STATE.LISTEN) {
        this.peerMss = seg.mss ?? this.mss;
        this.rxSeq = seg.seq;
        this.peerWindow = seg.window;
        if (seg.flags & STREAM_FLAG.HB_ENABLE) this.setHeartbeatTimeout(4000, this._hbOverride ?? 1000);
        else this.setHeartbeatTimeout(0, 0);
        this._pendingSyn = true;
        this.state = STREAM_STATE.ESTABLISHED;
        this.emit('established');
      } else {
        this._fail(NATIVE_ERR.PROTOCOL, `unexpected SYN in state ${this.state}`);
        return;
      }
      if (seg.data.length) this._deliver(seg.data);
      return;
    }
    if (!this.isOpen && this.state !== STREAM_STATE.CLOSING) return;
    const expected = (this.rxSeq + 1) & 0xff;
    if (seg.seq !== expected) {
      this._fail(NATIVE_ERR.PROTOCOL, `stream seq ${seg.seq} != expected ${expected}: abort`);
      return;
    }
    this.rxSeq = seg.seq;
    this.peerWindow = seg.window;
    if (seg.data.length) this._deliver(seg.data);
    if (seg.flags & STREAM_FLAG.FIN) {
      if (this.state === STREAM_STATE.CLOSING) {
        this.state = STREAM_STATE.IDLE;
        this.destroy();
        this.emit('closed');
      } else if (this.state === STREAM_STATE.ESTABLISHED) {
        this.state = STREAM_STATE.PEER_CLOSED;
        this.emit('peerClose');
      }
    }
  }

  _deliver(data) {
    if (this._dataHandler) {
      this._consume(data.length);
      this._dataHandler(data);
      return;
    }
    this._rxChunks.push(data);
    this._rxLen += data.length;
    this.emit('data', data);
    this._serveReaders();
  }
}
