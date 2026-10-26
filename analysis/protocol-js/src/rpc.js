// Service RPC envelope over a stream byte pipe (editor and librarian services).
//
// Spec: native_transport.md §6, native_messages.md §1.
// Requests  phone → amp:  u32 cmd, u32 payload_len, payload   (DoCommandCommon 0x103850 / 0x10b4ea)
// Inbound   amp → phone:  u32 type, u32 len, body             (HandleInPacket 0x106b16 / 0x10c61e)
// Responses are matched FIFO to the oldest outstanding request: there is no transaction id.

import { concatBytes, EMPTY, readU32, u32words } from './values.js';
import { realClock } from './clock.js';
import { AmpProtocolError, NATIVE_ERR, TimeoutError } from './errors.js';
import { assertCommandAllowed } from './guard.js';

/** Inbound message types. CONFIRMED (§6.2). */
export const INBOUND = Object.freeze({
  NONE: 0, // ignored
  RESPONSE: 1,
  DSP_EVENT: 2,
  PATCH_EVENT: 3,
  PARAM_EVENT: 4,
  TAP_TEMPO_EVENT: 5,
  FBV_STATUS_EVENT: 6,
  PSKEY_CHANGE_EVENT: 7,
  SYS_SETTING_CHANGE_EVENT: 8,
});

/** Editor events must have a body ≤ 16 bytes (Init(port,0x200,7,0x10)); longer → −19. CONFIRMED. */
export const MAX_EVENT_BODY = 16;

/** Default per-request wait (5000 ms). CONFIRMED (§6.3). */
export const DEFAULT_RPC_TIMEOUT_MS = 5000;

/**
 * Build a request: u32 cmd, u32 len, payload. `declaredLen` overrides the length field
 * (not needed in practice: SetPresetFile's len already counts the 8-byte args + blob).
 */
export function encodeRpcRequest(cmd, payload = EMPTY, declaredLen = payload.length) {
  return concatBytes(u32words(cmd, declaredLen), payload);
}

/** Build an inbound message (used by the mock amp): u32 type, u32 len, body. */
export function encodeRpcInbound(type, body = EMPTY) {
  return concatBytes(u32words(type, body.length), body);
}

/**
 * Incremental parser for `u32 id, u32 len, body` records arriving in arbitrary chunks.
 * Works for both directions (requests on the amp side, inbound messages on the phone side).
 */
export class RpcParser {
  /** @param {(rec:{id:number, body:Uint8Array})=>void} onRecord */
  constructor(onRecord, { maxBody = 1 << 20 } = {}) {
    this.onRecord = onRecord;
    this.maxBody = maxBody;
    this.buf = EMPTY;
  }

  push(chunk) {
    this.buf = this.buf.length ? concatBytes(this.buf, chunk) : chunk;
    let o = 0;
    while (this.buf.length - o >= 8) {
      const id = readU32(this.buf, o);
      const len = readU32(this.buf, o + 4);
      if (len > this.maxBody) throw new AmpProtocolError(`RPC record length ${len} too large`, NATIVE_ERR.PROTOCOL);
      if (this.buf.length - o - 8 < len) break;
      const body = this.buf.slice(o + 8, o + 8 + len);
      o += 8 + len;
      this.onRecord({ id, body });
    }
    this.buf = o < this.buf.length ? this.buf.slice(o) : EMPTY;
  }
}

/**
 * FIFO request/response client bound to an open StreamEndpoint.
 *
 * - `request()` writes the bytes and returns a promise for the response body.
 * - Inbound type 1 completes the oldest pending request; type 0 is ignored; other types go to
 *   `onEvent` when `allowEvents` (editor), otherwise they are a protocol error (librarian: −4).
 * - A request that times out keeps its FIFO slot (marked stale) so that a late response is
 *   consumed and discarded instead of being matched to the next request (INFERRED-safe choice).
 */
export class RpcClient {
  /**
   * @param {object} o
   * @param {import('./stream.js').StreamEndpoint} o.stream
   * @param {string} o.name
   * @param {'editor'|'librarian'} [o.service]  enables the guard.js allow-list check on every request
   * @param {boolean} [o.allowEvents=false]
   * @param {(ev:{type:number, body:Uint8Array})=>void} [o.onEvent]
   * @param {(err:Error)=>void} [o.onError]
   * @param {object} [o.clock]
   * @param {number} [o.maxOutstanding=512]
   */
  constructor({ stream, name, service, allowEvents = false, onEvent, onError, clock = realClock, maxOutstanding = 512 }) {
    Object.assign(this, { stream, name, service, allowEvents, onEvent, onError, clock, maxOutstanding });
    this.pending = [];
    this.closed = false;
    this.parser = new RpcParser((rec) => this._onInbound(rec));
    stream.setDataHandler((bytes) => {
      try {
        this.parser.push(bytes);
      } catch (e) {
        this._fatal(e);
      }
    });
  }

  /**
   * Send `requestBytes` (already-encoded `u32 cmd, u32 len, payload`) and await the response body.
   * @param {Uint8Array} requestBytes
   * @param {{timeoutMs?:number|null, label?:string, confirmWrite?:boolean}} [opts] timeoutMs null = wait forever
   * @returns {Promise<Uint8Array>}
   */
  request(requestBytes, { timeoutMs = DEFAULT_RPC_TIMEOUT_MS, label, confirmWrite } = {}) {
    if (this.closed) return Promise.reject(new AmpProtocolError(`${this.name}: client closed`));
    if (this.pending.length >= this.maxOutstanding) return Promise.reject(new AmpProtocolError(`${this.name}: too many outstanding requests`));
    const cmd = readU32(requestBytes, 0);
    if (this.service) {
      // second line of defence: the allow-list is checked again on the encoded bytes
      const index = requestBytes.length >= 12 ? readU32(requestBytes, 8) : undefined;
      try {
        assertCommandAllowed(this.service, cmd, { index, confirmWrite });
      } catch (e) {
        return Promise.reject(e);
      }
    }
    return new Promise((resolve, reject) => {
      const entry = { cmd, label: label ?? `cmd ${cmd}`, resolve, reject, stale: false, timer: null };
      if (timeoutMs != null) {
        entry.timer = this.clock.setTimeout(() => {
          entry.stale = true;
          reject(new TimeoutError(`${this.name}: ${entry.label} timed out after ${timeoutMs} ms`));
        }, timeoutMs);
      }
      this.pending.push(entry);
      try {
        this.stream.write(requestBytes);
      } catch (e) {
        this.pending = this.pending.filter((p) => p !== entry);
        if (entry.timer != null) this.clock.clearTimeout(entry.timer);
        reject(e);
      }
    });
  }

  _onInbound({ id: type, body }) {
    if (type === INBOUND.NONE) return;
    if (type === INBOUND.RESPONSE) {
      const entry = this.pending.shift();
      if (!entry) return; // unsolicited response: ignore
      if (entry.timer != null) this.clock.clearTimeout(entry.timer);
      if (!entry.stale) entry.resolve(body);
      return;
    }
    if (this.allowEvents && type <= INBOUND.SYS_SETTING_CHANGE_EVENT) {
      if (body.length > MAX_EVENT_BODY) {
        throw new AmpProtocolError(`${this.name}: event type ${type} body ${body.length} > ${MAX_EVENT_BODY}`, NATIVE_ERR.EVENT_TOO_LONG);
      }
      this.onEvent?.({ type, body });
      return;
    }
    throw new AmpProtocolError(`${this.name}: unexpected inbound type ${type}`, NATIVE_ERR.PROTOCOL);
  }

  _fatal(err) {
    this.close(err);
    this.onError?.(err);
  }

  /** Reject everything outstanding. */
  close(err = new AmpProtocolError(`${this.name}: closed`)) {
    this.closed = true;
    for (const p of this.pending) {
      if (p.timer != null) this.clock.clearTimeout(p.timer);
      if (!p.stale) p.reject(err);
    }
    this.pending = [];
  }
}
