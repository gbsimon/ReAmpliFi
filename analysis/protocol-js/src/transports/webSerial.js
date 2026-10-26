// Web Serial transport for Bluetooth Classic RFCOMM / SPP (PLAN.md §2.1, §3.1).
//
//   const support = webSerialSupport();
//   if (!support.supported) show(support.message);
//   const port = await requestSppPort();             // browser picker (needs a user gesture)
//   const t = new WebSerialTransport(port);
//   await t.open();
//   const amp = new AmpSession(t, { readOnly: true });
//
// Implements the transport contract AmpSession uses:
//   { write(Uint8Array), onData(cb) → unsubscribe, close(), onClose(cb) → unsubscribe }
//
// Facts this relies on ([docs] in PLAN.md §2.1):
// - Chrome/Edge 117+ desktop and Chrome 138+ Android talk to an already-paired Bluetooth device
//   over RFCOMM through navigator.serial. The SPP class id 0x1101 is the one SIG UUID that is
//   not blocked; it still has to be listed in allowedBluetoothServiceClassIds.
// - baudRate is required by open() and meaningless for RFCOMM.
// - Desktop Chrome 130+ fires 'disconnect' for RFCOMM ports and closes the port when the device
//   goes out of range. Android does not reliably fire it: a read error is the signal there.
//
// The transport only moves bytes. It never parses or builds protocol data.

/** Serial Port Profile service class id. */
export const SPP_SERVICE_CLASS_ID = '00001101-0000-1000-8000-00805f9b34fb';

/** RFCOMM ignores it, but SerialPort.open() requires one. */
export const DEFAULT_BAUD_RATE = 115200;

export const UNSUPPORTED_BROWSER_MESSAGE =
  'This browser has no Web Serial. Use Chrome or Edge on desktop (117 or later, 130+ recommended) ' +
  'or Chrome 138+ on Android. Safari, Firefox, iOS browsers and Android WebViews cannot reach the amp.';

export const INSECURE_CONTEXT_MESSAGE =
  'Web Serial needs a secure context: open the app over https:// or from http://localhost.';

/**
 * Feature detection. Never throws.
 * @param {{navigator?:object, isSecureContext?:boolean}} [env] injectable for tests
 * @returns {{supported:boolean, reason:null|'no-navigator'|'insecure-context'|'no-web-serial', message:string|null}}
 */
export function webSerialSupport(env = {}) {
  const nav = 'navigator' in env ? env.navigator : globalThis.navigator;
  const secure = 'isSecureContext' in env ? env.isSecureContext : globalThis.isSecureContext;
  if (!nav) return { supported: false, reason: 'no-navigator', message: UNSUPPORTED_BROWSER_MESSAGE };
  if (secure === false) return { supported: false, reason: 'insecure-context', message: INSECURE_CONTEXT_MESSAGE };
  if (!nav.serial || typeof nav.serial.requestPort !== 'function') {
    return { supported: false, reason: 'no-web-serial', message: UNSUPPORTED_BROWSER_MESSAGE };
  }
  return { supported: true, reason: null, message: null };
}

const serialOf = (serial) => {
  const s = serial ?? globalThis.navigator?.serial;
  if (!s) throw new Error(UNSUPPORTED_BROWSER_MESSAGE);
  return s;
};

/** True when `id` (UUID string or 16-bit number) names the SPP service class. */
export function isSppServiceClassId(id) {
  if (typeof id === 'number') return id === 0x1101;
  return typeof id === 'string' && id.toLowerCase() === SPP_SERVICE_CLASS_ID;
}

/** True when a SerialPort is a Bluetooth RFCOMM port of the SPP service. */
export function isSppPort(port) {
  let info = {};
  try {
    info = port?.getInfo?.() ?? {};
  } catch {
    /* treat as unknown */
  }
  return isSppServiceClassId(info.bluetoothServiceClassId);
}

/** Options for navigator.serial.requestPort(): SPP only, picker narrowed to SPP devices. */
export function sppRequestOptions() {
  return {
    filters: [{ bluetoothServiceClassId: SPP_SERVICE_CLASS_ID }],
    allowedBluetoothServiceClassIds: [SPP_SERVICE_CLASS_ID],
  };
}

/**
 * Open the browser's port picker narrowed to SPP devices. Must run inside a user gesture.
 * Rejects with a DOMException 'NotFoundError' when the user cancels.
 */
export function requestSppPort({ serial } = {}) {
  return serialOf(serial).requestPort(sppRequestOptions());
}

/** Ports this origin was granted before that are SPP ports (one-click reconnect). */
export async function getRememberedSppPorts({ serial } = {}) {
  const ports = await serialOf(serial).getPorts();
  return ports.filter(isSppPort);
}

/**
 * Byte pipe over one SerialPort.
 *
 * Close reasons passed to onClose listeners:
 *   'closed'        close() was called
 *   'disconnected'  the 'disconnect' event fired (desktop Chrome 130+)
 *   'read-error'    the readable stream failed fatally (the Android signal for link loss)
 *   'write-error'   a write failed
 *   'ended'         the readable stream ended without an error
 */
export class WebSerialTransport {
  /**
   * @param {SerialPort} port
   * @param {{serial?:object, baudRate?:number, onWarning?:(err:Error)=>void}} [opts]
   */
  constructor(port, { serial, baudRate = DEFAULT_BAUD_RATE, onWarning } = {}) {
    if (!port) throw new Error('WebSerialTransport needs a SerialPort');
    this.port = port;
    this.serial = serial ?? globalThis.navigator?.serial ?? null;
    this.baudRate = baudRate;
    this.onWarning = onWarning;
    this.isOpen = false;
    this.closed = false;
    this.closeReason = null;
    this.stats = { rxBytes: 0, txBytes: 0, rxChunks: 0, txWrites: 0 };
    this._data = new Set();
    this._close = new Set();
    this._reader = null;
    this._writer = null;
    this._writeChain = Promise.resolve();
    this._readLoopDone = null;
    this._onDisconnectEvent = (ev) => {
      // the event is fired at the port and bubbles to navigator.serial: ignore other ports
      if (ev?.target === this.port || ev?.port === this.port) this._finish('disconnected');
    };
  }

  /** Port info (usbVendorId / bluetoothServiceClassId …). */
  getInfo() {
    try {
      return this.port.getInfo?.() ?? {};
    } catch {
      return {};
    }
  }

  /** Open the port and start the reader loop. */
  async open() {
    if (this.closed) throw new Error('WebSerialTransport: already closed');
    if (this.isOpen) return;
    await this.port.open({ baudRate: this.baudRate });
    this.isOpen = true;
    if (!this.port.writable) throw new Error('serial port opened without a writable stream');
    this._writer = this.port.writable.getWriter();
    this.port.addEventListener?.('disconnect', this._onDisconnectEvent);
    this.serial?.addEventListener?.('disconnect', this._onDisconnectEvent);
    this._readLoopDone = this._readLoop();
  }

  async _readLoop() {
    // Standard Web Serial loop: non-fatal errors (framing, overrun, break) leave port.readable
    // set and the loop takes a new reader; a fatal error (link lost) sets it to null.
    let lastError = null;
    while (!this.closed && this.port.readable) {
      const reader = this.port.readable.getReader();
      this._reader = reader;
      try {
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value.length) {
            this.stats.rxBytes += value.length;
            this.stats.rxChunks++;
            const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
            for (const cb of [...this._data]) {
              try {
                cb(bytes);
              } catch (e) {
                this.onWarning?.(e);
              }
            }
          }
        }
      } catch (e) {
        lastError = e;
        if (!this.closed) this.onWarning?.(e);
      } finally {
        try {
          reader.releaseLock();
        } catch {
          /* already released */
        }
        this._reader = null;
      }
      if (this.closed) return;
      if (!lastError) break; // done without error: the stream ended
      if (!this.port.readable) break;
      lastError = null; // non-fatal: retry with a new reader
    }
    if (!this.closed) this._finish(lastError ? 'read-error' : 'ended', lastError);
  }

  /** Queue bytes for the amp. Synchronous for the caller; writes are serialised. */
  write(bytes) {
    if (this.closed || !this._writer) return;
    const copy = bytes.slice();
    this.stats.txBytes += copy.length;
    this.stats.txWrites++;
    // queued writes still go out when close() runs (it awaits this chain); new writes are refused
    this._writeChain = this._writeChain
      .then(() => this._writer?.write(copy))
      .catch((e) => {
        if (!this.closed) this._finish('write-error', e);
      });
  }

  /** Subscribe to received chunks. Returns an unsubscribe function. */
  onData(cb) {
    this._data.add(cb);
    return () => this._data.delete(cb);
  }

  /** Subscribe to link loss / close: cb({ reason, error? }). Returns an unsubscribe function. */
  onClose(cb) {
    this._close.add(cb);
    return () => this._close.delete(cb);
  }

  /** Close the port. Safe to call more than once. */
  close() {
    return this._finish('closed');
  }

  _finish(reason, error) {
    if (this.closed) return this._closing;
    this.closed = true;
    this.closeReason = reason;
    this.port.removeEventListener?.('disconnect', this._onDisconnectEvent);
    this.serial?.removeEventListener?.('disconnect', this._onDisconnectEvent);
    this._closing = (async () => {
      try {
        await this._reader?.cancel();
      } catch {
        /* ignore */
      }
      try {
        await this._writeChain;
      } catch {
        /* ignore */
      }
      try {
        this._writer?.releaseLock();
      } catch {
        /* ignore */
      }
      this._writer = null;
      try {
        await this._readLoopDone;
      } catch {
        /* ignore */
      }
      if (this.isOpen) {
        try {
          await this.port.close();
        } catch {
          /* the port may already be gone */
        }
      }
      this.isOpen = false;
    })();
    const ev = error ? { reason, error } : { reason };
    for (const cb of [...this._close]) {
      try {
        cb(ev);
      } catch (e) {
        this.onWarning?.(e);
      }
    }
    return this._closing;
  }
}
