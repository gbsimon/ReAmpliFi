// Tiny event emitter (works in browsers and Node; no dependency on EventTarget semantics).

export class Emitter {
  constructor() {
    /** @type {Map<string, Set<Function>>} */
    this._listeners = new Map();
  }

  /**
   * Subscribe. Returns an unsubscribe function.
   * @param {string} event
   * @param {(data:any)=>void} fn
   */
  on(event, fn) {
    if (!this._listeners.has(event)) this._listeners.set(event, new Set());
    this._listeners.get(event).add(fn);
    return () => this.off(event, fn);
  }

  /** Subscribe for a single emission. */
  once(event, fn) {
    const off = this.on(event, (d) => {
      off();
      fn(d);
    });
    return off;
  }

  off(event, fn) {
    this._listeners.get(event)?.delete(fn);
  }

  /**
   * Emit to all listeners. A throwing listener does not break protocol processing: the error
   * is re-thrown asynchronously (like EventTarget does).
   */
  emit(event, data) {
    const set = this._listeners.get(event);
    if (!set) return;
    for (const fn of [...set]) {
      try {
        fn(data);
      } catch (e) {
        queueMicrotask(() => {
          throw e;
        });
      }
    }
  }

  /** Promise for the next emission of `event`. */
  waitFor(event) {
    return new Promise((resolve) => this.once(event, resolve));
  }
}
