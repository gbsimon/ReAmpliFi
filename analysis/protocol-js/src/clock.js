// Injectable time source. Every timer in the library goes through a "clock" object so tests
// (and the mock) can run deterministically with FakeClock instead of wall time.
//
// Clock interface: { now(): ms, setTimeout(fn, ms): id, clearTimeout(id),
//                    setInterval(fn, ms): id, clearInterval(id) }

/** Wall-clock implementation (browser or Node). */
export const realClock = Object.freeze({
  now: () => Date.now(),
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (id) => globalThis.clearTimeout(id),
  setInterval: (fn, ms) => globalThis.setInterval(fn, ms),
  clearInterval: (id) => globalThis.clearInterval(id),
});

/**
 * Deterministic virtual clock. Timers only fire when you advance time.
 *
 *   const clock = new FakeClock();
 *   await clock.runUntil(session.connect());   // advances virtual time until the promise settles
 *   await clock.advance(1000);                 // run all timers due in the next second
 */
export class FakeClock {
  constructor(startMs = 0) {
    this._now = startMs;
    this._nextId = 1;
    /** @type {Map<number, {due:number, fn:Function, interval:number|null, order:number}>} */
    this._timers = new Map();
    this._order = 0;
  }

  now() {
    return this._now;
  }

  setTimeout(fn, ms = 0) {
    const id = this._nextId++;
    this._timers.set(id, { due: this._now + Math.max(0, ms), fn, interval: null, order: this._order++ });
    return id;
  }

  clearTimeout(id) {
    this._timers.delete(id);
  }

  setInterval(fn, ms) {
    const id = this._nextId++;
    const iv = Math.max(1, ms);
    this._timers.set(id, { due: this._now + iv, fn, interval: iv, order: this._order++ });
    return id;
  }

  clearInterval(id) {
    this._timers.delete(id);
  }

  /** Number of pending timers (useful for leak checks in tests). */
  get pendingTimers() {
    return this._timers.size;
  }

  _nextTimer() {
    let best = null;
    let bestId = null;
    for (const [id, t] of this._timers) {
      if (!best || t.due < best.due || (t.due === best.due && t.order < best.order)) {
        best = t;
        bestId = id;
      }
    }
    return best ? { id: bestId, t: best } : null;
  }

  /** Let pending promise continuations run (microtasks only, no wall-clock wait). */
  async flush(rounds = 50) {
    for (let i = 0; i < rounds; i++) await Promise.resolve();
  }

  /** Fire exactly one due timer (the earliest one at or before `limit`). Returns false if none. */
  async _fireOne(limit) {
    const next = this._nextTimer();
    if (!next || next.t.due > limit) return false;
    const { id, t } = next;
    this._now = Math.max(this._now, t.due);
    if (t.interval != null) {
      t.due += t.interval;
      t.order = this._order++;
    } else {
      this._timers.delete(id);
    }
    t.fn();
    await this.flush();
    return true;
  }

  /** Advance virtual time by `ms`, firing every timer that falls due, in order. */
  async advance(ms) {
    const target = this._now + ms;
    await this.flush();
    while (await this._fireOne(target)) {
      /* keep going */
    }
    this._now = target;
    await this.flush();
  }

  /**
   * Advance virtual time until `promise` settles; returns its value (or throws its error).
   * Throws if `maxMs` of virtual time pass first, or if no timer is left to make progress.
   */
  async runUntil(promise, { maxMs = 120_000 } = {}) {
    let settled = false;
    let value;
    let error;
    let failed = false;
    promise.then(
      (v) => {
        settled = true;
        value = v;
      },
      (e) => {
        settled = true;
        failed = true;
        error = e;
      },
    );
    const deadline = this._now + maxMs;
    await this.flush();
    while (!settled) {
      const next = this._nextTimer();
      if (!next) throw new Error('FakeClock.runUntil: no pending timers and promise not settled (deadlock)');
      if (next.t.due > deadline) throw new Error(`FakeClock.runUntil: promise not settled within ${maxMs} ms of virtual time`);
      await this._fireOne(deadline);
    }
    if (failed) throw error;
    return value;
  }
}
