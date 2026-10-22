// Tiny in-memory sliding-window rate limiter. Nothing here is ever persisted.

export class RateLimiter {
  constructor() {
    this.entries = new Map(); // key -> { times: number[], windowMs }
    this.timer = setInterval(() => this.sweep(), 60_000);
    this.timer.unref();
  }

  #prune(key, windowMs) {
    const now = Date.now();
    const e = this.entries.get(key) ?? { times: [], windowMs };
    e.windowMs = Math.max(e.windowMs, windowMs);
    e.times = e.times.filter((t) => now - t < windowMs);
    this.entries.set(key, e);
    return e;
  }

  /** How many events were recorded for `key` inside the window. */
  count(key, windowMs) {
    return this.#prune(key, windowMs).times.length;
  }

  /** Record one event. */
  add(key, windowMs) {
    this.#prune(key, windowMs).times.push(Date.now());
  }

  /** Record an event unless the limit is already reached. Returns true if allowed. */
  take(key, max, windowMs) {
    const e = this.#prune(key, windowMs);
    if (e.times.length >= max) return false;
    e.times.push(Date.now());
    return true;
  }

  sweep() {
    const now = Date.now();
    for (const [key, e] of this.entries) {
      const last = e.times[e.times.length - 1];
      if (last === undefined || now - last > e.windowMs) this.entries.delete(key);
    }
  }

  stop() {
    clearInterval(this.timer);
  }
}
