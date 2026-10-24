/**
 * lru — insertion-ordered bounded set.
 *
 * Node's Map preserves insertion order, so "oldest first" eviction is one `next()`
 * call; the cost is O(1) amortised and, crucially, **no unbounded growth**: a gateway
 * that keys memory to message volume is an outage waiting for one flood (TM-012).
 */

export class LruSet {
  constructor(max = 4096) {
    this.max = Math.max(1, Number(max) || 4096);
    this.map = new Map();
    this.evictions = 0;
  }

  has(key) {
    return this.map.has(key);
  }

  add(key) {
    if (this.map.has(key)) {
      // Refresh recency without growing the map.
      this.map.delete(key);
    }
    this.map.set(key, true);
    while (this.map.size > this.max) {
      const oldest = this.map.keys().next().value;
      this.map.delete(oldest);
      this.evictions += 1;
    }
    return this;
  }

  get size() {
    return this.map.size;
  }

  stats() {
    return { size: this.map.size, max: this.max, evictions: this.evictions };
  }
}
