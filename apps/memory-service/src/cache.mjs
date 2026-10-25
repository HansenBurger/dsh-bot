/**
 * cache — SQLite read-through projection of the PG authority (t4 §2.1 / §4.2 / §8.3).
 *
 * Task requirement: "写入时双写（PG + SQLite），读取先查 SQLite miss 再查 PG 并回填".
 * PG stays the only authority; this layer is an accelerator, so every rule here is
 * "when in doubt, don't cache":
 *
 *   1. **Encrypted rows are never cached with plaintext.** A pii/secret body would
 *      turn the L1 volume into a second copy of what §5.2 works to protect, so only
 *      rows whose PG-side value lives in `*_plain` get a cache entry (M-03 invariant).
 *   2. **visibility='admin' rows are never cached at all** — they are readable only
 *      through the owner CLI path, and a disk copy would make "invisible" readable.
 *   3. **Generation invalidation.** Every write/forget bumps `cache_meta.generation`;
 *      reads filter on the stored generation, so a stale projection can never be
 *      returned as current truth (§8.3 "PG 与缓存的一致性").
 *   4. **ACL is re-checked on cache hits.** The cached row carries visibility +
 *      peer_key, and `repository.assertVisible` runs identically for hit and miss —
 *      otherwise the cache would become an ACL bypass (M-15).
 *
 * Search caching stores *identifiers only* (memory ids + truncation flag), never
 * bodies, so a leaked volume yields no conversational content by itself.
 */

const HOUR_MS = 3_600_000;

export class MemoryCache {
  /**
   * @param {{l1: import('./l1.mjs').L1Cache, ddl: string, searchTtlMs?: number, maxRows?: number}} opts
   */
  constructor(opts) {
    this.db = opts.l1.db;
    this.searchTtlMs = opts.searchTtlMs ?? 60_000;
    this.maxRows = opts.maxRows ?? 5000;
    this.db.exec(opts.ddl);
    this._generation = null;
  }

  /* ---------------- generation ---------------- */

  generation() {
    if (this._generation === null) {
      const row = this.db.prepare(`SELECT value FROM cache_meta WHERE key = 'generation'`).get();
      this._generation = Number(row?.value ?? 1) || 1;
    }
    return this._generation;
  }

  bumpGeneration() {
    const next = this.generation() + 1;
    this.db.prepare(`INSERT INTO cache_meta (key, value) VALUES ('generation', ?)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value`).run(String(next));
    this._generation = next;
    // Every search projection is now stale by definition — drop them in one statement
    // rather than leaving rows that can only be rejected at read time.
    this.db.prepare(`DELETE FROM search_cache`).run();
    return next;
  }

  /* ---------------- row cache ---------------- */

  /** @returns {boolean} whether the row was eligible for caching */
  put(memory) {
    if (!memory?.memoryId) return false;
    if (memory.sensitivity === 'pii' || memory.sensitivity === 'secret') return false;
    if (memory.visibility === 'admin') return false;
    if (typeof memory.body !== 'string') return false;
    const now = Date.now();
    this.db
      .prepare(
        `INSERT INTO memory_cache
           (memory_id, kind, class, subject_key, peer_key, visibility, sensitivity, body,
            encrypted, occurred_at, expires_at, generation, cached_at, hits)
         VALUES (?,?,?,?,?,?,?,?,0,?,?,?,?,0)
         ON CONFLICT(memory_id) DO UPDATE SET
           body = excluded.body, class = excluded.class, peer_key = excluded.peer_key,
           visibility = excluded.visibility, sensitivity = excluded.sensitivity,
           occurred_at = excluded.occurred_at, expires_at = excluded.expires_at,
           generation = excluded.generation, cached_at = excluded.cached_at`,
      )
      .run(
        memory.memoryId,
        memory.kind,
        memory.class,
        memory.subjectId ?? null,
        memory.peerKey ?? null,
        memory.visibility,
        memory.sensitivity,
        memory.body,
        memory.occurredAt ?? null,
        memory.expiresAt ? Date.parse(memory.expiresAt) : null,
        this.generation(),
        now,
      );
    this.#pruneIfNeeded();
    return true;
  }

  /**
   * @returns {object|null} a memory-shaped object, or null on miss/expiry/staleness
   */
  get(memoryId) {
    const now = Date.now();
    const row = this.db
      .prepare(
        `SELECT * FROM memory_cache
          WHERE memory_id = ? AND generation = ?
            AND (expires_at IS NULL OR expires_at > ?)`,
      )
      .get(memoryId, this.generation(), now);
    if (!row) return null;
    this.db.prepare(`UPDATE memory_cache SET hits = hits + 1 WHERE memory_id = ?`).run(memoryId);
    return {
      memoryId: row.memory_id,
      kind: row.kind,
      subjectId: row.subject_key,
      peerKey: row.peer_key,
      class: row.class,
      body: row.body,
      sensitivity: row.sensitivity,
      visibility: row.visibility,
      occurredAt: row.occurred_at,
      expiresAt: row.expires_at ? new Date(Number(row.expires_at)).toISOString() : null,
      hitCount: Number(row.hits ?? 0),
      confidence: 1,
      riskTags: [],
      provenance: { sourceChannel: null, sourceRef: null, createdByIdentity: row.subject_key ?? null },
      cacheHit: true,
    };
  }

  invalidate(memoryId) {
    const r = this.db.prepare(`DELETE FROM memory_cache WHERE memory_id = ?`).run(memoryId);
    return Number(r.changes ?? 0);
  }

  /* ---------------- search projection ---------------- */

  /**
   * @param {string} key
   * @returns {{memoryIds: string[], truncated: boolean, strategy: object}|null}
   */
  lookupSearch(key) {
    const now = Date.now();
    const row = this.db
      .prepare(`SELECT * FROM search_cache WHERE cache_key = ? AND generation = ? AND expires_at > ?`)
      .get(key, this.generation(), now);
    if (!row) return null;
    let strategy = {};
    try {
      strategy = JSON.parse(String(row.meta_json || '{}'));
    } catch {
      strategy = {}; // a corrupt projection degrades to "no strategy stats", never a 500
    }
    return { memoryIds: String(row.memory_ids).split(',').filter(Boolean), truncated: Boolean(row.truncated), strategy };
  }

  /**
   * @param {string} key
   * @param {string[]} memoryIds
   * @param {boolean} truncated
   * @param {object} strategy
   * @param {number} [expectedGeneration] - refuse the store when a write bumped the
   *        generation between the PG query and now. Without this guard a search
   *        could publish a projection of pre-write data under the post-write tag.
   */
  putSearch(key, memoryIds, truncated = false, strategy = {}, expectedGeneration = null) {
    const now = Date.now();
    if (expectedGeneration !== null && this.generation() !== expectedGeneration) return false;
    this.db
      .prepare(
        `INSERT INTO search_cache (cache_key, generation, memory_ids, meta_json, truncated, created_at, expires_at)
         VALUES (?,?,?,?,?,?,?)
         ON CONFLICT(cache_key) DO UPDATE SET
           generation = excluded.generation, memory_ids = excluded.memory_ids,
           meta_json = excluded.meta_json,
           truncated = excluded.truncated, created_at = excluded.created_at, expires_at = excluded.expires_at`,
      )
      .run(key, this.generation(), memoryIds.join(','), JSON.stringify(strategy || {}), truncated ? 1 : 0, now, now + this.searchTtlMs);
    return true;
  }

  /* ---------------- maintenance ---------------- */

  evictExpired() {
    const now = Date.now();
    const a = this.db.prepare(`DELETE FROM memory_cache WHERE expires_at IS NOT NULL AND expires_at < ?`).run(now);
    const b = this.db.prepare(`DELETE FROM search_cache WHERE expires_at < ?`).run(now);
    // Stale-generation rows are invisible to reads forever, so they are pure garbage.
    const g = this.db.prepare(`DELETE FROM memory_cache WHERE generation <> ?`).run(this.generation());
    return Number(a.changes ?? 0) + Number(b.changes ?? 0) + Number(g.changes ?? 0);
  }

  /** Drop the least-recently-refreshed rows when the cache outgrows its budget (§8.5). */
  #pruneIfNeeded() {
    const count = Number(this.db.prepare(`SELECT count(*) AS n FROM memory_cache`).get()?.n ?? 0);
    if (count <= this.maxRows) return 0;
    const r = this.db
      .prepare(
        `DELETE FROM memory_cache WHERE memory_id IN (
           SELECT memory_id FROM memory_cache ORDER BY cached_at ASC LIMIT ?)`,
      )
      .run(count - this.maxRows);
    return Number(r.changes ?? 0);
  }

  stats() {
    const rows = Number(this.db.prepare(`SELECT count(*) AS n FROM memory_cache`).get()?.n ?? 0);
    const hits = Number(this.db.prepare(`SELECT COALESCE(sum(hits),0) AS n FROM memory_cache`).get()?.n ?? 0);
    const queries = Number(this.db.prepare(`SELECT count(*) AS n FROM search_cache`).get()?.n ?? 0);
    return { rows, hits, queries, generation: this.generation(), searchTtlMs: this.searchTtlMs, maxRows: this.maxRows };
  }

  /** §8.4: online backup to a file (called by the retention job, never by the agent). */
  backupTo(path) {
    this.db.exec(`PRAGMA wal_checkpoint(TRUNCATE)`);
    this.db.exec(`VACUUM INTO '${String(path).replace(/'/g, "''")}'`);
    return path;
  }

  static HOUR_MS = HOUR_MS;
}
