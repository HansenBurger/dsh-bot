/**
 * l1 — SQLite short-term context cache (memory architecture §2.1 / §4.3 / §8.3).
 *
 * Engine: `node:sqlite` (built into Node 22, verified present in t4 §1.4). No npm
 * native module, so no toolchain inside the container image.
 *
 * The three rules that make this layer safe to persist at all:
 *   1. **PG is the only authority.** L1 is a disposable cache; anything
 *      inconsistent is rebuilt from PG (`rebuildFromPg`). Deleting l1.db costs 24h
 *      of conversational context, never long-term memory (§8.3).
 *   2. **PII never enters L1.** Enforced twice: here in code and by the SQLite
 *      CHECK on `context_entry.sensitivity`.
 *   3. **Hard capacity ceiling.** `max_page_count` = 64 MiB (measured: page_size
 *      must be set before the first page is written). Hitting it raises
 *      "database or disk is full", which we distinguish from real ENOSPC and
 *      answer by evicting the oldest slots rather than failing the request (§8.5).
 */

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { sqliteDdl } from './migrate.mjs';

const HOUR_MS = 3_600_000;

export class L1Cache {
  /**
   * @param {{path: string, ttlHours?: number, maxPageCount?: number, pageSize?: number}} opts
   */
  constructor(opts) {
    this.path = opts.path;
    this.ttlMs = (opts.ttlHours ?? 24) * HOUR_MS;
    if (opts.path !== ':memory:') {
      mkdirSync(dirname(opts.path), { recursive: true });
    }
    this.db = new DatabaseSync(opts.path);
    // page_size only takes effect before the first page exists, hence DDL-after-pragma order.
    this.db.exec(`PRAGMA journal_mode = WAL`);
    this.db.exec(`PRAGMA synchronous = NORMAL`);
    this.db.exec(`PRAGMA foreign_keys = ON`);
    this.db.exec(`PRAGMA busy_timeout = 5000`);
    this.db.exec(`PRAGMA temp_store = MEMORY`);
    if (opts.pageSize) this.db.exec(`PRAGMA page_size = ${Number(opts.pageSize) | 0}`);
    if (opts.maxPageCount) this.db.exec(`PRAGMA max_page_count = ${Number(opts.maxPageCount) | 0}`);
    this.db.exec(sqliteDdl());
  }

  static now() {
    return Date.now();
  }

  /* ---------------- context slots ---------------- */

  /**
   * @param {{peerKey:string, slot:string, valueJson:string, sensitivity?:string, sourceMsgId?:string}} entry
   * @returns {{accepted: boolean, evictedSlots: number, expiresAt: number}}
   */
  putContext(entry) {
    const sens = entry.sensitivity || 'internal';
    // Rule 2: refuse before the statement even runs, so the reason is explicit.
    if (sens === 'pii' || sens === 'secret') {
      const err = new Error('L1 refuses pii/secret values');
      err.code = 'MEMORY_REFUSED_CATEGORY';
      throw err;
    }
    const now = L1Cache.now();
    const expiresAt = now + this.ttlMs;
    const stmt = this.db.prepare(
      `INSERT INTO context_entry (peer_key, slot, value_json, sensitivity, source_msg_id, hits, created_at, expires_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
       ON CONFLICT (peer_key, slot) DO UPDATE
         SET value_json = excluded.value_json,
             sensitivity = excluded.sensitivity,
             source_msg_id = excluded.source_msg_id,
             hits = context_entry.hits + 1,
             -- refresh the TTL but keep the original creation instant for promotion stats
             expires_at = excluded.expires_at,
             updated_at = excluded.updated_at`,
    );
    let evicted = 0;
    try {
      stmt.run(entry.peerKey, entry.slot, entry.valueJson, sens, entry.sourceMsgId ?? null, now, expiresAt, now);
    } catch (err) {
      // Capacity ceiling vs genuine disk-full: both surface as "database or disk is
      // full". Evicting the oldest rows and retrying once distinguishes them — if it
      // still fails the volume really is out of space and the caller must see it.
      // (Pattern written with escaped slashes: an unescaped `/` in "disk I/O" would
      // terminate the literal and fail the module load.)
      if (!/database or disk is full|disk I\/O error/.test(String(err.message))) throw err;
      evicted = this.evictForCapacity();
      stmt.run(entry.peerKey, entry.slot, entry.valueJson, sens, entry.sourceMsgId ?? null, now, expiresAt, now);
    }
    return { accepted: true, evictedSlots: evicted, expiresAt };
  }

  /**
   * @param {string} peerKey
   * @returns {{exists: boolean, slots: Record<string, any>, turnWindow: any[], ttlRemainingSeconds: number|null, promotedCandidates: number}}
   */
  getContext(peerKey) {
    const now = L1Cache.now();
    const rows = this.db
      .prepare(`SELECT slot, value_json, sensitivity, hits, expires_at FROM context_entry WHERE peer_key = ? AND expires_at > ?`)
      .all(peerKey, now);
    const turns = this.db
      .prepare(`SELECT role, summary, text_hash, created_at FROM turn_window WHERE peer_key = ? AND expires_at > ? ORDER BY created_at DESC LIMIT 20`)
      .all(peerKey, now);
    const promoted = this.db
      .prepare(`SELECT count(*) AS n FROM promotion_candidate WHERE peer_key = ? AND proposed = 0`)
      .get(peerKey);
    const slots = {};
    for (const r of rows) {
      try {
        slots[r.slot] = JSON.parse(r.value_json);
      } catch {
        slots[r.slot] = null; // corrupt cache row: report as absent, never crash a read
      }
    }
    const minExpiry = rows.length ? Math.min(...rows.map((r) => Number(r.expires_at))) : null;
    return {
      exists: rows.length > 0 || turns.length > 0,
      slots,
      turnWindow: turns
        .reverse()
        .map((t) => ({ role: t.role, summary: String(t.summary).slice(0, 200), textHash: t.text_hash })),
      ttlRemainingSeconds: minExpiry === null ? null : Math.max(0, Math.round((minExpiry - now) / 1000)),
      promotedCandidates: Number(promoted?.n ?? 0),
    };
  }

  /** Append one turn summary (never the raw text — L0 owns that). */
  appendTurn({ peerKey, role, summary, textHash, sessionRef, senderUserId, riskTags = '' }) {
    const now = L1Cache.now();
    this.db
      .prepare(
        `INSERT INTO turn_window (peer_key, role, summary, text_hash, session_ref, sender_user_id, risk_tags, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(peerKey, role, String(summary).slice(0, 200), textHash, sessionRef ?? null, senderUserId ?? null, riskTags, now, now + this.ttlMs);
    // Keep the per-peer window bounded so one chatty group cannot crowd out others.
    this.db
      .prepare(
        `DELETE FROM turn_window WHERE peer_key = ? AND turn_id NOT IN (
           SELECT turn_id FROM turn_window WHERE peer_key = ? ORDER BY created_at DESC LIMIT 40)`,
      )
      .run(peerKey, peerKey);
  }

  /**
   * Record an observation for the §2.3 promotion judgement
   * ("stable" requires ≥2 observations OR ≥2 sessions).
   *
   * `session_count` is tracked by storing the distinct session ids that produced
   * this value, comma-joined in `sessions`. Counting them on read keeps the
   * judgement cheap and auditable.
   */
  recordObservation({ peerKey, subjectKey, attrKey, valueHash, sessionId }) {
    const now = L1Cache.now();
    const existing = this.db
      .prepare(`SELECT cand_id, observations, sessions FROM promotion_candidate WHERE subject_key = ? AND attr_key = ? AND value_hash = ?`)
      .get(subjectKey, attrKey, valueHash);
    if (existing) {
      const seen = new Set(String(existing.sessions || '').split(',').filter(Boolean));
      if (sessionId) seen.add(String(sessionId));
      this.db
        .prepare(`UPDATE promotion_candidate SET observations = observations + 1, sessions = ?, last_seen_at = ? WHERE cand_id = ?`)
        .run([...seen].join(','), now, existing.cand_id);
      return { observations: Number(existing.observations) + 1, sessionCount: Math.max(1, seen.size) };
    }
    this.db
      .prepare(
        `INSERT INTO promotion_candidate (peer_key, subject_key, attr_key, value_hash, observations, session_count, sessions, first_seen_at, last_seen_at, proposed)
         VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, 0)`,
      )
      .run(peerKey, subjectKey, attrKey, valueHash, sessionId ? 1 : 1, sessionId ? String(sessionId) : '', now, now);
    return { observations: 1, sessionCount: 1 };
  }

  /** Candidates that satisfy §2.3's conservative bar. */
  qualifiedPromotions(limit = 50) {
    return this.db
      .prepare(
        `SELECT peer_key, subject_key, attr_key, value_hash, observations, session_count, first_seen_at, last_seen_at
           FROM promotion_candidate
          WHERE proposed = 0 AND (observations >= 2 OR session_count >= 2)
          ORDER BY last_seen_at DESC LIMIT ?`,
      )
      .all(Number(limit));
  }

  markProposed(subjectKey, attrKey, valueHash) {
    this.db
      .prepare(`UPDATE promotion_candidate SET proposed = 1, last_seen_at = ? WHERE subject_key = ? AND attr_key = ? AND value_hash = ?`)
      .run(L1Cache.now(), subjectKey, attrKey, valueHash);
  }

  /* ---------------- dedupe window ---------------- */

  /**
   * @returns {{hit: boolean, ref?: string, kind?: string}}
   */
  lookupDedupe(dedupeKey) {
    const row = this.db.prepare(`SELECT memory_kind, memory_ref, hit_count FROM dedupe_window WHERE dedupe_key = ?`).get(dedupeKey);
    if (!row) return { hit: false };
    this.db.prepare(`UPDATE dedupe_window SET hit_count = hit_count + 1, last_seen_at = ? WHERE dedupe_key = ?`).run(L1Cache.now(), dedupeKey);
    return { hit: true, ref: row.memory_ref, kind: row.memory_kind };
  }

  rememberDedupe({ dedupeKey, memoryKind, memoryRef }) {
    const now = L1Cache.now();
    this.db
      .prepare(
        `INSERT INTO dedupe_window (dedupe_key, memory_kind, memory_ref, hit_count, first_seen_at, last_seen_at)
         VALUES (?, ?, ?, 1, ?, ?)
         ON CONFLICT (dedupe_key) DO UPDATE SET last_seen_at = excluded.last_seen_at, hit_count = dedupe_window.hit_count + 1`,
      )
      .run(dedupeKey, memoryKind, memoryRef, now, now);
  }

  forgetDedupe(memoryRef) {
    this.db.prepare(`DELETE FROM dedupe_window WHERE memory_ref = ?`).run(memoryRef);
  }

  /* ---------------- maintenance ---------------- */

  /**
   * TTL eviction + WAL checkpoint. Called hourly by the job scheduler (M-08).
   * ⚠ VACUUM cannot run inside a transaction; node:sqlite has no implicit
   * transaction around exec(), so the checkpoint below is safe but a future
   * refactor must keep it outside any BEGIN.
   */
  evictExpired() {
    const now = L1Cache.now();
    let deleted = 0;
    for (const table of ['context_entry', 'turn_window']) {
      const r = this.db.prepare(`DELETE FROM ${table} WHERE expires_at < ?`).run(now);
      deleted += Number(r.changes ?? 0);
    }
    // 7-day message-dedupe window (arch §5.2 idempotency note)
    const dd = this.db.prepare(`DELETE FROM dedupe_window WHERE last_seen_at < ?`).run(now - 7 * 24 * HOUR_MS);
    deleted += Number(dd.changes ?? 0);
    // Promotion candidates older than the TTL are noise: their evidence is gone.
    const pc = this.db.prepare(`DELETE FROM promotion_candidate WHERE proposed = 0 AND last_seen_at < ?`).run(now - this.ttlMs);
    deleted += Number(pc.changes ?? 0);
    try {
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch {
      /* checkpoint is best-effort */
    }
    return deleted;
  }

  /** Free room by dropping the oldest expired-then-oldest rows; returns count removed. */
  evictForCapacity(maxRemoval = 200) {
    const now = L1Cache.now();
    const expired = this.db.prepare(`DELETE FROM context_entry WHERE expires_at < ?`).run(now);
    let removed = Number(expired.changes ?? 0);
    if (removed === 0) {
      const oldest = this.db
        .prepare(`DELETE FROM context_entry WHERE rowid IN (
            SELECT rowid FROM context_entry ORDER BY updated_at ASC LIMIT ?)`)
        .run(Number(maxRemoval));
      removed += Number(oldest.changes ?? 0);
    }
    return removed;
  }

  /** Health facts for /healthz (page-cap percentage is the capacity alarm, §8.5). */
  health() {
    // node:sqlite exposes pragmas only as `PRAGMA name` statements (or the
    // `select * from pragma_x()` table form) — `SELECT page_count()` is not a SQL
    // function and throws "no such function".
    const read = (name) => Number(this.db.prepare(`PRAGMA ${name}`).get()?.[name] ?? 0);
    const pages = read('page_count');
    const size = read('page_size') || 4096;
    const cap = read('max_page_count') || 16384;
    let integrity = 'ok';
    try {
      integrity = String(this.db.prepare('PRAGMA integrity_check').get()?.integrity_check ?? 'ok');
    } catch (err) {
      integrity = `error:${String(err.message).slice(0, 40)}`;
    }
    return {
      up: integrity === 'ok',
      integrity,
      dbBytes: pages * size,
      pageCapPct: cap > 0 ? Number(((pages / cap) * 100).toFixed(2)) : 0,
    };
  }

  /**
   * §8.3: on startup, drop cache rows whose PG-side projection already expired —
   * PG is authoritative, so anything it does not confirm gets discarded.
   * @param {(peerKeys:string[])=>Promise<Set<string>>} livePeerProvider
   */
  async rebuildFromPg(livePeerProvider) {
    const peers = this.db.prepare(`SELECT DISTINCT peer_key FROM context_entry`).all().map((r) => r.peer_key);
    if (peers.length === 0) return { cleared: 0, checked: 0 };
    const live = await livePeerProvider(peers);
    let cleared = 0;
    for (const peer of peers) {
      if (live.has(peer)) continue;
      this.db.prepare(`DELETE FROM context_entry WHERE peer_key = ?`).run(peer);
      this.db.prepare(`DELETE FROM turn_window WHERE peer_key = ?`).run(peer);
      cleared += 1;
    }
    return { cleared, checked: peers.length };
  }

  close() {
    try {
      this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } catch {
      /* ignore */
    }
    this.db.close();
  }
}
