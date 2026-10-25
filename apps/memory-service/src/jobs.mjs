/**
 * jobs — in-process retention scheduler (t4 §8.1 / §4.3, acceptance M-08 / M-19).
 *
 * Why in-process and not pg_cron: the host PG is a **shared** instance and
 * `pg_cron` is not installed there; installing an extension into someone else's
 * production cluster for our benefit is not this project's call (t4 §8.1). The cost
 * is that a stopped service stops its own cleanup, which is exactly why every run
 * lands in `companion.job_run` and the watcher alarms on a heartbeat older than the
 * interval (M-19).
 *
 * Failure policy: a job error is recorded and logged, never thrown into a timer —
 * an uncaught exception inside setInterval kills the whole service (TM-012 class).
 */

const HOUR_MS = 3_600_000;

export class JobScheduler {
  /**
   * @param {{repo: import('./repository.mjs').MemoryRepository, cache?: import('./cache.mjs').MemoryCache, l1: import('./l1.mjs').L1Cache, pg: import('./pg.mjs').PgAccess, config: object, audit?: {emit:(t:string,f:object)=>void}} } deps
   */
  constructor(deps) {
    this.repo = deps.repo;
    this.cache = deps.cache || null;
    this.l1 = deps.l1;
    this.pg = deps.pg;
    this.config = deps.config;
    this.audit = deps.audit || null;
    this.timers = [];
    this.lastRun = new Map();
    // `status` must not be an instance field: a Map assigned to `this.status` shadows
    // the `status()` method that /healthz calls, and the job list silently disappeared.
    this.statusByJob = new Map();
  }

  definitions() {
    const j = this.config.jobs || {};
    return [
      { name: 'l1_evict', everyMs: (j.l1EvictIntervalMinutes ?? 60) * 60_000, run: () => this.runL1Evict() },
      { name: 'purge_expired', everyMs: (j.purgeIntervalMinutes ?? 1440) * 60_000, run: () => this.runPurgeExpired() },
      { name: 'prune_access_log', everyMs: 7 * 24 * HOUR_MS, run: () => this.runPruneAccessLog() },
      { name: 'cache_backup', everyMs: 24 * HOUR_MS, run: () => this.runCacheBackup() },
    ];
  }

  start() {
    for (const def of this.definitions()) {
      if (!def.everyMs || def.everyMs <= 0) continue;
      const timer = setInterval(() => {
        this.#guarded(def).catch(() => {});
      }, def.everyMs);
      // A Node timer must never be the reason the process refuses to exit.
      timer.unref?.();
      this.timers.push(timer);
    }
    return this;
  }

  stop() {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
  }

  async #guarded(def) {
    const started = Date.now();
    try {
      const result = await def.run();
      this.lastRun.set(def.name, { at: Date.now(), ok: true, result });
      this.statusByJob.set(def.name, { ok: true, ms: Date.now() - started, result });
      return { ok: true, job: def.name, ms: Date.now() - started, result };
    } catch (err) {
      this.lastRun.set(def.name, { at: Date.now(), ok: false, error: String(err.message).slice(0, 120) });
      this.statusByJob.set(def.name, { ok: false, ms: Date.now() - started, error: String(err.message).slice(0, 120) });
      this.audit?.emit('sandbox.denied', { stage: 'job', job: def.name, message: String(err.message).slice(0, 120) });
      process.stderr.write(`${JSON.stringify({ ts: Date.now(), type: 'sandbox.denied', service: 'memory-service', job: def.name, result: 'error', message: String(err.message).slice(0, 120) })}\n`);
      return { ok: false, job: def.name, error: 'job failed' };
    }
  }

  /** Manual trigger from the admin port (M-19 rehearsal). */
  async runNow(name) {
    const def = this.definitions().find((d) => d.name === name);
    if (!def) return { ok: false, job: name, error: 'unknown job' };
    return this.#guarded(def);
  }

  status() {
    return [...this.statusByJob.entries()].map(([job, v]) => ({ job, ok: v.ok, ms: v.ms, result: v.result ?? null, error: v.error ?? null }));
  }

  /** Heartbeat rows for /healthz (M-19: `purge_expired` must be <26 h old). */
  heartbeat() {
    return [...this.lastRun.entries()].map(([job, v]) => ({
      job,
      at: new Date(v.at).toISOString(),
      ageSeconds: Math.round((Date.now() - v.at) / 1000),
      ok: v.ok,
    }));
  }

  /* ---------------- individual jobs ---------------- */

  /** L1 TTL eviction + read-cache expiry (M-08). */
  async runL1Evict() {
    const l1Deleted = this.l1.evictExpired();
    const cacheDeleted = this.cache ? this.cache.evictExpired() : 0;
    return { l1Deleted, cacheDeleted };
  }

  /**
   * L3 expiry purge. `companion.purge_expired()` is the only maintenance function
   * granted to the rw role (t4 §5.4: everything else stays service-side), and it
   * writes its own tombstones + job_run row.
   */
  async runPurgeExpired() {
    const { rows } = await this.pg.query('rw', `SELECT companion.purge_expired($1) AS n`, [
      Number(this.config.jobs?.purgeBatchSize ?? 5000),
    ]);
    return { purged: Number(rows[0]?.n ?? 0) };
  }

  /** Audit retention (t4 §5.7: floor 90 days — the DB function enforces it). */
  async runPruneAccessLog() {
    const keepDays = Number(this.config.jobs?.pruneAccessKeepDays ?? 365);
    const { rows } = await this.pg.query('rw', `SELECT companion.prune_access_log($1) AS n`, [keepDays]);
    return { pruned: Number(rows[0]?.n ?? 0), keepDays };
  }

  /** §8.4 online cache snapshot; disabled by default. */
  async runCacheBackup() {
    if (!this.config.backup?.enabled || !this.cache) return { skipped: true };
    const { mkdirSync } = await import('node:fs');
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const file = `${this.config.backup.dir}/l1-${stamp}.sqlite`;
    mkdirSync(this.config.backup.dir, { recursive: true });
    this.cache.backupTo(file);
    const { readdirSync, unlinkSync, statSync } = await import('node:fs');
    const files = readdirSync(this.config.backup.dir)
      .filter((f) => f.startsWith('l1-') && f.endsWith('.sqlite'))
      .sort();
    let removed = 0;
    while (files.length > this.config.backup.keep) {
      const old = files.shift();
      try {
        unlinkSync(`${this.config.backup.dir}/${old}`);
        removed += 1;
      } catch {
        /* best effort: a stuck backup must not break the service */
      }
    }
    return { file, bytes: statSync(file).size, removed };
  }
}
