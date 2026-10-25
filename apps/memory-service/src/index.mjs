/**
 * index — memory-service process entry (t4 §9.1 / task t5).
 *
 * Startup order is a security decision, not a convenience one:
 *
 *   1. resolve config; every secret arrives as an `opaque-ref:` and is resolved via
 *      the broker or a mounted file — never from a literal env value (D1/M-13);
 *   2. open SQLite L1 on the named volume (M-09: not tmpfs);
 *   3. optionally run the PG schema migration **at container start** (task
 *      requirement). The provisioning credential is only ever used here, so a
 *      long-lived pool can never hold a superuser-capable connection;
 *   4. connect the rw/ro pools (5 + 5 = 10, the agreed host-PG courtesy ceiling);
 *   5. bind 8091 (internal, HMAC-only) and 127.0.0.1:8190 (admin plane).
 *
 * Fail-closed: an unresolved secret, a failed migration, or a missing KEK aborts the
 * boot. A half-migrated schema serving writes is exactly the drift t4 §8.6 forbids.
 */

import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { AuditSink } from '@dsh-bot/bot-audit';
import { loadConfig } from './config.mjs';
import { L1Cache } from './l1.mjs';
import { MemoryCache } from './cache.mjs';
import { PgAccess } from './pg.mjs';
import { MemoryRepository } from './repository.mjs';
import { MemoryHttp } from './http.mjs';
import { JobScheduler } from './jobs.mjs';
import { runPgMigrations, sqliteCacheDdl } from './migrate.mjs';

const log = (obj) => process.stderr.write(`${JSON.stringify({ ts: Date.now(), service: 'memory-service', ...obj })}\n`);

/**
 * Build a running service. Split from `main()` so tests can boot the exact same
 * wiring against a throwaway PG without touching the host instance.
 * @param {{env?: Record<string,string|undefined>, allowLiterals?: boolean, runMigrations?: boolean}} [opts]
 */
export async function createService(opts = {}) {
  const env = opts.env ?? process.env;
  const config = await loadConfig({ env, literalAllowed: opts.allowLiterals ?? false });
  const audit = new AuditSink({ path: config.auditSink, service: 'memory-service' });

  if (!config.hmacSecret) throw new Error('MEM_HMAC_SECRET unresolved — every request would fail signature verification');
  if (!config.kek) throw new Error('memory KEK unresolved — encrypted fields would be written unreadable');
  if (!config.pg.rw.password || !config.pg.ro.password) throw new Error('PG credentials unresolved');

  mkdirSync(dirname(config.l1.path), { recursive: true });
  mkdirSync(dirname(config.auditSink), { recursive: true });

  const l1 = new L1Cache({
    path: config.l1.path,
    ttlHours: config.l1.ttlHours,
    pageSize: 4096,
    maxPageCount: Math.round((config.l1.maxMb * 1024 * 1024) / 4096),
  });
  const cache = config.cache.enabled ? new MemoryCache({ l1, ddl: sqliteCacheDdl(), searchTtlMs: config.cache.searchTtlMs, maxRows: config.cache.maxRows }) : null;

  // --- step 3: schema migration at start (task requirement), when granted ---
  let migration = { applied: [], skipped: true, detail: 'provisioning credential not configured' };
  const shouldMigrate = opts.runMigrations ?? config.runMigrationsOnStart;
  if (shouldMigrate) {
    if (!config.provisioning) throw new Error('MEM_RUN_MIGRATIONS is set but MEM_PG_PROVISIONING_REF is not — refusing to start without a schema guarantee');
    migration = await runPgMigrations({
      psqlBin: config.psqlBin,
      socketPath: config.pg.socketPath,
      host: config.pg.host,
      port: config.pg.port,
      database: config.pg.database,
      superuser: config.provisioning,
      passwords: { rw: config.pg.rw.password, ro: config.pg.ro.password },
      createDatabase: true,
    });
    log({ type: 'config.change', event: 'migration', detail: migration.detail, applied: migration.applied });
  }

  const pg = new PgAccess({ ...config.pg, statementTimeoutMs: config.pg.statementTimeoutMs });
  const repo = new MemoryRepository({ pg, l1, cache, audit, config: { ...config.limits, kek: config.kek } });
  const jobs = new JobScheduler({ repo, cache, l1, pg, config, audit }).start();
  const http = new MemoryHttp({ repo, config, jobs, audit });

  const internal = http.createInternalServer();
  const admin = http.createAdminServer({ startedAt: Date.now() });
  await listen(internal, config.internalPort, config.bind);
  await listen(admin, config.adminPort, '127.0.0.1');

  log({
    type: 'config.change',
    event: 'ready',
    internal: `${config.bind}:${config.internalPort}`,
    admin: `127.0.0.1:${config.adminPort}`,
    pg: { host: config.pg.socketPath || config.pg.host, database: config.pg.database, poolTotal: config.pg.poolTotal },
    l1: { path: config.l1.path, cache: cache ? 'on' : 'off' },
    // Refs only (D5): resolved material never appears in a log line.
    secretRefs: Object.keys(config.refFields || {}),
  });

  const close = async () => {
    jobs.stop();
    await Promise.allSettled([new Promise((r) => internal.close(r)), new Promise((r) => admin.close(r))]);
    await pg.close();
    l1.close();
  };

  return { config, audit, l1, cache, pg, repo, jobs, http, internal, admin, close, migration };
}

function listen(server, port, host) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
}

async function main() {
  let svc;
  try {
    svc = await createService();
  } catch (err) {
    // Startup failures are written to stdout because the entry script is PID 1 and
    // the compose healthcheck must see them (`docker compose logs` shows both).
    process.stdout.write(`memory-service: FATAL ${String(err.message).slice(0, 200)}\n`);
    process.exitCode = 1;
    return;
  }
  const shutdown = async (signal) => {
    log({ type: 'config.change', event: 'shutdown', signal });
    try {
      await svc.close();
    } catch (err) {
      log({ type: 'sandbox.denied', event: 'shutdown', message: String(err.message).slice(0, 120) });
    }
    process.exit(0);
  };
  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
  process.on('unhandledRejection', (err) => {
    // Never serialise the error object: a PG driver error can carry the DSN (D5).
    log({ type: 'sandbox.denied', event: 'unhandledRejection', message: String(err?.message ?? 'rejection').slice(0, 120) });
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  await main();
}
