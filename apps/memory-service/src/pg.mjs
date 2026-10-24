/**
 * pg — Host PostgreSQL access for the companion memory service.
 *
 * Two pools, matching the rw/ro split the design requires (t4 §3.2 / M-02):
 *   - `rw` is used by write/delete paths only
 *   - `ro` is used by every read/search path
 * A compromised read-only credential therefore cannot erase or poison anything,
 * and a bug in the search code can never accidentally mutate authority data.
 *
 * Pool sizing (task requirement "max=10"): `MAX_POOL_SIZE` defaults to 5 per
 * role → 10 connections total, which also stays under the roles'
 * `CONNECTION LIMIT 8`. The limit is deliberate: host PG is a shared instance
 * (t4 R-3) and long-lived idle sockets are exactly what starves neighbours.
 */

import pgPkg from 'pg';

const { Pool } = pgPkg;

/**
 * @param {{host?:string, socketPath?:string, port:number, database:string, user:string, password:string, max:number, statementTimeoutMs?:number, applicationName:string}} cfg
 */
function makePool(cfg) {
  const pool = new Pool({
    // Two physically different hops, one config shape:
    //   - `socketPath` (t4 §9.3 方案 B) — the host PG listens on 127.0.0.1 only and
    //     is measurably unreachable from an `internal: true` network over TCP, so the
    //     shipped compose stack mounts the unix socket instead of pretending
    //     host.docker.internal works.
    //   - host/port (方案 A) — kept for a host that deliberately listens on the
    //     docker bridge.
    // Measured on node-postgres 8.x: `socketPath` alone is silently ignored and the
    // client falls back to TCP localhost. The libpq convention — `host` set to the
    // socket *directory* — is what actually connects over the unix socket, so that is
    // the shape used here.
    ...(cfg.socketPath
      ? { host: cfg.socketPath }
      : { host: cfg.host || 'host.docker.internal', port: Number(cfg.port) || 5432 }),
    database: cfg.database,
    user: cfg.user,
    password: cfg.password,
    max: cfg.max,
    // Never let a runaway query hold a slot on a shared instance (t4 R-3).
    // ⚠ node-postgres reads pool *connection* parameters (camelCase) — `statement_timeout`
    //   here is ignored (measured: SET statement_timeout = -1). Passing it as a raw
    //   `options` string is what actually reaches the server.
    options: `-c statement_timeout=${cfg.statementTimeoutMs ?? 8000} -c idle_in_transaction_session_timeout=${cfg.statementTimeoutMs ?? 8000}`,
    idleTimeoutMillis: 30_000,
    connectionTimeoutMillis: 5_000,
    application_name: cfg.applicationName,
    // Loopback / unix-socket hop inside one VM: sslmode=disable per t4 §9.5.
    ssl: false,
    // Statement-level protection also needs a per-client keep of the same GUC.
    statement_timeout: cfg.statementTimeoutMs ?? 8000,
  });
  // A dropped socket must not kill the process; pg emits 'error' on idle clients.
  pool.on('error', (err) => {
    process.stderr.write(`${JSON.stringify({ ts: Date.now(), type: 'credential.resolve', service: 'memory-service', result: 'error', pool: cfg.applicationName, message: String(err.message).slice(0, 160) })}\n`);
  });
  return pool;
}

export class PgAccess {
  constructor(config) {
    this.config = config;
    // `config.rw` carries only user/password; host/port/socketPath/statementTimeout
    // live on the parent, so the spread order below is what makes them reach pg.
    this.rw = makePool({ ...config, ...config.rw, max: config.maxPerRole, applicationName: 'dshbot-memory-rw' });
    this.ro = makePool({ ...config, ...config.ro, max: config.maxPerRole, applicationName: 'dshbot-memory-ro' });
    // Task ceiling: 5 per role × 2 roles = 10 host-PG connections, and the roles
    // themselves are created with CONNECTION LIMIT 8 by 002_roles.sql.
    this.poolTotal = config.maxPerRole * 2;
  }

  /**
   * Run a parameterized query.
   * @param {'rw'|'ro'} role
   * @param {string} sql
   * @param {any[]} [params]
   */
  async query(role, sql, params = []) {
    const pool = role === 'rw' ? this.rw : this.ro;
    return pool.query(sql, params);
  }

  async withClient(role, fn) {
    const pool = role === 'rw' ? this.rw : this.ro;
    const client = await pool.connect();
    try {
      return await fn(client);
    } finally {
      client.release();
    }
  }

  /** Single-transaction helper; rolls back on any throw (never a partial write). */
  async transaction(role, fn) {
    const pool = role === 'rw' ? this.rw : this.ro;
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const result = await fn(client);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      try {
        await client.query('ROLLBACK');
      } catch {
        /* connection already broken */
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async health() {
    const started = Date.now();
    try {
      await this.ro.query('SELECT 1');
      return { up: true, latencyMs: Date.now() - started };
    } catch (err) {
      return { up: false, latencyMs: Date.now() - started, error: String(err.message).slice(0, 120) };
    }
  }

  async close() {
    await Promise.allSettled([this.rw.end(), this.ro.end()]);
  }
}
