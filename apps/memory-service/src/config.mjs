/**
 * config — environment contract for the memory service.
 *
 * Every secret-shaped field is an `opaque-ref:*` value (t4 §9.4 / D1). The resolved
 * material is returned by `loadConfig()` as promises the caller awaits once at boot;
 * nothing resolved is written back into `process.env`.
 *
 * Port discipline (t4 §9.2): 8091 internal-only on net-agent, 8190 admin published
 * to loopback. 8090 is deliberately NOT used — the host already listens there.
 */

import { SecretResolver, refOf } from '@dsh-bot/bot-secrets';

const BOOL = (v, dflt) => (v === undefined || v === '' ? dflt : ['1', 'true', 'yes', 'on'].includes(String(v).toLowerCase()));
const INT = (v, dflt) => {
  const n = Number.parseInt(String(v ?? ''), 10);
  return Number.isFinite(n) ? n : dflt;
};

/**
 * @param {{env?: Record<string,string|undefined>, resolver?: SecretResolver, literalAllowed?: boolean}} [opts]
 */
export async function loadConfig(opts = {}) {
  const env = opts.env ?? process.env;
  const resolver = opts.resolver || new SecretResolver({ brokerUrl: env.BROKER_URL, secretsDir: env.SECRETS_DIR });
  const literal = opts.literalAllowed ?? false;

  const internalPort = INT(env.MEM_INTERNAL_PORT, 8091);
  const adminPort = INT(env.MEM_ADMIN_PORT, 8190);
  if (internalPort === adminPort) throw new Error('MEM_INTERNAL_PORT and MEM_ADMIN_PORT must differ');

  const maxPerRole = Math.max(1, INT(env.MEM_PG_POOL_MAX_PER_ROLE, 5));
  const poolTotal = maxPerRole * 2;
  // Task requirement: "避免长连接耗尽 Host 资源" — the pool ceiling is asserted at
  // boot rather than discovered when a shared host instance starts refusing.
  if (poolTotal > 10) throw new Error(`PG pool total ${poolTotal} exceeds the agreed ceiling of 10 (t4 §9.4 / R-3)`);

  const database = env.MEM_PG_DATABASE || 'dsh_companion';
  const host = env.MEM_PG_HOST || 'host.docker.internal';
  const port = INT(env.MEM_PG_PORT, 5432);
  // `socket:` prefix = connect over a mounted unix socket instead of TCP (t4 §9.3
  // 方案 B). The host PG listens on 127.0.0.1 only, and host-gateway TCP is
  // measurably unreachable from an internal network, so this is the shipped default.
  const socketPath = host.startsWith('socket:') ? host.slice('socket:'.length) || '/var/run/postgresql' : undefined;

  const rwPassword = await resolver.resolve(env.MEM_PG_RW_PASSWORD_REF ?? env.MEM_PG_RW_PASSWORD, { label: 'pg-rw-password', literalAllowed: !literal ? false : undefined });
  const roPassword = await resolver.resolve(env.MEM_PG_RO_PASSWORD_REF ?? env.MEM_PG_RO_PASSWORD, { label: 'pg-ro-password', literalAllowed: !literal ? false : undefined });
  const kek = await resolver.resolve(env.MEM_KEK_REF ?? env.MEM_KEK, { label: 'memory-kek', literalAllowed: !literal ? false : undefined });
  const hmacSecret = await resolver.resolve(env.MEM_HMAC_SECRET_REF ?? env.MEM_HMAC_SECRET, { label: 'mem-hmac-secret', literalAllowed: !literal ? false : undefined });

  const provisioningRef = env.MEM_PG_PROVISIONING_REF ?? env.MEM_PG_SUPERUSER_REF;
  const provisioning = provisioningRef
    ? {
        user: env.MEM_PG_PROVISIONING_USER || 'postgres',
        database: env.MEM_PG_PROVISIONING_DATABASE || 'postgres',
        password: await resolver.resolve(provisioningRef, { label: 'pg-provisioning', literalAllowed: !literal ? false : undefined }),
      }
    : null;

  return {
    service: 'memory-service',
    bind: env.MEM_BIND || '0.0.0.0',
    internalPort,
    adminPort,
    pg: {
      host,
      port,
      socketPath,
      database,
      // Roles are fixed by 002_roles.sql; only the passwords are injected.
      rw: { user: env.MEM_PG_RW_USER || 'dsh_companion_rw', password: rwPassword },
      ro: { user: env.MEM_PG_RO_USER || 'dsh_companion_ro', password: roPassword },
      maxPerRole,
      poolTotal,
      statementTimeoutMs: INT(env.MEM_PG_STATEMENT_TIMEOUT_MS, 8000),
    },
    provisioning,
    runMigrationsOnStart: BOOL(env.MEM_RUN_MIGRATIONS, false),
    psqlBin: env.MEM_PSQL_BIN || undefined,
    l1: {
      path: env.MEM_L1_PATH || '/var/lib/dshbot-memory/l1.db',
      ttlHours: INT(env.MEM_L1_TTL_HOURS, 24),
      maxMb: INT(env.MEM_SQLITE_MAX_MB, 64),
    },
    cache: {
      enabled: BOOL(env.MEM_CACHE_ENABLED, true),
      searchTtlMs: INT(env.MEM_CACHE_SEARCH_TTL_MS, 60_000),
      maxRows: INT(env.MEM_CACHE_MAX_ROWS, 5000),
    },
    limits: {
      maxSearchRows: INT(env.MEM_MAX_ROWS_PER_SEARCH, 20),
      maxSearchChars: INT(env.MEM_MAX_SEARCH_CHARS, 4000),
    },
    kek,
    hmacSecret,
    auditSink: env.AUDIT_SINK || '/var/log/dshbot/memory.jsonl',
    degradedFlagPath: env.DEGRADED_FLAG_PATH || '/state/degraded',
    backup: {
      enabled: BOOL(env.MEM_BACKUP_ENABLED, false),
      dir: env.MEM_BACKUP_DIR || '/var/lib/dshbot-memory/backups',
      keep: INT(env.MEM_BACKUP_KEEP, 7),
    },
    jobs: {
      l1EvictIntervalMinutes: INT(env.MEM_JOB_L1_INTERVAL_MIN, 60),
      purgeIntervalMinutes: INT(env.MEM_JOB_PURGE_INTERVAL_MIN, 1440),
      pruneAccessKeepDays: INT(env.MEM_PRUNE_ACCESS_KEEP_DAYS, 365),
    },
    refFields: Object.fromEntries(
      Object.entries({
        MEM_PG_RW_PASSWORD_REF: env.MEM_PG_RW_PASSWORD_REF,
        MEM_PG_RO_PASSWORD_REF: env.MEM_PG_RO_PASSWORD_REF,
        MEM_KEK_REF: env.MEM_KEK_REF,
        MEM_HMAC_SECRET_REF: env.MEM_HMAC_SECRET_REF,
      }).filter(([, v]) => refOf(v) !== null),
    ),
  };
}
