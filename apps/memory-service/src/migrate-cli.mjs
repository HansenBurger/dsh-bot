/**
 * migrate-cli — operator-facing schema migration against the PostgreSQL instance.
 *
 * Used by `docker compose run --rm memory-migrate` and by the container entrypoint when
 * `MEM_RUN_MIGRATIONS=1`. Everything sensitive is resolved through the same
 * opaque-ref path as the service itself (t4 §9.4), so this process never takes a
 * password on argv — argv is visible in `ps`, the environment of the psql child is not.
 */

import { loadConfig } from './config.mjs';
import { runPgMigrations } from './migrate.mjs';

const env = process.env;
if (env.MEM_RUN_MIGRATIONS !== undefined && env.MEM_RUN_MIGRATIONS !== '1' && env.MEM_RUN_MIGRATIONS !== 'true') {
  process.stdout.write('migrate: refused — set MEM_RUN_MIGRATIONS=1 to apply the schema to the target instance\n');
  process.exitCode = 2;
} else {
  try {
    const config = await loadConfig({ env, literalAllowed: env.NODE_ENV === 'test' ? undefined : false });
    // Fail with the reason rather than a stack: this is the command an operator runs
    // first on a new host, and "cannot read properties of null" teaches them nothing.
    if (!config.provisioning) throw new Error('MEM_PG_PROVISIONING_REF is not set — the migration needs a role that may CREATE DATABASE');
    if (!config.pg.rw.password || !config.pg.ro.password) throw new Error('rw/ro passwords unresolved — 002_roles.sql cannot be applied without them');
    const result = await runPgMigrations({
      host: config.pg.host,
      socketPath: config.pg.socketPath,
      port: config.pg.port,
      database: config.pg.database,
      superuser: config.provisioning,
      passwords: { rw: config.pg.rw.password, ro: config.pg.ro.password },
      createDatabase: true,
      psqlBin: config.psqlBin,
    });
    process.stdout.write(`migrate: ${result.detail}; files ${result.applied.join(', ')}\n`);
  } catch (err) {
    process.stdout.write(`migrate: FAILED ${String(err.message || err).slice(0, 300)}\n`);
    process.exitCode = 1;
  }
}
