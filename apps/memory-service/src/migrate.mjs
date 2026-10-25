/**
 * migrate — run the t4 PG migrations + SQLite L1 DDL at container start.
 *
 * Task requirement: "Memory Service 容器：内置 psql 客户端 + SQLite3，启动时执行 PG schema migration".
 *
 * Two execution paths, deliberately:
 *   1. `psql` when present (the container image installs postgresql16-client).
 *      The migrations use `DO $$ … $$`, `\`-free plain SQL and psql session GUCs,
 *      all of which psql handles; node-pg cannot execute a multi-statement string
 *      that contains a dollar-quoted body with semicolons reliably enough to trust.
 *   2. Pure-node fallback that splits on top-level statements. Used only for tests
 *      where psql is unavailable; it refuses anything it cannot split safely.
 *
 * Passwords never appear in the repository or in argv (`ps` would show them): they
 * travel as **session GUCs** (`companion.rw_password`) written into a 0600 temp file
 * that psql executes in the same session as 002_roles.sql, which reads them through
 * current_setting() and interpolates them with %L. The temp file is removed in a
 * finally block, and statement logging stays at 'ddl' on the host instance (t4 §9.3).
 */

import { execFile } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const HERE = dirname(fileURLToPath(import.meta.url));
export const MIGRATION_DIR = join(HERE, '..', 'migrations');
export const SQLITE_DDL_PATH = join(HERE, '..', 'sqlite', 'l1-cache.sql');
export const MEMORY_CACHE_DDL_PATH = join(HERE, '..', 'sqlite', 'memory-cache.sql');

export const PG_MIGRATIONS = Object.freeze(['001_schema.sql', '002_roles.sql', '003_seed_policy.sql', '004_retention.sql']);

const sha256Hex = async (text) => {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(text, 'utf8').digest('hex');
};

/**
 * Build the artifact-baseline spec consumed by 003_seed_policy.sql (t4 §8.6 / B8).
 * @param {string[]} files
 */
async function baselineSpec(files) {
  const pairs = [];
  for (const f of files) {
    const abs = join(MIGRATION_DIR, f);
    if (!existsSync(abs)) continue;
    pairs.push(`docs/memory/sql/pg/${f}=${await sha256Hex(readFileSync(abs, 'utf8'))}`);
  }
  return pairs.join(',');
}

/** A GUC value may contain a single quote; double it, and never let a newline in. */
const guc = (value) => String(value ?? '').replace(/'/g, "''").replace(/[\r\n]/g, '');

const quoteIdent = (name) => `"${String(name).replace(/"/g, '""')}"`;

/**
 * @param {{psqlBin?: string, host?: string, socketPath?: string, port?: number|string, superuser: {database?:string,user:string,password:string}, passwords:{rw:string,ro:string}, database:string, createDatabase?: boolean, allowCreateDatabase?: boolean}} opts
 * @returns {Promise<{applied: string[], skipped: boolean, detail: string}>}
 */
export async function runPgMigrations(opts) {
  const psql = opts.psqlBin || (existsSync('/usr/bin/psql') ? '/usr/bin/psql' : 'psql');
  const database = opts.database;
  // `-h` accepts a directory for a unix-socket connection; that is the shipped path
  // because the host PG listens on 127.0.0.1 only and TCP from an internal docker
  // network is measurably refused (t4 §9.3 measured the same limitation).
  const common = [
    '-h', String(opts.socketPath || opts.host || '/var/run/postgresql'),
    '-p', String(opts.port || 5432),
    '-v', 'ON_ERROR_STOP=1',
    '--no-psqlrc',
  ];
  const superDb = opts.superuser.database || 'postgres';
  const env = { ...process.env, PGPASSWORD: opts.superuser.password };

  // 1) Ensure the target database exists (superuser action, once).
  const probe = await execFileAsync(psql, [...common, '-U', opts.superuser.user, '-d', superDb, '-tAc', 'select 1'], { env }).catch(() => null);
  if (!probe) {
    throw new Error(`cannot reach PostgreSQL at ${opts.socketPath || `${opts.host}:${opts.port}`} as the provisioning role`);
  }
  const exists = await execFileAsync(
    psql,
    [...common, '-U', opts.superuser.user, '-d', superDb, '-tAc',
      `select count(*) from pg_database where datname = '${database.replace(/'/g, "''")}'`],
    { env },
  ).then(({ stdout }) => stdout.trim() === '1');

  if (!exists) {
    if (opts.createDatabase !== true) {
      throw new Error(`database ${database} does not exist — run deploy/scripts/host-pg-prepare.sh (or pass createDatabase: true)`);
    }
    // C.UTF-8 is required for the byte-trigram path (t4 §3.1); template0 guarantees
    // the encoding/locale can be set explicitly instead of inheriting a latin1 template.
    await execFileAsync(
      psql,
      [...common, '-U', opts.superuser.user, '-d', superDb, '-c',
        `CREATE DATABASE ${quoteIdent(database)} ENCODING 'UTF8' LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8' TEMPLATE template0`],
      { env },
    );
  }

  const baseline = await baselineSpec([...PG_MIGRATIONS.filter((f) => f !== '003_seed_policy.sql'), '003_seed_policy.sql']);
  const applied = [];
  for (const file of PG_MIGRATIONS) {
    const path = join(MIGRATION_DIR, file);
    const args = [...common, '-U', opts.superuser.user, '-d', database];
    // The migration bodies read their inputs through `current_setting()`. psql `-c`
    // is "run this SQL", NOT "set a parameter" (measured: syntax error at or near
    // "companion") — a custom GUC has to travel in the connection options, and only
    // the two statements that actually consume them get a value attached.
    // Values the migration reads through current_setting() travel in a 0600 temp
    // bootstrap file, executed in the SAME psql session as the migration (`-f a -f b`).
    // Two transports were measured to be wrong:
    //   - psql `-c name=value` is "run this SQL", not "set a parameter";
    //   - PGOPTIONS splits on commas, which silently truncates the baseline spec, and
    //     quote-wrapping a value would corrupt it because 002 interpolates %L.
    const sets = [];
    if (file === '002_roles.sql') {
      sets.push(['companion.rw_password', opts.passwords.rw], ['companion.ro_password', opts.passwords.ro]);
    }
    if (file === '003_seed_policy.sql' && baseline) {
      sets.push(['companion.baseline_sha256', baseline]);
    }
    let boot = null;
    if (sets.length) {
      boot = mkdtempSync(join(tmpdir(), 'dshbot-mig-'));
      const file060 = join(boot, 'bootstrap.sql');
      writeFileSync(file060, sets.map(([k, v]) => `SET ${k} = $dshbot$${String(v ?? '').replace(/\r?\n/g, '')}$dshbot$;`).join('\n') + '\n', { mode: 0o600 });
      args.push('-f', file060);
    }
    args.push('-f', path);
    try {
      await execFileAsync(psql, args, { env, maxBuffer: 8 * 1024 * 1024 });
    } finally {
      if (boot) rmSync(boot, { recursive: true, force: true });
    }
    applied.push(file);
  }
  return { applied, skipped: false, detail: `${applied.length} migrations applied via psql${exists ? ' (existing db)' : ' (created db)'}` };
}

/* ------------------------------------------------------------------ *
 * Pure-node fallback (tests without psql). Splits on top-level ';' only.
 * ------------------------------------------------------------------ */

/**
 * Split SQL into statements while respecting dollar-quoted bodies, strings and
 * comments. Anything ambiguous throws instead of guessing — a silently mis-split
 * migration is worse than a refused one.
 *
 * Trailing comment-only blocks are dropped: the migration files end with a
 * "Post-check（人工执行）" comment listing psql meta-commands, which is documentation,
 * not an executable statement.
 *
 * @param {string} sql
 */
export function splitStatements(sql) {
  const out = [];
  let buf = '';
  let i = 0;
  let dollarTag = null;
  let inSingle = false;
  let inDouble = false;
  let lineComment = false;
  let blockComment = false;

  while (i < sql.length) {
    const ch = sql[i];
    const rest = sql.slice(i, i + 2);

    if (lineComment) {
      if (ch === '\n') lineComment = false;
      buf += ch;
      i += 1;
      continue;
    }
    if (blockComment) {
      if (rest === '*/') blockComment = false;
      buf += ch;
      i += 1;
      continue;
    }
    if (dollarTag !== null) {
      if (rest === dollarTag) {
        buf += dollarTag;
        i += dollarTag.length;
        dollarTag = null;
        continue;
      }
      buf += ch;
      i += 1;
      continue;
    }
    if (inSingle || inDouble) {
      const quote = inSingle ? "'" : '"';
      if (ch === quote) {
        // doubled quote inside the literal
        if (sql[i + 1] === quote) {
          buf += ch + ch;
          i += 2;
          continue;
        }
        if (inSingle) inSingle = false;
        else inDouble = false;
      }
      buf += ch;
      i += 1;
      continue;
    }
    if (rest === '--') {
      lineComment = true;
      buf += rest;
      i += 2;
      continue;
    }
    if (rest === '/*') {
      blockComment = true;
      buf += rest;
      i += 2;
      continue;
    }
    const dollarMatch = /^\$[A-Za-z_0-9]*\$/.exec(sql.slice(i));
    if (dollarMatch) {
      dollarTag = dollarMatch[0];
      buf += dollarTag;
      i += dollarTag.length;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      buf += ch;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      buf += ch;
      i += 1;
      continue;
    }
    if (ch === ';') {
      const trimmed = buf.trim();
      if (trimmed.length) out.push(trimmed);
      buf = '';
      i += 1;
      continue;
    }
    buf += ch;
    i += 1;
  }
  if (dollarTag !== null || inSingle || inDouble || blockComment) {
    throw new Error('unterminated quoted context in migration file; refusing to split');
  }
  const tail = buf.trim();
  if (tail.length) out.push(tail);
  return out.filter((stmt) => {
    // Strip line comments and block comments, then require real content.
    const code = stmt.replace(/--[^\n]*/g, '').replace(/\/\*[\s\S]*?\*\//g, '').trim();
    return code.length > 0;
  });
}

/**
 * Node-only migration runner. Requires the database to already exist and the
 * GUC-providing caller to pass resolved values (used by the test harness).
 *
 * @param {{client: {query:(sql:string)=>Promise<any>}, passwords:{rw:string,ro:string}, baselineSpec?: string, files?: string[]}} opts
 */
export async function runPgMigrationsWithClient(opts) {
  const files = opts.files || PG_MIGRATIONS;
  const applied = [];
  for (const file of files) {
    let sql = readFileSync(join(MIGRATION_DIR, file), 'utf8');
    // Substitute the GUC reads the same runner would provide via psql -c.
    sql = sql
      .replaceAll("current_setting('companion.rw_password', true)", `'${opts.passwords.rw.replace(/'/g, "''")}'`)
      .replaceAll("current_setting('companion.ro_password', true)", `'${opts.passwords.ro.replace(/'/g, "''")}'`)
      .replaceAll("current_setting('companion.baseline_sha256', true)", opts.baselineSpec ? `'${opts.baselineSpec.replace(/'/g, "''")}'` : 'NULL');
    const statements = splitStatements(sql);
    for (const stmt of statements) {
      if (/^\\/.test(stmt)) throw new Error(`psql meta-command in ${file} is unsupported by the node runner`);
      await opts.client.query(stmt);
    }
    applied.push(file);
  }
  return { applied, skipped: false, detail: `${applied.length} migrations applied via node driver` };
}

/** Read + return the SQLite L1 DDL text. */
export function sqliteDdl() {
  return readFileSync(SQLITE_DDL_PATH, 'utf8');
}

/** Read + return the SQLite read-through projection DDL (t5 addition). */
export function sqliteCacheDdl() {
  return readFileSync(MEMORY_CACHE_DDL_PATH, 'utf8');
}
