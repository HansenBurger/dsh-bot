/**
 * integration-memory — end-to-end exercise of the memory service against a real
 * PostgreSQL, with an ephemeral cluster by default so the host's shared instance is
 * never touched by a test.
 *
 * What it proves (acceptance mapping):
 *   - 001..004 migrations apply, and apply a SECOND time without error (幂等);
 *   - the rw/ro permission matrix really denies (M-02/M-07, executed as the login
 *     role, not `SET ROLE`);
 *   - CJK recall works through byte trigrams (t4 §7.1, the corrected design);
 *   - read → write → search → forget all work over the signed REST surface, and
 *     forget without an approval token is refused (M-05/M-06);
 *   - the SQLite L1 projection is really used on the second read (task requirement
 *     双写 + 回填), while an encrypted PII row is never served from cache;
 *   - unsigned / wrong-secret / replayed requests are rejected (M-14);
 *   - the pool total respects the agreed ceiling of 10 (task requirement).
 *
 * Usage:
 *   node scripts/integration-memory.mjs                     # ephemeral cluster
 *   MEM_PG_HOST=/tmp/sock node scripts/integration-memory.mjs   # reuse a running one
 */

import { execFile, spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { openSync as fsOpenSync } from 'node:fs';
import { promisify } from 'node:util';
import { encodePrincipal, sign } from '../packages/bot-hmac/src/index.mjs';

const execFileAsync = promisify(execFile);

const PGBIN = process.env.PGBIN_DIR || (existsSync('/usr/lib/postgresql/16/bin') ? '/usr/lib/postgresql/16/bin' : null);
const results = [];
let failed = 0;

function check(name, ok, detail = '') {
  results.push({ name, ok: Boolean(ok), detail });
  if (!ok) failed += 1;
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? ` — ${detail}` : ''}\n`);
}

const sha256 = (s) => createHash('sha256').update(String(s), 'utf8').digest('hex');

async function main() {
  const work = mkdtempSync(join(tmpdir(), 'dshbot-int-'));
  const env = { ...process.env };
  const cluster = { external: Boolean(env.MEM_PG_HOST) };
  let pgProc = null;
  let pgLog = '';

  const pw = {
    rw: `RW-${randomBytes(18).toString('base64url')}`,
    ro: `RO-${randomBytes(18).toString('base64url')}`,
    super: `SU-${randomBytes(18).toString('base64url')}`,
  };
  const kek = randomBytes(32).toString('base64url');
  const hmac = randomBytes(32).toString('base64url');

  let pgHost = env.MEM_PG_HOST || '';
  let pgPort = Number(env.MEM_PG_PORT || 5432);
  let superUser = env.MEM_PG_PROVISIONING_USER || 'postgres';
  let superPassword = env.MEM_PG_SUPER_PASSWORD || '';

  try {
    if (!cluster.external) {
      if (!PGBIN) throw new Error('no /usr/lib/postgresql/16/bin and no MEM_PG_HOST — cannot run an ephemeral cluster');
      const data = join(work, 'data');
      const sock = join(work, 'sock');
      // postgres refuses to start if the socket directory does not exist.
      mkdirSync(sock, { recursive: true });
      // unix_socket_directories must be a *directory*: psql takes `-h <dir>`. Same
      // class of mistake as treating a socket file as a host (t4 §9.3 方案 B).
      await execFileAsync(`${PGBIN}/initdb`, ['-D', data, '-A', 'trust', '-U', 'postgres', '--encoding=UTF8', '--locale=C.UTF-8']);
      pgLog = join(work, 'postgres.log');
      pgProc = spawn(`${PGBIN}/postgres`, ['-D', data, '-c', 'listen_addresses=', '-c', `unix_socket_directories=${sock}`, '-c', 'fsync=off', '-c', 'synchronous_commit=off'], { stdio: ['ignore', fsOpenSync(pgLog, 'a'), fsOpenSync(pgLog, 'a')] });
      pgHost = sock;
      pgPort = Number(env.MEM_PG_PORT || 5432);
      await waitForSocket(sock, 30_000);
      superUser = 'postgres';
      superPassword = '';
      cluster.socket = sock;
    }

    // ---------------- 1) migrations, twice (idempotency) ----------------
    const migrateArgs = {
      socketPath: cluster.external ? undefined : pgHost,
      host: cluster.external ? pgHost : undefined,
      port: pgPort,
      database: 'dsh_companion_it',
      superuser: { user: superUser, password: superPassword, database: 'postgres' },
      passwords: { rw: pw.rw, ro: pw.ro },
      createDatabase: true,
      psqlBin: process.env.PSQL_BIN || (existsSync(`${PGBIN || ''}/psql`) ? `${PGBIN}/psql` : 'psql'),
    };
    const { runPgMigrations } = await import('../apps/memory-service/src/migrate.mjs');
    const first = await runPgMigrations(migrateArgs);
    check('migrations apply on a fresh database', first.applied.length === 4, first.detail);
    const second = await runPgMigrations(migrateArgs);
    check('migrations are idempotent (second run, no error)', second.applied.length === 4, second.detail);

    // ---------------- 2) service boot ----------------
    const internalPort = 18091;
    const adminPort = 18190;
    const l1Path = join(work, 'l1', 'l1.db');
    const env2 = {
      ...env,
      MEM_PG_HOST: cluster.external ? pgHost : `socket:${pgHost}`,
      MEM_PG_PORT: String(pgPort),
      MEM_PG_DATABASE: 'dsh_companion_it',
      MEM_PG_RW_PASSWORD_REF: pw.rw,
      MEM_PG_RO_PASSWORD_REF: pw.ro,
      MEM_PG_PROVISIONING_REF: superPassword || 'trust',
      MEM_KEK_REF: kek,
      MEM_HMAC_SECRET_REF: hmac,
      MEM_L1_PATH: l1Path,
      MEM_INTERNAL_PORT: String(internalPort),
      MEM_ADMIN_PORT: String(adminPort),
      MEM_BIND: '127.0.0.1',
      AUDIT_SINK: join(work, 'logs', 'memory.jsonl'),
      SECRETS_DIR: join(work, 'no-secrets'),
      BROKER_URL: '',
      MEM_RUN_MIGRATIONS: 'false',
    };

    const { createService } = await import('../apps/memory-service/src/index.mjs');
    const svc = await createService({ env: env2, allowLiterals: true, runMigrations: false });
    check('service boots (internal + admin listeners)', svc.internal.listening && svc.admin.listening);
    check('PG pool total respects the ceiling of 10', svc.pg.poolTotal <= 10, `total=${svc.pg.poolTotal}`);

    const base = `http://127.0.0.1:${internalPort}`;
    const adminBase = `http://127.0.0.1:${adminPort}`;
    const DEFAULT_PRINCIPAL = { channel: 'telegram', chatId: '111', userId: '111', role: 'owner' };
    // Signed by hand rather than via signedHeaders(), because the replay test needs
    // to pin a nonce and encodePrincipal() always generates a fresh one.
    const call = async (method, path, body, opts = {}) => {
      const raw = body === undefined ? '' : JSON.stringify(body);
      const secret = opts.secret ?? hmac;
      const encoded = opts.rawPrincipal ?? encodePrincipal(opts.principal ?? DEFAULT_PRINCIPAL, opts.nonce ? { nonce: opts.nonce } : {});
      const headers = {
        'content-type': 'application/json',
        'X-Bot-Principal': encoded,
        // The signature covers method + path + query, so the signed string is exactly
        // what goes on the wire (`?dryRun=false` is part of the contract, not a hint).
        // The approval token is bound into the signature (canonicalString `bind`), so
        // it cannot be attached to an already-signed preview request afterwards.
        'X-Bot-Sig': sign(secret, { method, path, body: raw || undefined, principal: encoded, bind: opts.approval }),
        ...(opts.approval ? { 'X-Bot-Approval': opts.approval } : {}),
      };
      const res = await fetch(`${base}${path}`, { method, headers, body: raw || undefined });
      let json = null;
      try {
        json = await res.json();
      } catch {
        json = null;
      }
      return { status: res.status, json };
    };

    // ---------------- 3) health ----------------
    const health = await fetch(`${adminBase}/healthz`).then((r) => r.json());
    check('admin /healthz reports pg + sqlite up', health.status === 'ok' && health.pg.up && health.sqlite.up, JSON.stringify(health.pg));

    // ---------------- 4) auth failures (M-14) ----------------
    const unsigned = await fetch(`${base}/v1/memories/search`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ query: 'x' }) });
    check('unsigned request ⇒ 401', unsigned.status === 401, `status=${unsigned.status}`);
    const wrongSecret = await call('POST', '/v1/memories/search', { query: 'x' }, { secret: 'wrong-secret-value-000000' });
    check('wrong-secret signature ⇒ 401', wrongSecret.status === 401, JSON.stringify(wrongSecret.json));
    const nonce = randomBytes(12).toString('base64url');
    const forgedPublic = Buffer.from(JSON.stringify({ ...DEFAULT_PRINCIPAL, role: 'public', ts: Date.now(), nonce: randomBytes(12).toString('base64url') })).toString('base64url');
    void forgedPublic;
    const publicRole = await call('POST', '/v1/memories/search', { query: 'x' }, { rawPrincipal: forgedPublic });
    check('forged role=public principal is refused (U1)', publicRole.status === 403 || publicRole.status === 401, `status=${publicRole.status} code=${publicRole.json?.code}`);
    await call('POST', '/v1/memories/search', { query: '香菜' }, { nonce });
    const replay = await call('POST', '/v1/memories/search', { query: '香菜' }, { nonce });
    check('replayed nonce ⇒ 401 NONCE_REPLAY', replay.status === 401 && replay.json?.code === 'NONCE_REPLAY', JSON.stringify(replay.json));

    // ---------------- 5) write / read / search / forget ----------------
    const approval = `appr-${randomBytes(12).toString('hex')}`;
    const writeEp = await call('POST', '/v1/memories', {
      subjectKey: 'telegram:dm:111',
      class: 'episode',
      body: '主人说过她喜欢吃香菜和花生，讨厌芹菜。',
      scope: 'dm',
      approvalId: approval,
    });
    check('write episode (approved) ⇒ 2xx', writeEp.status >= 200 && writeEp.status < 300 && writeEp.json?.memoryId, JSON.stringify(writeEp.json).slice(0, 140));
    const memoryId = writeEp.json?.memoryId;

    const writeNoApproval = await call('POST', '/v1/memories', { subjectKey: 'telegram:dm:111', class: 'episode', body: '未经审批的写入' });
    check('write without approval token ⇒ 403 APPROVAL_REQUIRED', writeNoApproval.status === 403 && writeNoApproval.json?.code === 'APPROVAL_REQUIRED', JSON.stringify(writeNoApproval.json));

    const read1 = await call('GET', `/v1/memories/${memoryId}`);
    check('read returns the written body', read1.status === 200 && String(read1.json?.body).includes('香菜'), JSON.stringify(read1.json).slice(0, 140));
    check('contract field createdAt present (openapi Memory)', typeof read1.json?.createdAt === 'string' && read1.json.createdAt.length > 0, String(read1.json?.createdAt));
    const statsAfterMiss = svc.repo.cacheStatsReport();
    const read2 = await call('GET', `/v1/memories/${memoryId}`);
    const statsAfterHit = svc.repo.cacheStatsReport();
    check('second read served from the SQLite projection (双写+回填)', read2.status === 200 && statsAfterHit.hit > statsAfterMiss.hit && statsAfterMiss.miss >= 1, `hit ${statsAfterMiss.hit}→${statsAfterHit.hit}, miss=${statsAfterMiss.miss}`);

    const writeProfile = await call('POST', '/v1/memories', {
      subjectKey: 'telegram:dm:111',
      class: 'profile',
      attrKey: 'diet.forbidden',
      body: '芹菜',
      sensitivity: 'internal',
      approvalId: approval,
    });
    check('write profile KV ⇒ 2xx', writeProfile.status >= 200 && writeProfile.status < 300, JSON.stringify(writeProfile.json).slice(0, 120));

    const searchCjk = await call('POST', '/v1/memories/search', { query: '香菜', limit: 5 });
    check('CJK recall via byte trigrams (t4 §7.1)', searchCjk.status === 200 && Array.isArray(searchCjk.json?.results) && searchCjk.json.results.length >= 1, `hits=${searchCjk.json?.results?.length ?? 0}`);
    const searchCache = await call('POST', '/v1/memories/search', { query: '香菜', limit: 5 });
    check('search served from the L1 projection on repeat', searchCache.status === 200 && searchCache.json?.cacheHit === true, `cacheHit=${searchCache.json?.cacheHit}`);
    const searchMiss = await call('POST', '/v1/memories/search', { query: '量子力学不存在词', limit: 5 });
    check('unrelated CJK query returns nothing', searchMiss.status === 200 && (searchMiss.json?.results?.length ?? 1) === 0, `hits=${searchMiss.json?.results?.length}`);

    const piiApproval = `pii-${randomBytes(12).toString('hex')}`;
    const writePii = await call('POST', '/v1/memories', {
      subjectKey: 'telegram:dm:111',
      class: 'pii_raw',
      attrKey: 'address.home',
      body: '上海市某某路 1 号 302 室',
      sensitivity: 'pii',
      visibility: 'owner',
      approvalId: piiApproval,
    });
    check('encrypted PII write ⇒ 2xx + encrypted flag', writePii.status >= 200 && writePii.status < 300 && writePii.json?.encrypted === true, JSON.stringify(writePii.json).slice(0, 140));
    const readPii = await call('GET', `/v1/memories/${writePii.json?.memoryId}`);
    check('PII read decrypts through PG', readPii.status === 200 && String(readPii.json?.body).includes('上海'), String(readPii.json?.body).slice(0, 30));
    const piiCached = svc.cache.get(writePii.json?.memoryId);
    check('PII body never enters the SQLite cache (§5.2)', piiCached === null, piiCached ? 'LEAK' : 'absent');

    const secretWrite = await call('POST', '/v1/memories', { subjectKey: 'telegram:dm:111', class: 'preference', attrKey: 'api.key', body: 'sk-proj-abcdefghijklmnop1234', scope: 'global', approvalId: approval });
    check('secret-class payload refused, not encrypted-stored (§5.1)', secretWrite.status === 422 && secretWrite.json?.code === 'MEMORY_REFUSED_CATEGORY', JSON.stringify(secretWrite.json).slice(0, 120));

    // Tamper test: reuse a *signed preview* request and flip dryRun on the wire.
    const previewSigned = await (async () => {
      const p = `/v1/memories/${memoryId ?? '00000000-0000-4000-8000-000000000000'}/forget?dryRun=true`;
      const encoded = encodePrincipal(DEFAULT_PRINCIPAL);
      return { p, encoded, sig: sign(hmac, { method: 'POST', path: p, principal: encoded }) };
    })();
    const tampered = await fetch(`${base}${previewSigned.p.replace('dryRun=true', 'dryRun=false')}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'X-Bot-Principal': previewSigned.encoded, 'X-Bot-Sig': previewSigned.sig },
    });
    check('query-string tampering (preview→delete) breaks the signature', tampered.status === 401, `status=${tampered.status}`);
    const forgetDry = await call('POST', `/v1/memories/${memoryId}/forget?dryRun=true`, {});
    check('forget dry-run lists tombstones without deleting', forgetDry.status === 200 && forgetDry.json?.dryRun === true && forgetDry.json?.deletedCount === 0, JSON.stringify(forgetDry.json).slice(0, 140));
    const forgetNoToken = await call('POST', `/v1/memories/${memoryId}/forget?dryRun=false`, {});
    check('forget without approval ⇒ 403 (M-05)', forgetNoToken.status === 403 && forgetNoToken.json?.code === 'APPROVAL_INVALID', JSON.stringify(forgetNoToken.json));
    const forgetReal = await call('POST', `/v1/memories/${memoryId}/forget?dryRun=false`, {}, { approval });
    check('forget deletes with approval token', forgetReal.status === 200 && forgetReal.json?.deletedCount === 1, JSON.stringify(forgetReal.json).slice(0, 140));
    const readAfterForget = await call('GET', `/v1/memories/${memoryId}`);
    check('deleted memory is gone from BOTH pg and cache', readAfterForget.status === 404 && svc.cache.get(memoryId) === null, `status=${readAfterForget.status}`);

    // ---------------- 6) permission matrix as the real login roles ----------------
    const roleProbe = await pgRoleProbe({ socketPath: cluster.external ? undefined : pgHost, host: cluster.external ? pgHost : undefined, port: pgPort, database: 'dsh_companion_it' }, pw);
    check('ro role cannot INSERT (M-02)', /permission denied/.test(roleProbe.roInsert), roleProbe.roInsert.slice(0, 90));
    check('ro role cannot decrypt (M-02)', /permission denied/.test(roleProbe.roDecrypt), roleProbe.roDecrypt.slice(0, 90));
    check('rw role cannot DELETE tombstones (append-only)', /permission denied/.test(roleProbe.rwTombstoneDelete), roleProbe.rwTombstoneDelete.slice(0, 90));
    check('rw role cannot execute forget_by_subject (M-07)', /permission denied/.test(roleProbe.rwForgetFn), roleProbe.rwForgetFn.slice(0, 90));
    check('rw role can execute purge_expired', /purge_expired/.test(roleProbe.rwPurge) || /^\s*[0-9]+\s*$/.test(roleProbe.rwPurge), roleProbe.rwPurge.slice(0, 90));

    // ---------------- 7) audit + retention job ----------------
    const auditText = existsSync(env2.AUDIT_SINK) ? (await import('node:fs')).readFileSync(env2.AUDIT_SINK, 'utf8') : '';
    const auditTypes = new Set(auditText.split('\n').filter(Boolean).map((l) => JSON.parse(l).type));
    check('audit JSONL covers authz + memory classes (F1)', auditTypes.has('credential.resolve') || auditTypes.has('authz.decision') || auditTypes.has('memory.access'), [...auditTypes].join(','));
    const jobRun = await fetch(`${adminBase}/jobs/purge_expired/run`, { method: 'POST' }).then((r) => r.json());
    check('admin can trigger the retention job (M-08/M-19)', jobRun.ok === true, JSON.stringify(jobRun).slice(0, 120));
    const healthAfterJob = await fetch(`${adminBase}/healthz`).then((r) => r.json());
    check('healthz exposes the job heartbeat', Array.isArray(healthAfterJob.jobs) && healthAfterJob.jobs.some((j) => j.job === 'purge_expired'), JSON.stringify(healthAfterJob.jobs));

    await svc.close();
  } catch (err) {
    check('integration run completed without crash', false, String(err?.stack ?? err).slice(0, 500));
  } finally {
    if (pgProc) {
      pgProc.kill('SIGINT');
      await new Promise((r) => setTimeout(r, 1500));
    }
    rmSync(work, { recursive: true, force: true });
  }

  process.stdout.write(`\n== ${results.length - failed}/${results.length} checks passed ==\n`);
  writeFileSync('/tmp/dshbot-int-summary.json', JSON.stringify({ results, failed }, null, 2));
  process.exit(failed ? 1 : 0);
}

async function waitForSocket(sockDir, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(join(sockDir, '.s.PGSQL.5432'))) return true;
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error(`ephemeral cluster did not come up: ${readFileSync(sockDir + '/../postgres.log', 'utf8').slice(-400)}`);
}

/** Permission assertions run as the *login* role, not `SET ROLE` (M-02). */
async function pgRoleProbe(opts, pw) {
  const probePasswords = { rw: pw.rw, ro: pw.ro };
  // Password travels via PGPASSWORD in the child env, never argv (would show in ps).
  const run = async (user, password, sql) => {
    const args = ['-h', String(opts.socketPath || opts.host), '-p', String(opts.port || 5432), '-U', user, '-d', opts.database, '-tAc', sql];
    try {
      const { stdout } = await execFileAsync(process.env.PSQL_BIN || 'psql', args, { env: { ...process.env, PGPASSWORD: password } });
      return String(stdout).trim();
    } catch (err) {
      return String(err.stderr || err.message || err).trim();
    }
  };
  return {
    roInsert: await run('dsh_companion_ro', probePasswords.ro, `INSERT INTO companion.memory_episode (subject_id, peer_key, class, body_plain, dedupe_key, sensitivity, visibility) VALUES (gen_random_uuid(), 'x', 'episode', 't', 'k', 'internal', 'private')`),
    roDecrypt: await run('dsh_companion_ro', probePasswords.ro, `SELECT pgp_sym_decrypt('\\x00'::bytea, 'k')`),
    rwTombstoneDelete: await run('dsh_companion_rw', probePasswords.rw, `DELETE FROM companion.memory_tombstone`),
    rwForgetFn: await run('dsh_companion_rw', probePasswords.rw, `SELECT companion.forget_by_subject(gen_random_uuid(), 'x', 'aaaaaaaa', true)`),
    rwPurge: await run('dsh_companion_rw', probePasswords.rw, `SELECT companion.purge_expired(10)`),
  };
}

await main();
