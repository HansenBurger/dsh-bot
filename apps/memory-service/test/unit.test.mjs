/**
 * Unit tests for the memory service's non-network layers: config contract, the SQLite L1
 * cache, the search/row projection, and the job scheduler. PostgreSQL behaviour is covered
 * by scripts/integration-memory.mjs (which runs real migrations and the role matrix) —
 * nothing here needs a database server.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, statSync, chmodSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecretResolver } from '@dsh-bot/bot-secrets';
import { loadConfig } from '../src/config.mjs';
import { L1Cache } from '../src/l1.mjs';
import { MemoryCache } from '../src/cache.mjs';
import { JobScheduler } from '../src/jobs.mjs';
import { normalizeText, byteTrigrams, MEMORY_CLASSES, SENSITIVITIES } from '../src/repository.mjs';
import { sqliteDdl, sqliteCacheDdl } from '../src/migrate.mjs';

const SECRETS = (() => {
  const d = mkdtempSync(join(tmpdir(), 'memtest-secrets-'));
  chmodSync(d, 0o700);
  const files = [
    ['mem-pg-rw-password', 'rw-secret-value'],
    ['mem-pg-ro-password', 'ro-secret-value'],
    ['mem-kek', 'kek-secret-value'],
    ['mem-hmac-secret', 'hmac-secret-value'],
    ['mem-pg-provision-password', 'super-secret-value'],
  ];
  for (const [name, value] of files) {
    // The resolver's own mode rule is about *writability*; here the files just have to
    // be readable, so the harness writes them plainly.
    writeFileSync(join(d, name), value);
  }
  return d;
})();

const baseEnv = () => ({
  BROKER_URL: '',
  SECRETS_DIR: SECRETS,
  MEM_PG_HOST: 'socket:/var/run/postgresql',
  MEM_PG_RW_PASSWORD_REF: 'opaque-ref:mem-pg-rw-password',
  MEM_PG_RO_PASSWORD_REF: 'opaque-ref:mem-pg-ro-password',
  MEM_KEK_REF: 'opaque-ref:mem-kek',
  MEM_HMAC_SECRET_REF: 'opaque-ref:mem-hmac-secret',
  MEM_L1_PATH: ':memory:',
});

const load = async (overrides = {}, opts = {}) =>
  loadConfig({ env: { ...baseEnv(), ...overrides }, resolver: new SecretResolver({ secretsDir: SECRETS, brokerUrl: '' }), ...opts });

/* ---------------- config ---------------- */

test('the config contract reads refs, never literals, and exposes them for logging', async () => {
  const config = await load();
  assert.equal(config.pg.socketPath, '/var/run/postgresql', 'socket: prefix selects the unix socket');
  assert.equal(config.pg.host, 'socket:/var/run/postgresql', 'the raw value is kept for the log line');
  assert.equal(config.pg.rw.password, 'rw-secret-value');
  assert.equal(config.pg.ro.password, 'ro-secret-value');
  assert.equal(config.kek, 'kek-secret-value');
  assert.deepEqual(Object.keys(config.refFields).sort(), ['MEM_HMAC_SECRET_REF', 'MEM_KEK_REF', 'MEM_PG_RO_PASSWORD_REF', 'MEM_PG_RW_PASSWORD_REF']);
  assert.equal(config.provisioning, null, 'no provisioning ref means no migration capability');
});

test('a literal credential is refused instead of silently accepted', async () => {
  const env = baseEnv();
  delete env.MEM_KEK_REF;
  env.MEM_KEK = 'a-password-in-the-environment';
  await assert.rejects(
    () => loadConfig({ env, resolver: new SecretResolver({ secretsDir: SECRETS, brokerUrl: '' }) }),
    /literal value is not allowed/,
  );
  // Only the test harness may inject literals; the flag is explicit at the call site.
  const config = await load({ MEM_KEK_REF: undefined, MEM_KEK: 'a-test-value' }, { literalAllowed: true });
  assert.equal(config.kek, 'a-test-value');
});

test('the pool ceiling is enforced at boot, not discovered under load', async () => {
  // Two pools (rw + ro), so 5 per role is the agreed total of 10.
  const ok = await load({ MEM_PG_POOL_MAX_PER_ROLE: '5' });
  assert.equal(ok.pg.poolTotal, 10);
  await assert.rejects(() => load({ MEM_PG_POOL_MAX_PER_ROLE: '6' }), /exceeds the agreed ceiling of 10/);
  const floored = await load({ MEM_PG_POOL_MAX_PER_ROLE: '0' });
  assert.equal(floored.pg.maxPerRole, 1, 'a zero pool is clamped to 1, not disabled');
});

test('internal and admin ports must differ and default to 8091/8190', async () => {
  const config = await load();
  assert.equal(config.internalPort, 8091);
  assert.equal(config.adminPort, 8190);
  await assert.rejects(() => load({ MEM_ADMIN_PORT: '8091' }), /must differ/);
});

test('a provisioning ref unlocks migrations and keeps the superuser separate', async () => {
  const config = await load({ MEM_PG_PROVISIONING_REF: 'opaque-ref:mem-pg-provision-password', MEM_RUN_MIGRATIONS: '1' });
  assert.equal(config.runMigrationsOnStart, true);
  assert.equal(config.provisioning.user, 'postgres', 'the provisioning identity is explicit, not inherited');
  assert.equal(config.provisioning.password, 'super-secret-value');
  assert.notEqual(config.provisioning.password, config.pg.rw.password, 'the migration identity is not the runtime identity');
});

/* ---------------- l1 ---------------- */

const newL1 = (opts = {}) => new L1Cache({ path: ':memory:', ttlHours: 24, ...opts });

test('context slots round-trip and a repeat write refreshes the same slot', () => {
  const l1 = newL1();
  l1.putContext({ peerKey: 'p1', slot: 'topic_stack', valueJson: JSON.stringify({ items: ['a'] }) });
  l1.putContext({ peerKey: 'p1', slot: 'topic_stack', valueJson: JSON.stringify({ items: ['a', 'b'] }) });
  const ctx = l1.getContext('p1');
  assert.deepEqual(ctx.slots.topic_stack.items, ['a', 'b']);
  assert.equal(ctx.turnWindow.length, 0);
  assert.ok(ctx.ttlRemainingSeconds > 86000, 'the TTL starts near 24h');
  l1.close();
});

test('pii and secret values never enter the short-term cache', () => {
  const l1 = newL1();
  for (const sensitivity of ['pii', 'secret']) {
    assert.throws(
      () => l1.putContext({ peerKey: 'p1', slot: 'entity_alias', valueJson: '{}', sensitivity }),
      (err) => err.code === 'MEMORY_REFUSED_CATEGORY',
    );
  }
  l1.close();
});

test('expired slots are invisible and evictExpired removes them', () => {
  // Negative rather than zero: `expires_at = now` compares equal to the clock inside the
  // same millisecond, so a zero TTL makes the eviction assertion flaky.
  const l1 = newL1({ ttlHours: -1 });
  l1.putContext({ peerKey: 'p1', slot: 'last_intent', valueJson: '{"intent":"order"}' });
  assert.equal(l1.getContext('p1').exists, false, 'a zero TTL row must not be readable');
  assert.ok(l1.evictExpired() >= 1);
  l1.close();
});

test('a corrupt cached value degrades to absent instead of throwing on read', () => {
  const l1 = newL1();
  l1.db.prepare(`INSERT INTO context_entry (peer_key, slot, value_json, sensitivity, hits, created_at, expires_at, updated_at) VALUES ('p1','entity_alias','not-json','internal',1,0,9e15,0)`).run();
  const ctx = l1.getContext('p1');
  assert.equal(ctx.slots.entity_alias, null);
  assert.equal(ctx.exists, true, 'the peer is still known');
  l1.close();
});

test('the dedupe window answers repeats and forgets by memory ref', () => {
  const l1 = newL1();
  assert.deepEqual(l1.lookupDedupe('k1'), { hit: false });
  l1.rememberDedupe({ dedupeKey: 'k1', memoryKind: 'episode', memoryRef: 'm1' });
  assert.deepEqual(l1.lookupDedupe('k1'), { hit: true, ref: 'm1', kind: 'episode' });
  l1.forgetDedupe('m1');
  assert.deepEqual(l1.lookupDedupe('k1'), { hit: false });
  l1.close();
});

test('promotion needs repetition across observations, and marks as proposed suppress it', () => {
  const l1 = newL1();
  l1.recordObservation({ peerKey: 'p1', subjectKey: 'onebot:dm:1', attrKey: 'pref:spicy', valueHash: 'h1', sessionId: 's1' });
  assert.equal(l1.qualifiedPromotions().length, 0, 'a single sighting is not a preference');
  const second = l1.recordObservation({ peerKey: 'p1', subjectKey: 'onebot:dm:1', attrKey: 'pref:spicy', valueHash: 'h1', sessionId: 's1' });
  assert.equal(second.observations, 2);
  assert.equal(l1.qualifiedPromotions().length, 1);
  l1.markProposed('onebot:dm:1', 'pref:spicy', 'h1');
  assert.equal(l1.qualifiedPromotions().length, 0, 'a promoted candidate is not offered twice');
  l1.close();
});

test('rebuildFromPg discards peers PostgreSQL does not confirm', async () => {
  const l1 = newL1();
  l1.putContext({ peerKey: 'live', slot: 'topic_stack', valueJson: '{}' });
  l1.putContext({ peerKey: 'ghost', slot: 'topic_stack', valueJson: '{}' });
  const result = await l1.rebuildFromPg(async () => new Set(['live']));
  assert.equal(result.checked, 2);
  assert.equal(result.cleared, 1);
  assert.equal(l1.getContext('ghost').exists, false);
  l1.close();
});

test('health reports integrity and the page budget, never row contents', () => {
  const l1 = newL1({ maxPageCount: 400, pageSize: 4096 });
  const health = l1.health();
  assert.equal(health.up, true);
  assert.equal(health.integrity, 'ok');
  assert.ok(health.dbBytes > 0 && health.pageCapPct >= 0);
  assert.ok(!JSON.stringify(health).includes('topic_stack'));
  l1.close();
});

/* ---------------- projection cache ---------------- */

const newCache = (l1 = newL1(), searchTtlMs = 60_000) =>
  new MemoryCache({ l1, ddl: sqliteCacheDdl(), searchTtlMs });

test('only cacheable rows are projected into SQLite', () => {
  const l1 = newL1();
  const cache = newCache(l1);
  const base = { memoryId: 'm1', kind: 'episode', class: 'episode', body: '普通内容', sensitivity: 'internal', visibility: 'private' };
  assert.equal(cache.put(base), true);
  assert.equal(cache.put({ ...base, memoryId: 'm2', sensitivity: 'pii' }), false, 'pii never lands in the cache');
  assert.equal(cache.put({ ...base, memoryId: 'm3', sensitivity: 'secret' }), false);
  assert.equal(cache.put({ ...base, memoryId: 'm4', visibility: 'admin' }), false, 'admin-only rows stay in PG');
  assert.equal(cache.put({ ...base, memoryId: undefined }), false);
  assert.equal(cache.stats().rows, 1);
  l1.close();
});

test('a write bumps the generation and invalidates every projection', () => {
  const l1 = newL1();
  const cache = newCache(l1);
  cache.put({ memoryId: 'm1', kind: 'episode', class: 'episode', body: 'a', sensitivity: 'internal', visibility: 'private' });
  cache.putSearch('key-1', ['m1'], false, { strategy: 'trgm' });
  assert.deepEqual(cache.lookupSearch('key-1').memoryIds, ['m1']);
  const gen = cache.generation();
  cache.bumpGeneration();
  assert.equal(cache.generation(), gen + 1);
  assert.equal(cache.lookupSearch('key-1'), null, 'a stale search projection must not answer');
  assert.equal(cache.get('m1'), null, 'a stale row projection must not answer');
  l1.close();
});

test('a projection cannot be stored under a generation that already moved on', () => {
  const l1 = newL1();
  const cache = newCache(l1);
  const gen = cache.generation();
  cache.putSearch('k', ['m1'], false, {}, gen);
  cache.bumpGeneration();
  assert.equal(cache.putSearch('k2', ['m1'], false, {}, gen), false, 'the write raced the projection: drop it');
  assert.equal(cache.putSearch('k3', ['m1'], false, {}, null), true, 'without a guard the store still works');
  l1.close();
});

test('evictExpired removes timed-out search projections', () => {
  const l1 = newL1();
  // A negative TTL writes `expires_at` in the past: asserting against a 1 ms TTL would
  // pass or fail on the clock's millisecond resolution, not on the eviction logic.
  const cache = newCache(l1, -1);
  cache.putSearch('k', ['m1']);
  assert.equal(cache.evictExpired(), 1);
  assert.equal(cache.lookupSearch('k'), null);
  l1.close();
});

test('evictExpired also collects rows left behind by a generation bump', () => {
  const l1 = newL1();
  const cache = newCache(l1);
  cache.put({ memoryId: 'm1', kind: 'episode', class: 'episode', body: 'a', sensitivity: 'internal', visibility: 'private' });
  assert.equal(cache.get('m1') !== null, true, 'the row is served before the bump');
  cache.bumpGeneration(); // a bump clears *search* projections, not row projections
  assert.equal(cache.stats().rows, 1, 'the stale row is still physically present');
  assert.ok(cache.evictExpired() >= 1, 'maintenance is what reclaims it');
  assert.equal(cache.stats().rows, 0);
  l1.close();
});

test('the cache can be checkpointed to a backup file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'memtest-backup-'));
  const file = join(dir, 'l1-backup.sqlite');
  const l1 = newL1();
  const cache = newCache(l1);
  cache.put({ memoryId: 'm1', kind: 'episode', class: 'episode', body: 'a', sensitivity: 'internal', visibility: 'private' });
  cache.backupTo(file);
  assert.ok(existsSync(file));
  assert.ok(statSync(file).size > 0);
  l1.close();
});

/* ---------------- jobs ---------------- */

function schedulerWith(stubs = {}) {
  const l1 = newL1();
  const cache = newCache(l1);
  const emitted = [];
  const jobs = new JobScheduler({
    l1,
    cache,
    repo: stubs.repo || {},
    pg: stubs.pg || { query: async () => ({ rows: [{ n: 0 }] }) },
    config: { jobs: { l1EvictIntervalMinutes: 60, purgeIntervalMinutes: 1440, pruneAccessKeepDays: 365 }, backup: { enabled: false } },
    audit: { emit: (type, fields) => emitted.push({ type, ...fields }) },
  });
  return { jobs, l1, cache, emitted };
}

test('four maintenance jobs are defined with the configured periods', () => {
  const { jobs, l1 } = schedulerWith();
  const defs = jobs.definitions();
  assert.deepEqual(defs.map((d) => d.name).sort(), ['cache_backup', 'l1_evict', 'prune_access_log', 'purge_expired']);
  assert.equal(defs.find((d) => d.name === 'l1_evict').everyMs, 60 * 60_000);
  assert.equal(defs.find((d) => d.name === 'purge_expired').everyMs, 1440 * 60_000);
  jobs.start();
  assert.equal(jobs.timers.length, 4);
  jobs.stop();
  assert.equal(jobs.timers.length, 0, 'stop must leave no timer behind (clean shutdown)');
  l1.close();
});

test('a manual run reports the job result and a heartbeat for /healthz', async () => {
  const { jobs, l1 } = schedulerWith();
  const out = await jobs.runNow('l1_evict');
  assert.equal(out.ok, true);
  assert.equal(out.job, 'l1_evict');
  assert.equal(jobs.heartbeat()[0].job, 'l1_evict');
  assert.ok(Array.isArray(jobs.status()));
  assert.equal((await jobs.runNow('nope')).error, 'unknown job');
  l1.close();
});

test('a failing job is contained, audited, and never crashes the service', async () => {
  const { jobs, l1, emitted } = schedulerWith({
    repo: {
      purgeExpired: async () => {
        throw new Error('purge exploded');
      },
    },
    pg: {
      query: async () => {
        throw new Error('purge exploded');
      },
    },
  });
  const out = await jobs.runNow('purge_expired');
  assert.equal(out.ok, false);
  assert.equal(out.error, 'job failed');
  assert.ok(emitted.some((e) => e.job === 'purge_expired'), 'the failure must be audited');
  assert.equal(jobs.status().find((s) => s.job === 'purge_expired').ok, false);
  l1.close();
});

test('the backup job stays silent when backups are disabled', async () => {
  const { jobs, l1 } = schedulerWith();
  const out = await jobs.runNow('cache_backup');
  assert.equal(out.ok, true);
  assert.deepEqual(out.result, { skipped: true });
  l1.close();
});

/* ---------------- text normalization ---------------- */

test('trigram retrieval keys on bytes, which is why the C-locale database works', () => {
  assert.deepEqual(MEMORY_CLASSES.includes('pii_raw'), true);
  assert.deepEqual(SENSITIVITIES, ['public', 'internal', 'pii', 'secret']);
  const norm = normalizeText('  不吃   香菜 \"; DROP TABLE memory; -- ');
  assert.ok(norm.includes('不吃'), 'the CJK content survives');
  assert.ok(!norm.includes('\"') && !norm.includes(';'), 'quote/semicolon noise is stripped (dedupe, not injection defence)');
  assert.equal(norm, norm.toLowerCase(), 'normalisation is case-folded');
  const tri = byteTrigrams('不吃香菜');
  assert.ok(tri instanceof Set, 'trigrams are a Set, so the array form cannot be empty by accident');
  assert.ok(tri.size >= 2, `expected byte trigrams, got ${tri.size}`);
  assert.ok([...tri].every((h) => /^[0-9a-f]{6}$/.test(h)), 'each trigram is three bytes in hex — that is why a C-locale DB works');
  assert.deepEqual([...byteTrigrams('ab')], [...byteTrigrams('ab')], 'deterministic');
  assert.equal(byteTrigrams('').size, 0, 'an empty query produces no trigrams, not a crash');
});

test('the SQLite DDL is applied from the shipped file, not duplicated in code', () => {
  const ddl = sqliteDdl();
  assert.match(ddl, /CREATE TABLE IF NOT EXISTS context_entry/);
  assert.match(ddl, /CHECK\s*\(\s*sensitivity\s+IN\s*\(\s*'public',\s*'internal'/i, 'the CHECK that keeps pii out of L1');
  assert.match(sqliteCacheDdl(), /CREATE TABLE IF NOT EXISTS memory_cache/);
});
