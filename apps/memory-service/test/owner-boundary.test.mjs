/**
 * Review R2 regression: the owner exemption is identity-bound, not role-bound.
 *
 * whitelist.json legitimately carries one owner entry per channel (onebot + telegram),
 * and the gateway only *warns* about the second cross-channel owner. Before R2, the
 * retrieval predicate and assertVisible checked `role = 'owner'` alone, so the telegram
 * "owner" could read every private row belonging to the QQ master. These tests pin the
 * fixed semantics against a fake pg (no database server needed): the real SQL predicate
 * carries the same identity bindings, and scripts/integration-memory.mjs runs it on PG.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryRepository } from '../src/repository.mjs';

const MASTER = '1035376945';
const TG_OWNER = '777000000';
const MASTER_SUBJECT = '11111111-2222-3333-4444-555555555555';
const ROW_UUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

const qqOwner = () => ({ channel: 'onebot', chatId: MASTER, userId: MASTER, role: 'owner' });
const tgOwner = () => ({ channel: 'telegram', chatId: TG_OWNER, userId: TG_OWNER, role: 'owner' });
const trusted = () => ({ channel: 'onebot', chatId: '900000001', userId: '900000001', role: 'trusted' });

/** Row as the PG view returns it (snake_case). */
const privateRow = (over = {}) => ({
  memory_id: ROW_UUID,
  kind: 'episode',
  subject_id: MASTER_SUBJECT,
  peer_key: `onebot:${MASTER}`,
  class: 'preference',
  body_plain: '主人喜欢香菜',
  body_enc: null,
  sensitivity: 'internal',
  visibility: 'private',
  occurred_at: new Date().toISOString(),
  expires_at: null,
  hit_count: 0,
  confidence: 0.5,
  risk_tags: [],
  source_channel: 'onebot',
  ...over,
});

function fakePg({ rows = [] } = {}) {
  const calls = [];
  return {
    calls,
    async query(mode, sql, params) {
      calls.push({ mode, sql, params });
      if (sql.includes('FROM companion.subject WHERE subject_key')) {
        // identity is per-subject-key: only the QQ master's DM key resolves to their uuid
        const hit = params[0] === `onebot:dm:${MASTER}` ? MASTER_SUBJECT : '99999999-8888-7777-6666-555555555555';
        return { rows: [{ subject_id: hit, identity_trust: 'server_backed', is_owner: true }] };
      }
      if (sql.includes('memory_readable')) return { rows };
      return { rows: [] };
    },
  };
}

const repo = (pg) => new MemoryRepository({ pg, l1: null, cache: null, config: { maxSearchRows: 10, maxSearchChars: 4000 } });

/* ---------------- assertVisible: the role bit alone must not open anything ---------------- */

test('R2: assertVisible is identity-bound, not role-bound', () => {
  const r = repo(fakePg());

  // the cross-channel owner cannot see the master's private row at all
  assert.throws(() => r.assertVisible(privateRow(), tgOwner()), (e) => e.status === 404);
  // ...same for the owner-visibility notebook class
  assert.throws(() => r.assertVisible(privateRow({ visibility: 'owner' }), tgOwner()), (e) => e.status === 404);
  // ...and for foreign peer-bound rows
  assert.throws(() => r.assertVisible(privateRow({ visibility: 'peer' }), tgOwner()), (e) => e.status === 404);

  // the real master reads their own private and owner rows
  const master = { ...qqOwner(), dmSubjectId: MASTER_SUBJECT };
  r.assertVisible(privateRow(), master);
  r.assertVisible(privateRow({ visibility: 'owner' }), master);

  // a second-owner row filed under the TG subject is *not* the master's row
  assert.throws(
    () => r.assertVisible(privateRow({ peer_key: `telegram:${TG_OWNER}`, subject_id: 'tg-uuid' }), master),
    (e) => e.status === 404,
  );

  // trusted peers keep their own DM and lose foreign ones (unchanged behaviour)
  r.assertVisible(privateRow({ peer_key: 'onebot:900000001', subject_id: 'x' }), trusted());
  assert.throws(() => r.assertVisible(privateRow(), trusted()), (e) => e.status === 404);

  // L1 cache shape (camelCase) enforces the same rule
  const cached = { memoryId: ROW_UUID, subjectId: MASTER_SUBJECT, peerKey: `onebot:${MASTER}`, visibility: 'private', body: 'x', sensitivity: 'internal', class: 'preference', kind: 'episode' };
  assert.throws(() => r.assertVisible(cached, tgOwner()), (e) => e.status === 404);
  r.assertVisible(cached, master);
});

/* ---------------- read(): the single-row path enforces it end-to-end ---------------- */

test('R2: read() as the telegram owner 404s on the master private row', async () => {
  const pg = fakePg({ rows: [privateRow()] });
  const r = repo(pg);
  await assert.rejects(r.read(ROW_UUID, tgOwner()), (e) => e.code === 'ACL_DENIED' && e.status === 404);
});

test('R2: read() as the real owner resolves their DM subject and returns the row', async () => {
  const pg = fakePg({ rows: [privateRow()] });
  const r = repo(pg);
  const out = await r.read(ROW_UUID, qqOwner());
  assert.equal(out.body, '主人喜欢香菜');
  const subjCall = pg.calls.find((c) => c.sql.includes('FROM companion.subject WHERE subject_key'));
  assert.deepEqual(subjCall.params, [`onebot:dm:${MASTER}`], 'the DM subject key is looked up by identity');
});

/* ---------------- search(): the SQL predicate is bound, parameters carry the identity ---------------- */

test('R2: search() binds the owner bypass to identity in SQL, not to the bare role', async () => {
  const pg = fakePg();
  const r = repo(pg);
  await r.search({ query: '香菜' }, qqOwner());

  const ep = pg.calls.find((c) => c.sql.includes('FROM companion.memory_episode e'));
  assert.ok(ep, 'the episode leg ran');
  assert.ok(
    /\$3 = 'owner' AND \(e\.peer_key = \$1 \|\| ':' \|\| \$5 OR e\.subject_id = \$6\)/.test(ep.sql),
    'the owner bypass in the episode predicate is identity-bound',
  );
  assert.ok(!/OR \$3 = 'owner'\)/.test(ep.sql), 'no bare role-only owner bypass remains');
  assert.deepEqual([ep.params[0], ep.params[1], ep.params[4], ep.params[5]], ['onebot', MASTER, MASTER, MASTER_SUBJECT]);

  const kv = pg.calls.find((c) => c.sql.includes('FROM companion.user_profile p'));
  const pref = pg.calls.find((c) => c.sql.includes('FROM companion.user_preference f'));
  assert.ok(/p\.visibility <> 'owner' OR \(\$2 = 'owner' AND p\.subject_id = \$5\)/.test(kv.sql));
  assert.ok(/f\.visibility <> 'owner' OR \(\$2 = 'owner' AND f\.subject_id = \$5\)/.test(pref.sql));
  assert.equal(kv.params[4], MASTER_SUBJECT);

  // the foreign owner binds to its own (different) subject: the master's rows never match
  const pg2 = fakePg();
  const r2 = repo(pg2);
  await r2.search({ query: '香菜' }, tgOwner());
  const ep2 = pg2.calls.find((c) => c.sql.includes('FROM companion.memory_episode e'));
  assert.equal(ep2.params[0], 'telegram');
  assert.notEqual(ep2.params[5], MASTER_SUBJECT, 'the telegram owner resolves a different subject — the master rows cannot match');
});

/* ---------------- context endpoints: same identity binding ---------------- */

test('R2: getContext refuses the cross-channel owner, allows the real owner', () => {
  const r = repo(fakePg());
  const l1 = { getContext: () => ({ value: {} }) };
  r.l1 = l1;
  assert.throws(() => r.getContext(`onebot:${MASTER}`, tgOwner()), (e) => e.status === 403);
  r.getContext(`onebot:${MASTER}`, qqOwner()); // same-channel owner bypasses on their own channel slots
  assert.throws(() => r.getContext('onebot:group:123', trusted()), (e) => e.status === 403);
});

/* ---------------- forget(): deletion stays a role capability ---------------- */

test('R2: forget remains role-gated and is not blocked by the identity-bound read rule', async () => {
  const pg = fakePg({
    rows: [{ memory_id: ROW_UUID, kind: 'episode', class: 'preference', sensitivity: 'internal', body_hash: 'h', body_plain: '合成号测试数据' }],
  });
  const r = repo(pg);
  const res = await r.forget(ROW_UUID, { principal: qqOwner(), dryRun: true });
  assert.equal(res.dryRun, true, 'the owner may tombstone a foreign-subject row (dry-run shows the preview)');
  await assert.rejects(r.forget(ROW_UUID, { principal: trusted(), dryRun: true }), (e) => e.code === 'FORBIDDEN_ROLE');
});
