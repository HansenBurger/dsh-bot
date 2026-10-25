/**
 * T9-F8 — the memory access ledger must be a *dual*-write: JSONL first (source of
 * truth, F3/§5.5), PG as the query view. Before the fix `logAccess` only INSERTed, so
 * the bot-audit header promise was the opposite of reality and a PG outage silently
 * erased the access trail. These tests pin both halves, including that a PG failure
 * cannot take the JSONL mirror down with it.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { MemoryRepository } from '../src/repository.mjs';

function collectingAudit() {
  const emitted = [];
  return { emitted, emit: (type, fields) => { emitted.push({ type, ...fields }); return {}; } };
}

/** Fake pg: records queries, optionally fails the access-log INSERT. */
function fakePg({ failInsert = false } = {}) {
  const calls = [];
  return {
    calls,
    async query(mode, sql, params) {
      calls.push({ mode, sql, params });
      if (sql.includes('INSERT INTO companion.memory_access_log')) {
        if (failInsert) throw new Error('pg down');
        return { rows: [{ log_id: 42 }] };
      }
      return { rows: [] };
    },
  };
}

const repo = (pg, audit) => new MemoryRepository({ pg, l1: null, cache: null, audit, config: { maxSearchRows: 10, maxSearchChars: 4000 } });

const owner = { channel: 'onebot', chatId: '900', userId: '111', role: 'owner' };

test('logAccess: the JSONL mirror goes out with the same ledger fields the PG row carries', async () => {
  const pg = fakePg();
  const audit = collectingAudit();
  const r = repo(pg, audit);
  const id = await r.logAccess({
    principal: owner,
    operation: 'search',
    objectRef: 'deadbeef'.repeat(8), // a sha256-shaped query hash
    result: 'allowed',
    approved: true,
    riskTags: [],
    rowsReturned: 3,
    bytesOut: 512,
    latencyMs: 7,
  });
  assert.equal(id, 'al-42', 'the PG view still returns its log id');
  assert.equal(audit.emitted.length, 1);
  const rec = audit.emitted[0];
  assert.equal(rec.type, 'memory.access');
  assert.equal(rec.operation, 'search');
  assert.equal(rec.result, 'allowed');
  assert.equal(rec.channel, 'onebot');
  assert.equal(rec.userId, '111');
  assert.equal(rec.rowsReturned, 3);
  assert.equal(rec.latencyMs, 7);
  // the INSERT half still happens (dual-write, not a replacement):
  assert.ok(pg.calls.some((c) => c.sql.includes('INSERT INTO companion.memory_access_log')));
});

test('logAccess: a PG outage must not lose the source-of-truth mirror', async () => {
  const pg = fakePg({ failInsert: true });
  const audit = collectingAudit();
  const r = repo(pg, audit);
  const id = await r.logAccess({ principal: owner, operation: 'read', objectRef: 'm-1', result: 'allowed' });
  assert.equal(id, 'al-unavailable', 'PG side behaves exactly as before (stderr keeps the alarm)');
  assert.equal(audit.emitted.length, 1);
  assert.equal(audit.emitted[0].type, 'memory.access');
  assert.equal(audit.emitted[0].operation, 'read');
});

test('logAccess: denials land in the mirror too — the ledger is not a success log', async () => {
  const audit = collectingAudit();
  const r = repo(fakePg(), audit);
  await r.logAccess({ principal: { channel: 'onebot', chatId: '900', userId: '222', role: 'trusted' }, operation: 'read', objectRef: 'm-x', result: 'denied', approved: false, riskTags: ['peer-boundary'] });
  assert.equal(audit.emitted[0].result, 'denied');
  assert.deepEqual(audit.emitted[0].riskTags, ['peer-boundary']);
});

test('logAccess: no audit sink means no crash (the sink is injected, may be absent in tests)', async () => {
  const r = repo(fakePg(), null);
  const id = await r.logAccess({ principal: owner, operation: 'write', objectRef: 'm-1', result: 'allowed' });
  assert.equal(id, 'al-42');
});
