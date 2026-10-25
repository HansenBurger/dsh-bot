import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildNormalized } from '@dsh-bot/bot-normalize';
import { createGateway } from '../src/index.mjs';
import { IntakeServer } from '../../../apps/bot-core/src/intake.mjs';

const SECRET = 'test-hmac-secret-value-1234';

const msg = (over = {}) =>
  buildNormalized({
    channel: 'onebot',
    peer: { kind: 'group', chatId: over.chatId ?? '900' },
    sender: { userId: over.userId ?? '111' },
    text: over.text ?? '今天天气不错',
    rawRef: { messageId: over.messageId ?? String(Date.now() + Math.random()) },
    receivedAt: Date.now(),
  });

async function boot({ whitelist, env = {} }) {
  const dir = mkdtempSync(join(tmpdir(), 'gw-test-'));
  const auditPath = join(dir, 'ingress.jsonl');
  const policyPath = join(dir, 'whitelist.json');
  writeFileSync(policyPath, JSON.stringify(whitelist));
  // Fake agent side: the real IntakeServer, so the SUB contract is exercised end to end.
  const seen = [];
  const intake = new IntakeServer({
    hmacSecret: SECRET,
    port: 0,
    bind: '127.0.0.1',
    onMessage: async ({ message, principal }) => {
      seen.push({ text: message.text, principal });
      return { reply: `已收到：${message.text}` };
    },
  });
  await intake.start();
  const gw = await createGateway({
    env: {
      NODE_ENV: 'test',
      AUDIT_SINK: auditPath,
      WHITELIST_PATH: policyPath,
      SUBMIT_HMAC_KEY_REF: SECRET,
      BOT_CORE_SUBMIT_URL: `http://127.0.0.1:${intake.server.address().port}/submit`,
      DEGRADED_FLAG_PATH: join(dir, 'no-such-flag'),
      OB11_LISTEN: 'off',
      GATEWAY_ADMIN_PORT: '0',
      ...env,
    },
  });
  return { gw, intake, seen, auditPath, dir };
}

const auditLines = (p) => readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);

test('non-whitelisted user_id is refused before submission and audited (acceptance #2)', async () => {
  const { gw, intake, seen, auditPath } = await boot({
    whitelist: { defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '900', userId: '111', role: 'owner' }] },
  });
  const receipt = await gw.handleMessage(msg({ userId: '999999' }));

  assert.equal(receipt.action, 'refused');
  assert.equal(seen.length, 0, 'a refused message must never reach the agent');
  const lines = auditLines(auditPath);
  const denied = lines.find((l) => l.type === 'authz.decision' && l.result === 'denied');
  assert.ok(denied, 'deny must be audit-logged');
  assert.equal(denied.reason, 'not-whitelisted');
  assert.equal(denied.stage, 'gate');
  // Structured ids only: no display name is ever consulted or logged (A1/A2).
  assert.equal(denied.structuredIds, true);
  assert.ok(!JSON.stringify(lines).includes('nickname'));
  await gw.close();
  await intake.stop();
});

test('whitelisted owner is submitted and the reply comes back through the same hop', async () => {
  const { gw, intake, seen, auditPath } = await boot({
    whitelist: { defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '900', userId: '111', role: 'owner' }] },
  });
  const receipt = await gw.handleMessage(msg({ text: '记住我不吃香菜' }));
  assert.equal(receipt.action, 'submitted');
  assert.equal(receipt.role, 'owner');
  assert.equal(seen.length, 1);
  assert.equal(seen[0].principal.role, 'owner');
  assert.equal(seen[0].principal.userId, '111');
  const allowed = auditLines(auditPath).find((l) => l.result === 'allowed' && l.stage === 'gate');
  assert.equal(allowed.role, 'owner');
  await gw.close();
  await intake.stop();
});

test('display-name entries cannot authorize anyone: only structured ids are keys', async () => {
  const { gw, intake, seen } = await boot({
    whitelist: { defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '900', userId: '111', role: 'owner', name: '大鱼' }] },
  });
  const byName = await gw.handleMessage({ ...msg({ userId: '大鱼' }), sender: { userId: '大鱼' } });
  assert.equal(byName.action, 'refused');
  // A different account with the same nickname must still be refused.
  const other = await gw.handleMessage(msg({ userId: '222' }));
  assert.equal(other.action, 'refused');
  assert.equal(seen.length, 0);
  await gw.close();
  await intake.stop();
});

test('duplicate frames are dropped inside the dedupe window', async () => {
  const { gw, intake, seen } = await boot({
    whitelist: { defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '900', userId: '111', role: 'trusted' }] },
  });
  const frame = msg({ messageId: 'fixed-1' });
  assert.equal((await gw.handleMessage(frame)).action, 'submitted');
  assert.equal((await gw.handleMessage(msg({ messageId: 'fixed-1' }))).action, 'deduped');
  assert.equal(seen.length, 1);
  await gw.close();
  await intake.stop();
});

test('rate limit stops a flooding sender after the per-sender budget', async () => {
  const { gw, intake, seen } = await boot({
    whitelist: { defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '900', userId: '111', role: 'trusted' }] },
    env: { RATE_SENDER_PER_MIN: '2', RATE_CHAT_PER_MIN: '100', RATE_GLOBAL_PER_MIN: '100' },
  });
  const results = [];
  for (let i = 0; i < 4; i += 1) results.push((await gw.handleMessage(msg({ messageId: `m${i}` }))).action);
  assert.deepEqual(results, ['submitted', 'submitted', 'throttled', 'throttled']);
  assert.equal(seen.length, 2);
  await gw.close();
  await intake.stop();
});

test('degraded flag rejects everything without touching the agent (E3)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'gw-degraded-'));
  writeFileSync(join(dir, 'flag'), 'halt by owner');
  const { gw, intake, seen } = await boot({
    whitelist: { defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '900', userId: '111', role: 'owner' }] },
    env: { DEGRADED_FLAG_PATH: join(dir, 'flag') },
  });
  const receipt = await gw.handleMessage(msg());
  assert.equal(receipt.action, 'degraded');
  assert.equal(seen.length, 0);
  await gw.close();
  await intake.stop();
});

test('an unreachable agent fails closed and is reported as submit-failed', async () => {
  const { gw, intake } = await boot({
    whitelist: { defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '900', userId: '111', role: 'owner' }] },
  });
  await intake.stop();
  const receipt = await gw.handleMessage(msg());
  assert.equal(receipt.action, 'submit-failed');
  assert.equal(receipt.reason, 'agent-unreachable');
  await gw.close();
});

test('a missing or invalid whitelist policy refuses to start (no open gate)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'gw-badpolicy-'));
  const bad = join(dir, 'whitelist.json');
  writeFileSync(bad, '{"defaultRole":"trusted","entries":[]}');
  await assert.rejects(
    createGateway({ env: { NODE_ENV: 'test', AUDIT_SINK: join(dir, 'a.jsonl'), WHITELIST_PATH: bad, SUBMIT_HMAC_KEY_REF: SECRET, OB11_LISTEN: 'off', GATEWAY_ADMIN_PORT: '0' } }),
    /invalid/,
  );
  await assert.rejects(
    createGateway({ env: { NODE_ENV: 'test', AUDIT_SINK: join(dir, 'b.jsonl'), WHITELIST_PATH: join(dir, 'absent.json'), SUBMIT_HMAC_KEY_REF: SECRET, OB11_LISTEN: 'off', GATEWAY_ADMIN_PORT: '0' } }),
    /missing/,
  );
});

test('gateway refuses to boot without a signing secret', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'gw-nosecret-'));
  const policyPath = join(dir, 'whitelist.json');
  writeFileSync(policyPath, JSON.stringify({ defaultRole: 'public', entries: [] }));
  await assert.rejects(
    createGateway({
      env: { AUDIT_SINK: join(dir, 'a.jsonl'), WHITELIST_PATH: policyPath, SUBMIT_HMAC_KEY_REF: 'opaque-ref:missing-submit-key', SECRETS_DIR: join(dir, 'none'), OB11_LISTEN: 'off', GATEWAY_ADMIN_PORT: '0' },
    }),
    /cannot resolve/,
  );
});
