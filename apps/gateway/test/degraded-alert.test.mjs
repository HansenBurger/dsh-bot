/**
 * E3 round trip: watcher writes the kill flag → the gateway's intake fails closed, and
 * the alert file the watcher drops in the queue is relayed to the owner over the existing
 * `send_private_msg` return path.
 *
 * Both halves are asserted in one place because DEV-19 was exactly this missing seam: the
 * producer (ops/watcher) and the consumer (gateway) existed separately and never met.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, readdirSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { buildNormalized } from '@dsh-bot/bot-normalize';
import { createServer } from 'node:http';
import { createGateway } from '../src/index.mjs';

const SECRET = 'test-hmac-secret-value-1234';
const OWNER = '1035376945';

async function boot({ degradedFlag, alertQueue } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'gw-degraded-'));
  const auditPath = join(dir, 'ingress.jsonl');
  const policyPath = join(dir, 'whitelist.json');
  writeFileSync(policyPath, JSON.stringify({ defaultRole: 'public', entries: [{ channel: 'onebot', chatId: OWNER, userId: OWNER, role: 'owner' }] }));
  const flagPath = degradedFlag ? join(dir, 'degraded') : join(dir, 'no-such-flag');
  if (degradedFlag) writeFileSync(flagPath, degradedFlag, 'utf8');
  let queueDir = null;
  if (alertQueue) {
    queueDir = join(dir, 'alerts');
    mkdirSync(join(queueDir, 'pending'), { recursive: true });
    for (const [name, body] of Object.entries(alertQueue)) writeFileSync(join(queueDir, 'pending', `${name}.json`), JSON.stringify(body), 'utf8');
  }

  const sent = [];
  const submits = [];
  // A stand-in agent plane that records whether anything was ever submitted to it: the
  // whole point of E3 is that a degraded intake never reaches the model path.
  const stub = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      submits.push(body);
      res.writeHead(500, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'agent-plane-must-not-be-called' }));
    });
  });
  await new Promise((r) => stub.listen(0, '127.0.0.1', r));
  const gw = await createGateway({
    env: {
      NODE_ENV: 'test',
      AUDIT_SINK: auditPath,
      WHITELIST_PATH: policyPath,
      SUBMIT_HMAC_KEY_REF: SECRET,
      BOT_CORE_SUBMIT_URL: `http://127.0.0.1:${stub.address().port}/submit`,
      DEGRADED_FLAG_PATH: flagPath,
      OB11_LISTEN: 'off',
      GATEWAY_ADMIN_PORT: '0',
      ALERT_QUEUE_DIR: queueDir || '',
      ALERT_OWNER_QQ: OWNER,
      ALERT_RELAY_INTERVAL_MS: '3600000', // one manual pass only; the test drives drain()
      ALERT_RELAY_MAX_QUEUE: '20',
    },
  });
  // The adapter is off in this harness (no reverse-WS peer), so stand in for the send leg.
  if (gw.alertRelay) {
    gw.alertRelay.send = async (text) => {
      sent.push(text);
      return { ok: true };
    };
  }
  const stop = async () => {
    await gw.close();
    await new Promise((r) => stub.close(r));
    rmSync(dir, { recursive: true, force: true });
  };
  return { gw, stub, submits, seen: [], auditPath, dir, sent, flagPath, stop };
}

const msg = (over = {}) =>
  buildNormalized({
    channel: 'onebot',
    peer: { kind: 'dm', chatId: over.chatId ?? OWNER },
    sender: { userId: over.userId ?? OWNER },
    text: over.text ?? '还在吗',
    rawRef: { messageId: String(Date.now() + Math.random()) },
    receivedAt: Date.now(),
  });

const auditLines = (p) => readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);

test('a watcher-authored flag makes intake fail closed before the whitelist and before the LLM', async () => {
  const flag = { managed_by: 'ops/watcher', opened_at: '2026-10-25T10:55:57.644Z', reasons: [{ key: 'E3-health-probe:memory', kind: 'availability', summary: '必需依赖 memory 连续 4 次探测失败' }] };
  const { gw, submits, auditPath, dir, stop } = await boot({ degradedFlag: JSON.stringify(flag, null, 2) });
  const receipt = await gw.handleMessage(msg());

  assert.deepEqual(receipt, { action: 'degraded' }, 'the owner is refused while the circuit is open');
  assert.equal(gw.state.gate.degraded, 1, 'the degraded counter moved');
  assert.deepEqual(submits, [], 'zero submissions ⇒ zero LLM tokens while degraded');
  const denied = auditLines(auditPath).find((l) => l.type === 'authz.decision' && l.reason === 'degraded-flag');
  assert.ok(denied, 'E2/E3: the refusal is auditable');
  assert.equal(denied.result, 'denied');
  await stop();
});

test('the alert queue the watcher writes is relayed to the owner in the fixed template', async () => {
  const { gw, auditPath, dir, sent, stop } = await boot({
    alertQueue: { 'mvnppe3l-breaker-open': { id: 'mvnppe3l-breaker-open', ts: 1, at: '2026-10-25T10:55:57.644Z', type: 'breaker-open', service: 'ops-watchdog', state: 'degraded', severity: 'critical', summary: '这段正文不会被发给主人' } },
  });
  const results = await gw.alertRelay.drain();
  assert.deepEqual(results, [{ name: 'mvnppe3l-breaker-open.json', action: 'delivered' }]);
  assert.equal(sent.length, 1);
  assert.equal(sent[0], '[watcher 告警] breaker-open · ops-watchdog · degraded · 2026-10-25T10:55:57.644Z');
  assert.doesNotMatch(sent.join(''), /正文|不会被发给主人|这段/, 'constraint 1: queue prose never reaches the owner');
  const delivered = auditLines(auditPath).find((l) => l.stage === 'alert-relay' && l.event === 'delivered');
  assert.ok(delivered, 'F2: the delivery is in the audit trail, with no LLM in the path');
  assert.equal(existsSync(join(dir, 'alerts', 'sent', 'mvnppe3l-breaker-open.json')), true);
  await stop();
});

test('an unconfigured ALERT_QUEUE_DIR leaves the gateway exactly as it was (no relay, no new listener)', async () => {
  const { gw, dir, stop } = await boot({});
  assert.equal(gw.alertRelay, null);
  assert.equal(readdirSync(join(dir)).filter((n) => n === 'alerts').length, 0);
  await stop();
});
