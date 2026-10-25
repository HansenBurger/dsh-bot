import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, appendFileSync, rmSync, mkdirSync, renameSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:net';
import { loadConfig, parseTargets } from '../src/config.mjs';
import { JsonlTailer } from '../src/tail.mjs';
import { DetectionEngine } from '../src/rules.mjs';
import { Breaker, MANAGED_BY } from '../src/breaker.mjs';
import { AlertDispatcher, renderAlert, redactAlert } from '../src/alert.mjs';
import { HealthState, tcpProbe } from '../src/probe.mjs';
import { createWatcher } from '../src/index.mjs';

const dir = () => mkdtempSync(join(tmpdir(), 'watcher-test-'));
const line = (o) => `${JSON.stringify(o)}\n`;

/* ------------------------------------------------------------------ config */

test('parseTargets reads the compose-style target list and its required flag', () => {
  const targets = parseTargets('broker=tcp://172.28.3.30:8080:required,proxy=tcp://172.28.3.40:3128:optional,bad= nonsense,m=http://172.28.3.50:8091/healthz:required');
  assert.equal(targets.length, 3);
  assert.deepEqual([targets[2].path, targets[2].scheme, targets[2].required], ['/healthz', 'http', true]);
  assert.deepEqual(
    targets.map((t) => [t.name, t.host, t.port, t.required]),
    [
      ['broker', '172.28.3.30', 8080, true],
      ['proxy', '172.28.3.40', 3128, false],
      ['m', '172.28.3.50', 8091, true],
    ],
  );
});

test('the default config matches the net-ops topology declared in compose.yaml', () => {
  const config = loadConfig({});
  const names = config.targets.map((t) => t.name);
  assert.deepEqual(names.sort(), ['broker', 'memory', 'proxy']);
  assert.equal(config.targets.find((t) => t.name === 'broker').host, '172.28.3.30');
  assert.equal(config.failThreshold, 3);
  assert.equal(config.alert.dryRun, true, 'alerts must not send by default (hard discipline: 不发真实 QQ 消息)');
  assert.equal(config.degradedFlagPath, '/state/degraded', 'the path the gateway reads (E2)');
});

/* -------------------------------------------------------------------- tail */

test('tailer reads only what was appended since the last call', () => {
  const d = dir();
  const path = join(d, 'a.jsonl');
  const tailer = new JsonlTailer({ paths: [path] });
  writeFileSync(path, line({ type: 'x', n: 1 }));
  assert.deepEqual(tailer.read().map((r) => r.n), [1]);
  appendFileSync(path, line({ type: 'x', n: 2 }));
  assert.deepEqual(tailer.read().map((r) => r.n), [2], 'no re-read of old lines');
  appendFileSync(path, line({ type: 'x', n: 3 }) + line({ type: 'x', n: 4 }));
  assert.deepEqual(tailer.read().map((r) => r.n), [3, 4]);
  assert.deepEqual(tailer.read(), [], 'an idle tick yields nothing');
  rmSync(d, { recursive: true, force: true });
});

test('tailer survives bot-audit rotation (rename+create) and a partial trailing line', () => {
  const d = dir();
  const path = join(d, 'a.jsonl');
  const tailer = new JsonlTailer({ paths: [path] });
  writeFileSync(path, line({ type: 'x', n: 1 }) + line({ type: 'x', n: 1 }));
  tailer.read();
  renameSync(path, `${path}.old`);
  writeFileSync(path, line({ type: 'x', n: 2 })); // rotation: the new file is shorter than the offset
  assert.deepEqual(tailer.read().map((r) => r.n), [2], 'restarts from 0 after rotation instead of skipping the new file');
  appendFileSync(path, '{"type":"x","n":3'); // truncated write
  assert.deepEqual(tailer.read(), [], 'a partial line is not parsed as an event');
  appendFileSync(path, '}\n');
  assert.deepEqual(tailer.read().map((r) => r.n), [3], 'the completed line is picked up next tick');
  rmSync(d, { recursive: true, force: true });
});

test('tailer counts unparseable lines instead of throwing at hostile input', () => {
  const d = dir();
  const path = join(d, 'a.jsonl');
  const tailer = new JsonlTailer({ paths: [path] });
  writeFileSync(path, 'not json at all\n{"no_type":true}\n');
  assert.deepEqual(tailer.read(), []);
  assert.equal(tailer.badLines, 1);
  rmSync(d, { recursive: true, force: true });
});

/* ------------------------------------------------------------------- rules */

const engine = (over = {}) =>
  new DetectionEngine({ credentialBurst: 3, credentialWindowMs: 60_000, approvalDenyStreak: 3, egressDriftStreak: 2, egressAllowlist: ['api.deepseek.com'], ...over });

test('E3 信号1: a burst of credential-path denials degrades', () => {
  const e = engine();
  const now = 1_000;
  const first = e.feed([line0('credential.resolve', { result: 'denied', reason: 'unknown-token' })], now);
  assert.equal(first[0].rule, 'E3-credential-probe-early');
  assert.equal(first[0].degrade, false, 'one attempt is a warning, not an outage');
  const third = e.feed(
    [line0('credential.resolve', { result: 'denied', reason: 'unknown-token' }), line0('credential.resolve', { result: 'denied', reason: 'ref-not-authorized' })],
    now + 1000,
  );
  assert.equal(third.length, 2);
  assert.equal(third[0].rule, 'E3-credential-probe-early');
  assert.equal(third[1].rule, 'E3-credential-probe');
  assert.equal(third[1].degrade, true);
});

test('E3 信号1: gateway handshake denials count as the same attack class', () => {
  const e = engine({ credentialBurst: 1 });
  const out = e.feed([line0('authz.decision', { result: 'denied', stage: 'ob11-self-id', reason: 'self-id-mismatch' })], 1);
  assert.equal(out[0].rule, 'E3-credential-probe');
  assert.equal(out[0].degrade, true);
});

test('E3 信号1: an allowed resolve or a non-credential denial is not an attack', () => {
  const e = engine({ credentialBurst: 1 });
  assert.deepEqual(e.feed([line0('credential.resolve', { result: 'allowed', ref: 'mem-hmac-secret' })], 1), []);
  assert.deepEqual(e.feed([line0('authz.decision', { result: 'denied', stage: 'gate', reason: 'not-whitelisted' })], 2), [], 'a stranger messaging the bot is A1 working, not E3');
  assert.deepEqual(e.feed([line0('ratelimit.exceeded', { result: 'denied', scope: 'sender' })], 3), []);
});

test('E3 信号2: an egress target outside the squid allowlist degrades on the second sighting', () => {
  const e = engine();
  const a = e.feed([line0('llm.egress', { target: 'api.deepseek.com/chat/completions', status: 200 })], 1);
  assert.deepEqual(a, [], 'the allowlisted model host is normal traffic');
  const b = e.feed([line0('llm.egress', { target: 'evil.example.org/collect', status: 200 })], 2);
  assert.equal(b[0].rule, 'E3-egress-drift-early');
  const c = e.feed([line0('llm.egress', { target: 'evil.example.org/collect', status: 200 })], 3);
  assert.equal(c[0].rule, 'E3-egress-drift');
  assert.equal(c[0].degrade, true);
});

test('E3 信号3: three consecutive owner refusals degrade; an approval resets the streak', () => {
  const e = engine();
  const denial = line0('approval.outcome', { stage: 'decided', decision: 'denied', toolName: 'memory_write' });
  assert.equal(e.feed([denial], 1)[0].degrade, false);
  assert.equal(e.feed([denial], 2)[0].degrade, false);
  assert.equal(e.feed([denial], 3)[0].rule, 'E3-approval-denials');
  assert.equal(e.feed([denial], 4)[0].degrade, true, 'the fourth continues to hold the breaker open');
  const e2 = engine();
  e2.feed([denial], 1);
  e2.feed([denial], 2);
  assert.deepEqual(e2.feed([line0('approval.outcome', { stage: 'decided', decision: 'approved' })], 3), [], 'an approval clears the streak');
  assert.equal(e2.stats().approvalStreak, 0);
});

test('E3 信号3: expiry and orphan approvals are not refusals (主人睡着 ≠ 攻击)', () => {
  const e = engine({ approvalDenyStreak: 1 });
  assert.deepEqual(e.feed([line0('approval.outcome', { stage: 'expired', result: 'denied' })], 1), []);
  assert.deepEqual(e.feed([line0('approval.outcome', { stage: 'orphan', result: 'noop', decision: 'denied' })], 2), []);
});

test('C-32: losing the QQ protocol leg alerts but never degrades', () => {
  const e = engine();
  const down = e.feed([line0('session.lifecycle', { stage: 'ob11-handshake', event: 'disconnected', socketId: 's1' })], 1);
  assert.equal(down[0].rule, 'E6-protocol-down');
  assert.equal(down[0].alert, true);
  assert.equal(down[0].degrade, false, 'NapCat is the alert carrier; degrading on its loss would silence the alarm');
  const back = e.feed([line0('session.lifecycle', { stage: 'ob11-handshake', event: 'connected', socketId: 's2' })], 2);
  assert.equal(back[0].rule, 'E6-protocol-restore');
});

test('E7/TM-014: a stalled audit stream is an alert, not a circuit-break', () => {
  const f = engine().streamStalled({ file: 'agent.jsonl', ageMs: 90_000 });
  assert.equal(f.rule, 'E7-audit-silence');
  assert.equal(f.degrade, false);
  assert.match(f.summary, /停增/);
});

function line0(type, fields) {
  return { ts: Date.now(), type, ...fields };
}

/* ----------------------------------------------------------------- breaker */

test('breaker opens the flag with its own stamp and closes it when reasons clear', () => {
  const d = dir();
  const path = join(d, 'degraded');
  const b = new Breaker({ path });
  const f = { degrade: true, rule: 'E3-egress-drift', summary: '非白名单出站点', kind: 'security' };
  b.note(f, 1000);
  assert.equal(b.reconcile(1000).opened, true);
  assert.equal(existsSync(path), true);
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).managed_by, MANAGED_BY);
  // still held by the latch window
  assert.equal(b.reconcile(2000).changed, false);
  b.reasons.clear();
  assert.equal(b.reconcile(3000).changed, true);
  assert.equal(existsSync(path), false);
  rmSync(d, { recursive: true, force: true });
});

test('breaker never deletes a flag an operator wrote by hand', () => {
  const d = dir();
  const path = join(d, 'degraded');
  writeFileSync(path, ''); // `touch state/degraded`
  const b = new Breaker({ path });
  assert.equal(b.foreignFlagPresent(), true);
  const res = b.reconcile(Date.now());
  assert.equal(res.changed, false);
  assert.equal(existsSync(path), true, 'a manual halt stays halted');
  b.note({ degrade: true, rule: 'x', summary: 'y', kind: 'availability' }, Date.now());
  assert.equal(b.reconcile(Date.now() + 1).changed, false, 'and it is not overwritten with our JSON either');
  rmSync(d, { recursive: true, force: true });
});

test('a security reason latches; an availability reason recovers as soon as the probe is green', () => {
  const d = dir();
  const b = new Breaker({ path: join(d, 'degraded'), holdMs: 1000 });
  b.note({ degrade: true, rule: 'E3-credential-probe', summary: 's', kind: 'security' }, 0);
  assert.equal(b.activeCount(500), 1);
  assert.equal(b.activeCount(2001), 0, 'latch expires');
  b.note({ degrade: true, rule: 'E3-health-probe:memory', summary: 's', kind: 'availability' }, 0);
  assert.equal(b.activeCount(99_999), 1, 'availability does not expire on a timer — it needs a real recovery');
  assert.equal(b.clearAvailability('E3-health-probe:memory', 99_999), true);
  assert.equal(b.activeCount(99_999), 0);
  rmSync(d, { recursive: true, force: true });
});

/* ------------------------------------------------------------------ alerts */

test('renderAlert keeps the fixed shape and strips credential shapes (D5)', () => {
  const text = renderAlert({ rule: 'E3-credential-probe', severity: 'critical', summary: '凭据路径访问尝试', evidence: { token: 'sk-abcdefghijklmnop1234', target: 'memory' }, now: 0 });
  assert.match(text, /\[DSH-Bot/);
  assert.match(text, /E3-credential-probe/);
  assert.doesNotMatch(text, /sk-abcdefghijklmnop1234/);
  assert.equal(redactAlert('password=hunter2-super-secret-value-abc').includes('hunter2'), false);
});

test('a cold start does not re-fire history: the loop seeks to end-of-file', async () => {
  const d = dir();
  const logDir = join(d, 'logs');
  const stateDir = join(d, 'state');
  mkdirSync(logDir);
  const port = await freePort();
  const up = createServer((sock) => sock.end());
  await new Promise((r) => up.listen(port, '127.0.0.1', r));
  writeFileSync(join(logDir, 'broker.jsonl'), line({ type: 'credential.resolve', service: 'secret-broker', result: 'denied', reason: 'unknown-token' }));
  writeFileSync(join(logDir, 'broker.jsonl'), line({ type: 'credential.resolve', service: 'secret-broker', result: 'denied', reason: 'unknown-token' }) + line({ type: 'credential.resolve', service: 'secret-broker', result: 'denied', reason: 'unknown-token' }));
  const watcher = createWatcher({
    env: {
      WATCHER_LOG_DIR: logDir,
      WATCHER_LOG_FILES: 'broker.jsonl',
      WATCHER_TARGETS: `memory=tcp://127.0.0.1:${port}:required`,
      DEGRADED_FLAG_PATH: join(stateDir, 'degraded'),
      WATCHER_ALERT_OUTBOX: join(stateDir, 'alerts.jsonl'),
      WATCHER_CURSOR_PATH: join(stateDir, 'cursor.json'),
      WATCHER_HEARTBEAT_PATH: join(stateDir, 'heartbeat'),
      WATCHER_CREDENTIAL_BURST: '1',
    },
  });
  const boot = await watcher.tickOnce(1000);
  assert.deepEqual(boot.findings, [], 'history already on disk at boot is not a live finding');
  appendFileSync(join(logDir, 'broker.jsonl'), line({ type: 'credential.resolve', service: 'secret-broker', result: 'denied', reason: 'unknown-token' }));
  const live = await watcher.tickOnce(2000);
  assert.equal(live.findings[0].rule, 'E3-credential-probe', 'what arrives after boot is');
  await new Promise((r) => up.close(r));
  rmSync(d, { recursive: true, force: true });
});

test('dispatcher is dry-run by default: the ledger gets the alert, the network does not', async () => {
  const d = dir();
  const outbox = join(d, 'alerts.jsonl');
  let hits = 0;
  const a = new AlertDispatcher({
    outboxPath: outbox,
    alert: { dryRunIgnores: true, cooldownMs: 0, tg: { botToken: 'x', chatId: '1' }, qq: { url: 'http://127.0.0.1:1', token: 't', userId: '2' } },
    dryRun: true,
    httpRequest: () => { hits += 1; return fakeRequest(); },
    httpsRequest: () => { hits += 1; return fakeRequest(); },
  });
  const res = await a.dispatch({ rule: 'E3-egress-drift', severity: 'critical', summary: 'x', evidence: { target: 'evil' } }, { flagPresent: true, reasons: [] }, { force: true });
  assert.equal(res.sent, false);
  assert.equal(res.reason, 'dry-run');
  assert.equal(hits, 0, 'dry-run must not open a socket');
  const rec = JSON.parse(readFileSync(outbox, 'utf8').trim().split('\n')[0]);
  assert.deepEqual(rec.channels, ['telegram', 'qq-ob11', 'ledger']);
  assert.equal(rec.mode, 'dry-run');
  rmSync(d, { recursive: true, force: true });
});

test('dispatcher skips unconfigured channels and dedups within the cooldown', async () => {
  const d = dir();
  let clock = 1_000_000;
  const a = new AlertDispatcher({ outboxPath: join(d, 'alerts.jsonl'), alert: { cooldownMs: 60_000, tg: {}, qq: {} }, dryRun: false, now: () => clock });
  assert.deepEqual(a.channelStatus().networkLive, [], 'no token, no chat id, no url ⇒ nothing to send to');
  const first = await a.dispatch({ rule: 'R', severity: 'warn', summary: 's' }, {});
  assert.equal(first.record.channels.join(','), 'ledger');
  clock += 1000;
  const second = await a.dispatch({ rule: 'R', severity: 'warn', summary: 's' }, {});
  assert.equal(second.sent, false);
  assert.equal(second.reason, 'cooldown');
  assert.equal(a.counters.suppressed, 1);
  rmSync(d, { recursive: true, force: true });
});

function fakeRequest() {
  const cbs = {};
  return { once: (ev, fn) => { cbs[ev] = fn; }, end: () => cbs.error?.(new Error('unexpected socket')), write: () => {}, destroy: () => {} };
}

test('the delivery leg gets a structured queue file even in dry-run (mapped subject, no prose)', async () => {
  const d = dir();
  const queueDir = join(d, 'alerts');
  const a = new AlertDispatcher({
    outboxPath: join(d, 'alerts.jsonl'),
    alert: { cooldownMs: 0, tg: {}, qq: {}, queueDir },
    dryRun: true,
  });
  const res = await a.dispatch({ rule: 'E3-egress-drift', severity: 'critical', summary: '出站点 evil.example.org 不在白名单', evidence: { target: 'evil.example.org' } }, { flagPresent: true });
  assert.equal(res.queued, true, 'dry-run still exercises the queue the gateway reads');
  const files = readdirSync(join(queueDir, 'pending'));
  assert.equal(files.length, 1);
  const entry = JSON.parse(readFileSync(join(queueDir, 'pending', files[0]), 'utf8'));
  assert.equal(entry.type, 'egress-drift', 'the rule maps onto the relay vocabulary');
  assert.equal(entry.state, 'degraded');
  assert.equal(entry.target, 'evil.example.org');
  assert.equal(entry.summary, undefined, 'free text stays in the local ledger, not in the queue');
  assert.equal('text' in entry, false, 'the rendered prose stays local');
  rmSync(d, { recursive: true, force: true });
});

/* ------------------------------------------------------------------- probe */

test('tcpProbe reports a live listener and a refused port', async () => {
  const server = createServer((sock) => sock.end());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const up = await tcpProbe({ host: '127.0.0.1', port, timeoutMs: 500 });
  assert.equal(up.ok, true);
  const down = await tcpProbe({ host: '127.0.0.1', port: 1, timeoutMs: 500 });
  assert.equal(down.ok, false);
  server.close();
});

test('HealthState needs N consecutive failures to trip and M successes to recover', () => {
  const h = new HealthState({ failThreshold: 3, closeThreshold: 2 });
  assert.equal(h.record('m', false, 'ECONNREFUSED').tripped, false);
  assert.equal(h.record('m', false, 'ECONNREFUSED').tripped, false);
  assert.equal(h.record('m', false, 'ECONNREFUSED').tripped, true);
  assert.deepEqual(h.failed(['m']).map((f) => f.name), ['m']);
  assert.equal(h.record('m', true, 'connected').tripped, false, 'the first success stops the failure run');
  assert.equal(h.record('m', true, 'connected').recovered, true);
  assert.deepEqual(h.failed(['m']), []);
});

/* ------------------------------------------------------------- whole loop */

/** Reserve a port by binding and releasing it: after `close()` the connect is refused. */
async function freePort() {
  const s = createServer((sock) => sock.end());
  await new Promise((r) => s.listen(0, '127.0.0.1', r));
  const { port } = s.address();
  await new Promise((r) => s.close(r));
  return port;
}

test('end to end: a stopped dependency trips the breaker and writing alerts on the bypass path; its return closes the circuit', async () => {
  const d = dir();
  const stateDir = join(d, 'state');
  const port = await freePort();
  const watcher = createWatcher({
    env: {
      WATCHER_LOG_DIR: join(d, 'logs'), // does not exist yet: absent streams are simply not read
      WATCHER_TARGETS: `memory=tcp://127.0.0.1:${port}:required`,
      DEGRADED_FLAG_PATH: join(stateDir, 'degraded'),
      WATCHER_ALERT_OUTBOX: join(stateDir, 'alerts.jsonl'),
      WATCHER_CURSOR_PATH: join(stateDir, 'cursor.json'),
      WATCHER_HEARTBEAT_PATH: join(stateDir, 'heartbeat'),
      WATCHER_FAIL_THRESHOLD: '2',
      WATCHER_CLOSE_THRESHOLD: '1',
      WATCHER_ALERT_DRY_RUN: '1',
    },
  });

  await watcher.tickOnce(1000);
  assert.equal(existsSync(join(stateDir, 'degraded')), false, 'one failure short of the threshold must not degrade');
  const afterTrip = await watcher.tickOnce(2000);
  assert.equal(afterTrip.breakerState.flagPresent, true, 'E3: 连续失败达阈值 → /state/degraded 置位（intake fail-closed）');
  const flag = JSON.parse(readFileSync(join(stateDir, 'degraded'), 'utf8'));
  assert.equal(flag.managed_by, MANAGED_BY);
  assert.match(flag.reasons[0].key, /E3-health-probe:memory/);

  const ledger = readFileSync(join(stateDir, 'alerts.jsonl'), 'utf8');
  assert.match(ledger, /E3-health-probe/, 'F2: the finding is recorded on the bypass path (no agent, no LLM)');
  assert.match(ledger, /E3-breaker-open/);
  assert.equal(JSON.parse(readFileSync(join(stateDir, 'heartbeat'), 'utf8')).degraded, true, 'E7: the heartbeat carries the breaker state');

  // dependency returns ⇒ the flag must clear by itself
  const up = createServer((sock) => sock.end());
  await new Promise((r) => up.listen(port, '127.0.0.1', r));
  const recovered = await watcher.tickOnce(3000);
  assert.equal(recovered.breakerState.flagPresent, false, '恢复后自动闭合');
  assert.equal(existsSync(join(stateDir, 'degraded')), false);
  assert.match(readFileSync(join(stateDir, 'alerts.jsonl'), 'utf8'), /E3-breaker-close/);
  assert.equal(watcher.status().degraded, false);

  await new Promise((r) => up.close(r));
  rmSync(d, { recursive: true, force: true });
});

test('end to end: a non-allowlisted egress site found in broker.jsonl degrades on the live stream', async () => {
  const d = dir();
  const logDir = join(d, 'logs');
  const stateDir = join(d, 'state');
  mkdirSync(logDir);
  writeFileSync(join(logDir, 'broker.jsonl'), '');
  writeFileSync(join(logDir, 'agent.jsonl'), '');

  const port = await freePort();
  const up = createServer((sock) => sock.end());
  await new Promise((r) => up.listen(port, '127.0.0.1', r));

  const watcher = createWatcher({
    env: {
      WATCHER_LOG_DIR: logDir,
      WATCHER_LOG_FILES: 'broker.jsonl,agent.jsonl',
      WATCHER_TARGETS: `memory=tcp://127.0.0.1:${port}:required`,
      DEGRADED_FLAG_PATH: join(stateDir, 'degraded'),
      WATCHER_ALERT_OUTBOX: join(stateDir, 'alerts.jsonl'),
      WATCHER_CURSOR_PATH: join(stateDir, 'cursor.json'),
      WATCHER_HEARTBEAT_PATH: join(stateDir, 'heartbeat'),
      WATCHER_EGRESS_ALLOWLIST: 'api.deepseek.com',
      WATCHER_EGRESS_DRIFT_STREAK: '1',
    },
  });

  // the watcher is up first, *then* the drift appears: a cold start must not re-alert on
  // history (the cursor baseline is end-of-file), and the new line must be caught.
  appendFileSync(join(logDir, 'broker.jsonl'), line({ type: 'llm.egress', service: 'secret-broker', target: 'evil.example.org/collect', status: 200, clientId: 'bot-core' }));
  const first = await watcher.tickOnce(1000);
  assert.equal(first.findings.some((f) => f.rule === 'E3-egress-drift'), true);
  assert.equal(first.breakerState.flagPresent, true, 'C5 breach ⇒ degrade');
  // second tick: the cursor means the same lines are not re-detected, but the latch holds
  const second = await watcher.tickOnce(2000);
  assert.equal(second.findings.length, 0, 'no re-read of history (cursor persisted)');
  assert.equal(second.breakerState.flagPresent, true, 'the security latch keeps it closed until the hold expires');
  assert.deepEqual(JSON.parse(readFileSync(join(stateDir, 'cursor.json'), 'utf8')).offsets && true, true);

  await new Promise((r) => up.close(r));
  rmSync(d, { recursive: true, force: true });
});

/* ------------------------------------------- E7 divergence gate (post-merge hotfix) */

test('E7: an idle stack is silent on every stream at once and that is not a finding', async () => {
  const d = dir();
  const logDir = join(d, 'logs');
  const stateDir = join(d, 'state');
  mkdirSync(logDir);
  mkdirSync(stateDir, { recursive: true });
  const port = await freePort();
  const up = createServer((sock) => sock.end());
  await new Promise((r) => up.listen(port, '127.0.0.1', r));
  try {
    writeFileSync(join(logDir, 'ingress.jsonl'), line({ type: 'authz.decision', service: 'gateway' }));
    writeFileSync(join(logDir, 'agent.jsonl'), line({ type: 'agent.turn', service: 'bot-core' }));
    const outbox = join(stateDir, 'alerts.jsonl');
    const w = createWatcher({
      env: {
        WATCHER_LOG_DIR: logDir,
        WATCHER_LOG_FILES: 'ingress.jsonl,agent.jsonl',
        WATCHER_TARGETS: `memory=tcp://127.0.0.1:${port}:required`,
        DEGRADED_FLAG_PATH: join(stateDir, 'degraded'),
        WATCHER_ALERT_OUTBOX: outbox,
        WATCHER_CURSOR_PATH: join(stateDir, 'cursor.json'),
        WATCHER_HEARTBEAT_PATH: join(stateDir, 'heartbeat'),
        WATCHER_STALE_LOG_MIN: '0.0005', // 30ms — the fake-clock ticks below are far apart
      },
    });
    // E7 findings bypass tickOnce().findings and go straight to the dispatcher
    // (index.mjs: checkGrowth → alerts.dispatch), so the dry-run ledger is the
    // observable, not the returned findings array.
    const e7s = () => {
      try {
        return readFileSync(outbox, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).filter((a) => a.rule === 'E7-audit-silence');
      } catch {
        return [];
      }
    };

    await w.tickOnce(1000); // baseline: sized but never grew
    appendFileSync(join(logDir, 'ingress.jsonl'), line({ type: 'authz.decision', service: 'gateway' }));
    appendFileSync(join(logDir, 'agent.jsonl'), line({ type: 'agent.turn', service: 'bot-core' }));
    await w.tickOnce(2000); // both grow: everGrew=true, at=2000

    await w.tickOnce(5000); // both silent 3000ms >> 30ms — a quiet evening
    assert.deepEqual(e7s(), [], 'all streams silent together = idle companion, not a stalled writer');

    appendFileSync(join(logDir, 'agent.jsonl'), line({ type: 'agent.turn', service: 'bot-core' }));
    await w.tickOnce(6000); // agent moves; ingress stalled 4000ms
    assert.equal(e7s().length, 1, 'a stream that stalls while a peer still moves = the real TM-014 signal');
    assert.equal(e7s()[0].evidence.file, 'ingress.jsonl');

    await w.tickOnce(7000); // ingress deduped until it grows again; agent aged out of the peer window
    assert.equal(e7s().length, 1, 'one stall episode = one alert — no self-feeding hourly loop');
  } finally {
    await new Promise((r) => up.close(r));
    rmSync(d, { recursive: true, force: true });
  }
});
