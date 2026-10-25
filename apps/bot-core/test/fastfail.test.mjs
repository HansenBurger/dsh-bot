/**
 * T9-F4 — connect-layer fast-fail tests.
 *
 * The t9 fault matrix measured that a stopped container's bridge IP answers nothing: the
 * memory leg hung ~8s (its client ceiling), the broker leg ~10.5s, and with
 * MAX_CONCURRENT_RUNS=2 two such requests saturate the intake. These tests pin the new
 * behaviour: an unreachable dependency is decided at the TCP layer within the probe
 * budget, the fetch is never attempted, the audit says which leg failed, and the owner
 * keeps the existing fail-closed wording.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { EventEmitter } from 'node:events';
import { once } from 'node:events';
import { assertDependencyReachable, probeTarget, tcpConnectProbe, DEFAULT_CONNECT_PROBE_MS } from '../src/net-probe.mjs';
import { MemoryClient, MemoryClientError } from '../src/memory-client.mjs';
import { BrokerLlmClient, llmFailureMessage } from '../src/llm.mjs';

const SECRET = 'fastfail-hmac-secret-00000000';
const owner = { channel: 'onebot', chatId: '900', userId: '111', role: 'owner' };

/* ---------------- the probe itself ---------------- */

test('probeTarget: host/port and scheme defaults', () => {
  assert.deepEqual(probeTarget('http://172.28.2.50:8091'), { host: '172.28.2.50', port: 8091 });
  assert.deepEqual(probeTarget('http://memory.local'), { host: 'memory.local', port: 80 });
  assert.deepEqual(probeTarget('https://broker.example:8443/'), { host: 'broker.example', port: 8443 });
});

test('tcpConnectProbe: a live listener passes immediately', async () => {
  const server = createServer(() => {});
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    await tcpConnectProbe({ host: '127.0.0.1', port: server.address().port, timeoutMs: 1000 });
  } finally {
    server.closeAllConnections?.();
    await new Promise((r) => server.close(r));
  }
});

test('tcpConnectProbe: a closed port is decided at once (real ECONNREFUSED)', async () => {
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const started = Date.now();
  await assert.rejects(() => tcpConnectProbe({ host: '127.0.0.1', port, timeoutMs: 2000 }), (err) => /ECONNREFUSED/.test(String(err.code || err.message)));
  assert.ok(Date.now() - started < 1000, 'refused must not burn the probe budget');
});

test('tcpConnectProbe: silence trips the budget with CONNECT_PROBE_TIMEOUT (the stopped-container case)', async () => {
  // A stopped container's IP answers NOTHING — no SYN-ACK, no RST. That is not testable
  // against a real socket without blackholing, so the dial itself is stubbed to the
  // exact observed shape: connect never fires.
  const socket = new EventEmitter();
  const started = Date.now();
  await assert.rejects(
    () => tcpConnectProbe({ host: '172.28.2.50', port: 8091, timeoutMs: 200, connectImpl: () => socket }),
    (err) => err.code === 'CONNECT_PROBE_TIMEOUT',
  );
  const elapsed = Date.now() - started;
  assert.ok(elapsed >= 150 && elapsed < 1000, `fired at ${elapsed}ms — must be the budget, not much later`);
});

test('assertDependencyReachable: failure carries the machine-readable probe code', async () => {
  await assert.rejects(
    () => assertDependencyReachable({ baseUrl: 'http://172.28.2.50:8091', timeoutMs: 200, connectImpl: () => new EventEmitter() }),
    (err) => err.fast === true && err.probeCode === 'CONNECT_PROBE_TIMEOUT' && err.host === '172.28.2.50',
  );
});

test('probe budget default is the 1-2s class the task prescribes', () => {
  assert.equal(DEFAULT_CONNECT_PROBE_MS, 1500);
});

/* ---------------- memory leg ---------------- */

function collectingAudit() {
  const emitted = [];
  return { emitted, emit: (type, fields) => emitted.push({ type, ...fields }) };
}

test('memory leg: unreachable service fails at the probe, the fetch is never dialed', async () => {
  const auditSink = collectingAudit();
  let fetchCalled = 0;
  const client = new MemoryClient({
    baseUrl: 'http://172.28.2.50:8091',
    hmacSecret: SECRET,
    audit: auditSink,
    fetchImpl: async () => {
      fetchCalled += 1;
      throw new Error('fetch must not run when the probe failed');
    },
    dependencyProbe: async () => {
      throw Object.assign(new Error('dependency unreachable: 172.28.2.50:8091 (CONNECT_PROBE_TIMEOUT)'), { fast: true, probeCode: 'CONNECT_PROBE_TIMEOUT' });
    },
  });
  const started = Date.now();
  await assert.rejects(
    () => client.write({ subjectKey: 'onebot:dm:111', class: 'preference', body: '机密偏好内容' }, owner),
    (err) => err instanceof MemoryClientError && err.code === 'MEMORY_UNREACHABLE' && err.status === 503 && err.message === '记忆服务不可达',
  );
  assert.equal(fetchCalled, 0);
  assert.ok(Date.now() - started < 1000, 'fast-fail must return promptly, not hang');
  assert.equal(auditSink.emitted.length, 1);
  assert.equal(auditSink.emitted[0].type, 'sandbox.denied');
  assert.equal(auditSink.emitted[0].stage, 'memory-client');
  assert.equal(auditSink.emitted[0].code, 'CONNECT_FASTFAIL');
  assert.ok(!JSON.stringify(auditSink.emitted).includes('机密偏好内容'), 'no bodies in the audit line');
});

test('memory leg: probe disabled (connectProbeMs=0) keeps the old pure-fetch path', async () => {
  let fetchCalled = 0;
  const client = new MemoryClient({
    baseUrl: 'http://172.28.2.50:8091',
    hmacSecret: SECRET,
    connectProbeMs: 0,
    fetchImpl: async () => {
      fetchCalled += 1;
      return { ok: true, status: 200, json: async () => ({ results: [], truncated: false }) };
    },
    dependencyProbe: async () => {
      throw new Error('probe must not run when disabled');
    },
  });
  const out = await client.search({ query: 'x' }, owner);
  assert.equal(fetchCalled, 1);
  assert.deepEqual(out.results, []);
});

test('memory leg: real TCP against a dead port fast-fails within the budget', async () => {
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const auditSink = collectingAudit();
  const client = new MemoryClient({
    baseUrl: `http://127.0.0.1:${port}`,
    hmacSecret: SECRET,
    audit: auditSink,
    connectProbeMs: 800,
    fetchImpl: async () => {
      throw new Error('fetch must not run when the probe failed');
    },
  });
  const started = Date.now();
  await assert.rejects(() => client.read('m-1', owner), (err) => err.code === 'MEMORY_UNREACHABLE');
  assert.ok(Date.now() - started < 800, 'refused-port probe returns well under the budget');
  assert.equal(auditSink.emitted[0].code, 'CONNECT_FASTFAIL');
});

/* ---------------- broker llm leg ---------------- */

test('broker leg: unreachable broker fails in ~the probe budget with the existing fail-closed wording', async () => {
  const auditSink = collectingAudit();
  let fetchCalled = 0;
  const llm = new BrokerLlmClient({
    brokerUrl: 'http://172.28.2.30:8080',
    token: 'tok',
    audit: auditSink,
    dependencyProbe: async () => {
      throw Object.assign(new Error('dependency unreachable: 172.28.2.30:8080 (CONNECT_PROBE_TIMEOUT)'), { fast: true });
    },
    fetchImpl: async () => {
      fetchCalled += 1;
      throw new Error('fetch must not run when the probe failed');
    },
  });
  await assert.rejects(
    () => llm.chat({ messages: [{ role: 'user', content: 'hi' }], tools: [] }),
    (err) => {
      assert.equal(err.reason, 'connect-fastfail');
      // the owner-facing text reuses the existing pattern — no new vocabulary:
      assert.equal(llmFailureMessage(err), '我现在连不上模型，稍后再试。');
      return true;
    },
  );
  assert.equal(fetchCalled, 0);
  assert.equal(auditSink.emitted.length, 1);
  assert.equal(auditSink.emitted[0].type, 'llm.call');
  assert.equal(auditSink.emitted[0].reason, 'connect-fastfail');
});

test('broker leg: a reachable probe result still gets the full model budget (no short overall timeout)', () => {
  const llm = new BrokerLlmClient({ brokerUrl: 'http://x:1', token: 't', audit: collectingAudit(), connectProbeMs: 1500 });
  assert.equal(llm.timeoutMs, 60_000, 'the 60s stays: it bounds the model, not the handshake');
  assert.equal(llm.connectProbeMs, 1500);
});
