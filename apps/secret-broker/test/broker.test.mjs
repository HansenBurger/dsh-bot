import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { SecretBroker } from '../src/index.mjs';
import { authorize, canLlmEgress, identify, refsFor, CLIENTS, NEVER_RESOLVE } from '../src/policy.mjs';

const PG_RW = 'SuperSecretPgPassword-1234';
const KEK = 'kek-value-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const LLM_KEY = 'sk-proj-broker-side-key-0001112223334445';
const TOKENS = { 'bot-core': 'tok-bot-core-aaaa', 'memory-service': 'tok-memory-bbbb', ingress: 'tok-ingress-cccc' };

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'broker-test-'));
  for (const [id, token] of Object.entries(TOKENS)) writeFileSync(join(dir, `enroll-${id}`), token);
  writeFileSync(join(dir, 'mem-pg-rw-password'), PG_RW);
  writeFileSync(join(dir, 'mem-pg-ro-password'), 'ro-' + PG_RW);
  writeFileSync(join(dir, 'mem-kek'), KEK);
  writeFileSync(join(dir, 'mem-hmac-secret'), 'shared-hmac-secret-value');
  writeFileSync(join(dir, 'llm-key'), LLM_KEY);
  writeFileSync(join(dir, 'huge-ref'), 'x'.repeat(5000));
  return dir;
}

/** Boot a broker plus an echo upstream; returns a fetch helper bound to the broker port. */
async function boot({ withUpstream = true } = {}) {
  const dir = fixture();
  const auditPath = join(dir, 'broker.jsonl');
  let seenAuth = null;
  let upstream = null;
  if (withUpstream) {
    upstream = createServer((req, res) => {
      let body = '';
      req.on('data', (c) => (body += c));
      req.on('end', () => {
        seenAuth = req.headers.authorization || null;
        res.writeHead(200, { 'content-type': 'application/json', 'set-cookie': 'track=me' });
        res.end(JSON.stringify({ ok: true, echo: body, authSeen: Boolean(seenAuth) }));
      });
    });
    await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  }
  const broker = new SecretBroker({
    secretsDir: dir,
    auditPath,
    upstreamBase: upstream ? `http://127.0.0.1:${upstream.address().port}` : '',
  });
  const main = broker.createServer();
  await new Promise((r) => main.listen(0, '127.0.0.1', r));
  const port = main.address().port;
  return {
    dir,
    broker,
    auditPath,
    main,
    upstream,
    port,
    getAuth: () => seenAuth,
    call: async (path, { token = '', method = 'GET', body } = {}) => {
      const res = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { ...(token ? { 'x-broker-token': token } : {}) }, body });
      return { status: res.status, headers: Object.fromEntries(res.headers), text: await res.text() };
    },
    close: async () => {
      await new Promise((r) => main.close(r));
      if (upstream) await new Promise((r) => upstream.close(r));
    },
  };
}

/* ---------------- policy table (acceptance #4, first half) ---------------- */

test('bot-core is denied the database credentials and the KEK', () => {
  for (const ref of ['mem-pg-rw-password', 'mem-pg-ro-password', 'mem-kek']) {
    const decision = authorize('bot-core', ref);
    assert.equal(decision.ok, false, `${ref} must not be resolvable by the agent`);
    assert.equal(decision.reason, 'ref-not-authorized');
  }
  assert.deepEqual(refsFor('bot-core'), ['mem-hmac-secret']);
});

test('the LLM key is never resolvable, not even by the service that holds the DB password', () => {
  for (const clientId of Object.keys(CLIENTS)) {
    const decision = authorize(clientId, 'llm-api-key');
    assert.equal(decision.ok, false);
    assert.equal(decision.reason, 'never-resolvable');
  }
  assert.ok(NEVER_RESOLVE.includes('llm-api-key'));
});

test('ingress may read its bot token but has no LLM egress capability', () => {
  assert.equal(authorize('ingress', 'ingress-tg-token').ok, true);
  assert.equal(authorize('ingress', 'mem-pg-rw-password').ok, false);
  assert.equal(canLlmEgress('ingress'), false);
  assert.equal(canLlmEgress('bot-core'), true);
});

test('identity comes from the enrollment token and unknown tokens yield nothing', () => {
  const store = (name) => (name === 'enroll-bot-core' ? TOKENS['bot-core'] : null);
  assert.equal(identify(store, TOKENS['bot-core']), 'bot-core');
  assert.equal(identify(store, 'nope'), null);
  assert.equal(identify(store, ''), null);
});

/* ---------------- HTTP surface ---------------- */

test('an unauthenticated caller gets 401 and learns nothing', async () => {
  const f = await boot();
  const r = await f.call('/v1/secret/mem-pg-rw-password');
  assert.equal(r.status, 401);
  assert.match(r.text, /UNAUTHENTICATED/);
  const wrong = await f.call('/v1/secret/mem-pg-rw-password', { token: 'guessed-token' });
  assert.equal(wrong.status, 401);
  await f.close();
});

test('the agent identity is refused the DB password over the wire, with one uniform code', async () => {
  const f = await boot();
  const denied = await f.call('/v1/secret/mem-pg-rw-password', { token: TOKENS['bot-core'] });
  assert.equal(denied.status, 403);
  assert.match(denied.text, /REF_NOT_AUTHORIZED/);
  // A ref the broker does not hold at all answers the *same* way, so probing cannot
  // enumerate which credentials exist.
  const unknownRef = await f.call('/v1/secret/does-not-exist', { token: TOKENS['bot-core'] });
  assert.equal(unknownRef.status, 403);
  await f.close();
});

test('the memory service resolves its own refs and gets plaintext with no-store', async () => {
  const f = await boot();
  const ok = await f.call('/v1/secret/mem-pg-rw-password', { token: TOKENS['memory-service'] });
  assert.equal(ok.status, 200);
  assert.equal(ok.text, PG_RW);
  assert.equal(ok.headers['cache-control'], 'no-store');
  assert.equal(ok.headers['x-content-type-options'], 'nosniff');
  const caps = await f.call('/v1/capabilities', { token: TOKENS['memory-service'] });
  assert.deepEqual(JSON.parse(caps.text).allowedRefs.sort(), ['mem-hmac-secret', 'mem-kek', 'mem-pg-ro-password', 'mem-pg-rw-password']);
  await f.close();
});

test('a ref mounted oversized is refused rather than streamed', async () => {
  const f = await boot();
  const tooBig = await f.call('/v1/secret/huge-ref', { token: TOKENS['memory-service'] });
  // huge-ref is not in the memory-service allowlist, so the policy answers first...
  assert.equal(tooBig.status, 403);
  // ...which is exactly the ordering we want: authorization before I/O.
  await f.close();
});

test('path traversal in the ref never reaches the filesystem', async () => {
  const f = await boot();
  for (const ref of ['..%2F..%2Fetc%2Fpasswd', '..%2Fmem-kek', '%2E%2E%2Fmem-kek']) {
    const r = await fetch(`http://127.0.0.1:${f.port}/v1/secret/${ref}`, { headers: { 'x-broker-token': TOKENS['memory-service'] } });
    assert.ok(r.status === 403 || r.status === 404, `${ref} → ${r.status}`);
    await r.text();
  }
  await f.close();
});

test('a group-writable secrets tree is a startup failure', () => {
  const dir = fixture();
  chmodSync(dir, 0o777);
  assert.throws(() => new SecretBroker({ secretsDir: dir, auditPath: join(dir, 'a.jsonl') }), /must not be group\/world writable/);
  assert.equal(existsSync(join(dir, 'enroll-bot-core')), true);
});

/* ---------------- LLM egress (acceptance #4, second half) ---------------- */

test('the egress proxy overwrites a client-supplied authorization header', async () => {
  const f = await boot();
  const res = await fetch(`http://127.0.0.1:${f.port}/v1/llm/chat/completions`, {
    method: 'POST',
    headers: { 'x-broker-token': TOKENS['bot-core'], 'content-type': 'application/json', authorization: 'Bearer evil-smuggled-credential' },
    body: JSON.stringify({ model: 'deepseek-chat', messages: [] }),
  });
  assert.equal(res.status, 200);
  const json = JSON.parse(await res.text());
  assert.equal(json.ok, true);
  assert.equal(f.getAuth(), `Bearer ${LLM_KEY}`, 'upstream must see the injected key only');
  // The broker never echoes the key back and strips upstream cookies.
  assert.ok(!JSON.stringify(json).includes(LLM_KEY));
  assert.ok(!('set-cookie' in Object.fromEntries(res.headers)) || !String(res.headers.get('set-cookie')).includes('track=me'));
  await f.close();
});

test('a client without the llm-egress capability is refused, and no upstream call happens', async () => {
  const f = await boot();
  const res = await f.call('/v1/llm/chat/completions', { token: TOKENS['ingress'], method: 'POST', body: '{}' });
  assert.equal(res.status, 403);
  assert.match(res.text, /LLM_EGRESS_FORBIDDEN/);
  assert.equal(f.getAuth(), null);
  assert.equal(f.broker.counters.llmDenied, 1);
  await f.close();
});

test('with no upstream configured the broker fails closed instead of guessing', async () => {
  const f = await boot({ withUpstream: false });
  const res = await f.call('/v1/llm/chat/completions', { token: TOKENS['bot-core'], method: 'POST', body: '{}' });
  assert.equal(res.status, 503);
  await f.close();
});

/* ---------------- audit hygiene (D5) ---------------- */

test('audit records and admin health output never contain a credential value', async () => {
  const f = await boot();
  await f.call('/v1/secret/mem-pg-rw-password', { token: TOKENS['memory-service'] });
  await f.call('/v1/secret/mem-pg-rw-password', { token: TOKENS['bot-core'] });
  await fetch(`http://127.0.0.1:${f.port}/v1/llm/chat/completions`, { method: 'POST', headers: { 'x-broker-token': TOKENS['bot-core'] }, body: '{}' });
  const audit = readFileSync(f.auditPath, 'utf8');
  for (const secret of [PG_RW, KEK, LLM_KEY, TOKENS['bot-core']]) {
    assert.ok(!audit.includes(secret), 'audit must not contain credentials');
  }
  assert.match(audit, /"clientId":"memory-service"/);
  assert.match(audit, /"length":\d+/);

  const admin = f.broker.createAdminServer();
  await new Promise((r) => admin.listen(0, '127.0.0.1', r));
  const health = await (await fetch(`http://127.0.0.1:${admin.address().port}/healthz`)).text();
  await new Promise((r) => admin.close(r));
  assert.ok(!health.includes(PG_RW));
  assert.match(health, /mem-pg-rw-password/); // names are reported, values are not
  assert.match(health, /"counters"/);
  await f.close();
});
