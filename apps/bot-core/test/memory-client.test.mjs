/**
 * MemoryClient tests: request shape, signature coverage (including the query string and
 * the bound approval token), error mapping, and audit hygiene. A local stub server
 * re-verifies every request with the shared bot-hmac primitives, so these tests fail if
 * the client and the service ever disagree about what is signed.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { verify, HmacError } from '@dsh-bot/bot-hmac';
import { MemoryClient, MemoryClientError } from '../src/memory-client.mjs';

const SECRET = 'memtest-hmac-secret-000000';
const owner = { channel: 'onebot', chatId: '900', userId: '111', role: 'owner' };
const trusted = { ...owner, userId: '222', role: 'trusted' };

/** A stub that behaves like apps/memory-service/src/http.mjs about signing. */
function stubMemory(onRequest) {
  const seen = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      const record = { method: req.method, path: req.url, headers: req.headers, body };
      seen.push(record);
      let principal;
      try {
        ({ principal } = verify(SECRET, {
          method: req.method,
          path: req.url,
          body: body || undefined,
          headers: req.headers,
          // The service verifies the approval bind the same way; without it a bound
          // request looks like a forgery here.
          bind: req.headers['x-bot-approval'],
        }));
      } catch (err) {
        if (!(err instanceof HmacError)) throw err;
        res.writeHead(401, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({ code: err.code, message: err.message }));
      }
      const decision = onRequest ? onRequest(record, principal) : undefined;
      if (decision?.status) {
        res.writeHead(decision.status, { 'content-type': 'application/json' });
        return res.end(JSON.stringify(decision.payload ?? {}));
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, principal: { role: principal.role, userId: principal.userId } }));
    });
  });
  return {
    seen,
    listen: async () => {
      server.listen(0, '127.0.0.1');
      await once(server, 'listening');
      return `http://127.0.0.1:${server.address().port}`;
    },
    close: () => {
      server.closeAllConnections?.();
      return new Promise((r) => server.close(r));
    },
  };
}

const clientFor = async (base, extra = {}) => new MemoryClient({ baseUrl: base, hmacSecret: SECRET, ...extra });

test('a search is signed over method, path and body, and the identity survives', async () => {
  const stub = stubMemory();
  const base = await stub.listen();
  const client = await clientFor(base);
  const out = await client.search({ query: '香菜', limit: 5 }, trusted);
  assert.equal(out.principal.role, 'trusted');
  assert.equal(stub.seen.length, 1);
  const req = stub.seen[0];
  assert.equal(req.method, 'POST');
  assert.equal(req.path, '/v1/memories/search');
  assert.deepEqual(JSON.parse(req.body), { query: '香菜', limit: 5 });
  assert.equal(req.headers['content-type'], 'application/json');
  assert.ok(req.headers['x-bot-sig'], 'the signature header must be sent');
  assert.ok(!JSON.stringify(req.headers).includes('香菜'), 'no payload text in the headers');
  await stub.close();
});

test('an approval token is sent as a header AND bound into the signature', async () => {
  const stub = stubMemory();
  const base = await stub.listen();
  const client = await clientFor(base);
  const approvalId = 'appr-0123456789abcdef0123456789abcdef';
  await client.forget('m-1', owner, { dryRun: false, approvalId });
  const req = stub.seen[0];
  assert.equal(req.headers['x-bot-approval'], approvalId);
  assert.match(req.path, /\/v1\/memories\/m-1\/forget\?dryRun=false$/);

  // Re-signing the same request without the bind must fail: the token cannot be lifted
  // onto a request that was built before the owner approved anything.
  const forged = { ...req, headers: { ...req.headers, 'x-bot-sig': 'a'.repeat(43) } };
  assert.throws(
    () => verify(SECRET, { method: forged.method, path: forged.path, body: undefined, headers: forged.headers, bind: forged.headers['x-bot-approval'] }),
    (err) => err.code === 'UNAUTHENTICATED' && /signature mismatch/.test(err.message),
  );
  await stub.close();
});

test('dropping or moving the dry-run query breaks the signature', async () => {
  const stub = stubMemory();
  const base = await stub.listen();
  const client = await clientFor(base);
  await client.forget('m-2', owner, { dryRun: true });
  const good = stub.seen[0];
  assert.ok(good.path.includes('dryRun=true'));
  // A proxy that rewrites the query (or an attacker with a captured request) cannot
  // quietly flip the flag: the path is part of the signed string.
  assert.throws(
    () => verify(SECRET, { method: good.method, path: good.path.replace('dryRun=true', 'dryRun=false'), body: undefined, headers: good.headers }),
    (err) => err.code === 'UNAUTHENTICATED',
  );
  await stub.close();
});

test('a service error keeps its code and status instead of becoming a generic failure', async () => {
  const stub = stubMemory((req) => {
    if (req.path.includes('forget')) return { status: 403, payload: { code: 'APPROVAL_INVALID', message: '需要一次性审批令牌' } };
    return undefined;
  });
  const base = await stub.listen();
  const client = await clientFor(base);
  await assert.rejects(
    () => client.forget('m-3', owner, { dryRun: false }),
    (err) => {
      assert.ok(err instanceof MemoryClientError);
      assert.equal(err.code, 'APPROVAL_INVALID');
      assert.equal(err.status, 403);
      return true;
    },
  );
  await stub.close();
});

test('an unreachable service maps to MEMORY_UNREACHABLE and is audited without bodies', async () => {
  const emitted = [];
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const port = probe.address().port;
  await new Promise((r) => probe.close(r));
  const client = await clientFor(`http://127.0.0.1:${port}`, { audit: { emit: (type, f) => emitted.push({ type, ...f }) } });
  await assert.rejects(
    () => client.write({ subjectKey: 'onebot:dm:111', class: 'preference', body: '机密偏好内容' }, owner),
    (err) => {
      assert.equal(err.code, 'MEMORY_UNREACHABLE');
      assert.equal(err.status, 503);
      return true;
    },
  );
  assert.equal(emitted.length, 1);
  assert.equal(emitted[0].type, 'sandbox.denied');
  assert.ok(!JSON.stringify(emitted).includes('机密偏好内容'), 'a memory body must never reach the audit log');
});

test('a slow service is cut off by the client timeout, not left hanging', async () => {
  const stub = stubMemory((req, principal) => {
    if (req.path.includes('/context/')) return undefined; // fast path
    return { status: 200, payload: principal };
  });
  const base = await stub.listen();
  const slow = createServer(() => {
    /* never answers */
  });
  slow.listen(0, '127.0.0.1');
  await once(slow, 'listening');
  const client = await clientFor(`http://127.0.0.1:${slow.address().port}`, { timeoutMs: 300 });
  await assert.rejects(() => client.read('m-4', owner), (err) => err.code === 'MEMORY_UNREACHABLE');
  slow.closeAllConnections?.();
  await new Promise((r) => slow.close(r));
  await stub.close();
});

test('context helpers use the peer-scoped routes and encode the key', async () => {
  const stub = stubMemory();
  const base = await stub.listen();
  const client = await clientFor(base);
  await client.putContext('onebot:group:900', { slot: 'topic_stack', value: { items: ['a'] } }, trusted);
  await client.getContext('onebot:group:900', trusted);
  assert.equal(stub.seen[0].method, 'PUT');
  assert.equal(stub.seen[0].path, '/v1/context/onebot%3Agroup%3A900');
  assert.equal(stub.seen[1].method, 'GET');
  assert.equal(stub.seen[1].path, '/v1/context/onebot%3Agroup%3A900');
  await stub.close();
});

test('a whole-subject forget addresses the subject route with its own approval bind', async () => {
  const stub = stubMemory();
  const base = await stub.listen();
  const client = await clientFor(base);
  const approvalId = 'appr-ffffffffffffffffffffffffffffffff';
  await client.forgetSubject('onebot:dm:111', owner, { dryRun: false, approvalId });
  assert.equal(stub.seen[0].path, '/v1/subjects/onebot%3Adm%3A111/forget-all?dryRun=false');
  assert.equal(stub.seen[0].headers['x-bot-approval'], approvalId);
  await stub.close();
});

test('a malformed JSON response is reported as a service error, not a crash', async () => {
  const server = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('<html>proxy ate the response</html>');
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const client = await clientFor(`http://127.0.0.1:${server.address().port}`);
  await assert.rejects(() => client.read('m-5', owner), (err) => err instanceof MemoryClientError);
  server.closeAllConnections?.();
  await new Promise((r) => server.close(r));
});
