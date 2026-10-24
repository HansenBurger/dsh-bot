import test from 'node:test';
import assert from 'node:assert/strict';
import { encodePrincipal, decodePrincipal, sign, verify, signedHeaders, NonceCache, HmacError } from '../src/index.mjs';

const SECRET = 'test-secret-value-32-bytes-long!!';
const OWNER = { channel: 'telegram', chatId: '111', userId: '111', role: 'owner' };

test('principal round-trips structured identity only', () => {
  const enc = encodePrincipal(OWNER);
  const p = decodePrincipal(enc);
  assert.equal(p.channel, 'telegram');
  assert.equal(p.userId, '111');
  assert.equal(p.role, 'owner');
  assert.ok(typeof p.ts === 'number' && typeof p.nonce === 'string');
});

test('C-03: a principal carrying display text is refused', () => {
  assert.throws(() => encodePrincipal({ ...OWNER, displayName: '老板' }), (e) => e instanceof HmacError && e.code === 'UNKNOWN_FIELD');
  assert.throws(() => encodePrincipal({ ...OWNER, nickname: 'boss' }), (e) => e.code === 'UNKNOWN_FIELD');
});

test('U1: role=public never reaches the signed layer', () => {
  assert.throws(() => encodePrincipal({ ...OWNER, role: 'public' }), (e) => e.code === 'FORBIDDEN_ROLE');
});

test('signature covers method, path and body', () => {
  const principal = encodePrincipal(OWNER);
  const base = { method: 'POST', path: '/v1/memories/search', body: '{"query":"x"}', principal };
  const sig = sign(SECRET, base);
  assert.notEqual(sig, sign(SECRET, { ...base, body: '{"query":"y"}' }));
  assert.notEqual(sig, sign(SECRET, { ...base, path: '/v1/memories/other' }));
  assert.notEqual(sig, sign(SECRET, { ...base, method: 'GET' }));
});

test('verify accepts a correctly signed request and rejects tampering', () => {
  const headers = signedHeaders(SECRET, { ...OWNER, method: 'POST', path: '/v1/memories', body: '{"a":1}' });
  const req = { method: 'POST', path: '/v1/memories', body: '{"a":1}', headers, nonces: new NonceCache() };
  const { principal } = verify(SECRET, req);
  assert.equal(principal.role, 'owner');

  // M-14: forged owner assertion with a wrong signature -> UNAUTHENTICATED
  const forged = { ...headers, 'X-Bot-Sig': sign('another-secret-value-32bytes!!!', { method: 'POST', path: '/v1/memories', body: '{"a":1}', principal: headers['X-Bot-Principal'] }) };
  assert.throws(() => verify(SECRET, { method: 'POST', path: '/v1/memories', body: '{"a":1}', headers: forged, nonces: new NonceCache() }), (e) => e.code === 'UNAUTHENTICATED');

  // body modification after signing
  assert.throws(() => verify(SECRET, { method: 'POST', path: '/v1/memories', body: '{"a":2}', headers, nonces: new NonceCache() }), (e) => e.code === 'UNAUTHENTICATED');
});

test('replay of the same nonce is rejected (arch §6.4)', () => {
  const cache = new NonceCache();
  const headers = signedHeaders(SECRET, { ...OWNER, method: 'GET', path: '/v1/memories/1' });
  const mk = () => ({ method: 'GET', path: '/v1/memories/1', body: undefined, headers, nonces: cache });
  verify(SECRET, mk());
  assert.throws(() => verify(SECRET, mk()), (e) => e.code === 'NONCE_REPLAY');
});

test('timestamp outside ±5s window is rejected', () => {
  // The principal is base64url JSON, so a stale one must be minted with an
  // explicit ts — string-replacing the encoded blob cannot touch "ts":….
  const stale = encodePrincipal(OWNER, { ts: Date.now() - 60_000 });
  const headers = { 'X-Bot-Principal': stale, 'X-Bot-Sig': sign(SECRET, { method: 'GET', path: '/x', body: undefined, principal: stale }) };
  assert.throws(
    () => verify(SECRET, { method: 'GET', path: '/x', headers, nonces: new NonceCache() }),
    (e) => e.code === 'UNAUTHENTICATED' && /timestamp/.test(e.message),
  );
});

test('a future-dated principal beyond the window is also rejected', () => {
  const future = encodePrincipal(OWNER, { ts: Date.now() + 30_000 });
  const headers = { 'X-Bot-Principal': future, 'X-Bot-Sig': sign(SECRET, { method: 'GET', path: '/x', body: undefined, principal: future }) };
  assert.throws(() => verify(SECRET, { method: 'GET', path: '/x', headers, nonces: new NonceCache() }), (e) => e.code === 'UNAUTHENTICATED');
});

test('missing signature headers fail closed', () => {
  assert.throws(() => verify(SECRET, { method: 'GET', path: '/x', headers: {} }), (e) => e.code === 'UNAUTHENTICATED');
});

test('short signing secret is refused (D4 >=32 bytes)', () => {
  assert.throws(() => sign('tooshort', { method: 'GET', path: '/', principal: 'x' }), (e) => e.code === 'INTERNAL');
});

test('nonce cache is bounded LRU', () => {
  const c = new NonceCache(3);
  for (let i = 0; i < 10; i += 1) c.seen(`n${i}`);
  assert.equal(c.size, 3);
  assert.equal(c.seen('n9'), true);
  assert.equal(c.seen('n0'), false);
});
