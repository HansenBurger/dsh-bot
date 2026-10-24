import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecretResolver, refOf, OPAQUE_PREFIX } from '../src/index.mjs';

const dir = () => {
  const d = mkdtempSync(join(tmpdir(), 'secrets-test-'));
  chmodSync(d, 0o700);
  return d;
};

test('refOf recognises only the opaque-ref scheme', () => {
  assert.equal(refOf('opaque-ref:mem-kek'), 'mem-kek');
  assert.equal(refOf('  opaque-ref:spaced-ref  '), 'spaced-ref', 'surrounding whitespace is env-file noise');
  assert.equal(refOf(undefined), null);
  assert.equal(refOf('mem-kek'), null, 'a bare value is not a ref');
  assert.equal(refOf('opaque-ref:'), null, 'an empty ref name is not a ref');
  assert.equal(refOf('vault:mem-kek'), null, 'other schemes are not ours');
  assert.ok(OPAQUE_PREFIX.length > 0);
});

test('a mounted secret file resolves, with the trailing newline stripped', async () => {
  const d = dir();
  writeFileSync(join(d, 'mem-pg-rw-password'), 'pw-value-1234\n');
  const r = new SecretResolver({ secretsDir: d, brokerUrl: '' });
  assert.equal(await r.resolve('opaque-ref:mem-pg-rw-password', { label: 'pg' }), 'pw-value-1234');
  assert.equal(r.stats.file, 1);
  // memoized: a second call must not re-read (and re-log) the same credential
  assert.equal(await r.resolve('opaque-ref:mem-pg-rw-password', { label: 'pg' }), 'pw-value-1234');
  assert.equal(r.stats.file, 1);
});

test('an unresolvable ref fails closed instead of returning an empty password', async () => {
  const r = new SecretResolver({ secretsDir: dir(), brokerUrl: '' });
  await assert.rejects(() => r.resolve('opaque-ref:absent', { label: 'pg-ro-password' }), /pg-ro-password: cannot resolve absent/);
  assert.equal(r.stats.failed, 1);
});

test('a literal is a warning by default and an error when forbidden', async () => {
  const r = new SecretResolver({ secretsDir: dir(), brokerUrl: '' });
  assert.equal(await r.resolve('inline-literal', { label: 'kek' }), 'inline-literal');
  assert.equal(r.stats.literal, 1);
  await assert.rejects(() => r.resolve('inline-literal', { label: 'kek', literalAllowed: false }), /literal value is not allowed/);
  assert.equal(await r.resolve(undefined, { label: 'optional-field' }), null, 'unset is not an error');
  assert.equal(await r.resolve('', { label: 'optional-field' }), null);
});

test('a ref is resolved from the broker when one is reachable', async () => {
  const calls = [];
  const fetchImpl = async (url, opts) => {
    calls.push({ url, headers: opts.headers });
    return { ok: true, status: 200, text: async () => 'from-broker\n' };
  };
  const r = new SecretResolver({ secretsDir: dir(), brokerUrl: 'http://172.28.2.30:8080', fetchImpl, enrollmentFile: 'enrollment-token' });
  // With no enrollment token mounted, the resolver must not issue an unauthenticated
  // call and must not invent a value: it fails closed.
  await assert.rejects(() => r.resolve('opaque-ref:mem-kek', { label: 'kek' }), /cannot resolve mem-kek/);
  assert.equal(calls.length, 0, 'an unauthenticated broker request must not be issued');
  const d = dir();
  writeFileSync(join(d, 'enrollment-token'), 'enroll-secret-abc');
  const r2 = new SecretResolver({ secretsDir: d, brokerUrl: 'http://broker:8080/', fetchImpl });
  assert.equal(await r2.resolve('opaque-ref:mem-kek', { label: 'kek' }), 'from-broker');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'http://broker:8080/v1/secret/mem-kek');
  assert.equal(calls[0].headers['x-broker-token'], 'enroll-secret-abc');
});

test('the broker path uses the service HMAC principal when the secret is already known', async () => {
  let seen = null;
  const fetchImpl = async (url, opts) => {
    seen = { url, headers: opts.headers };
    return { ok: true, status: 200, text: async () => 'brokered' };
  };
  const r = new SecretResolver({
    secretsDir: dir(),
    brokerUrl: 'http://broker:8080',
    hmacSecret: 'known-hmac-secret-value',
    principal: { channel: 'system', chatId: 'memory', userId: 'memory-service', role: 'owner' },
    fetchImpl,
  });
  assert.equal(await r.resolve('opaque-ref:mem-pg-ro-password', { label: 'ro' }), 'brokered');
  assert.ok(seen.headers['x-bot-sig'], 'signed request expected');
  assert.match(seen.headers['x-bot-sig'], /^[A-Za-z0-9_-]{43}$/, 'a base64url HMAC is expected');
  const decoded = JSON.parse(Buffer.from(seen.headers['x-bot-principal'], 'base64url').toString('utf8'));
  assert.equal(decoded.userId, 'memory-service');
});

test('a broker error or timeout falls back to the mounted file, then fails', async () => {
  const d = dir();
  writeFileSync(join(d, 'mem-hmac-secret'), 'file-value');
  const failing = new SecretResolver({
    secretsDir: d,
    brokerUrl: 'http://broker:8080',
    fetchImpl: async () => ({ ok: false, status: 403, text: async () => '' }),
    enrollmentFile: 'enrollment-token',
  });
  // 403 from the broker (ref not authorized for this client) must not be retried
  // forever: fall through to the file, which is the documented fallback.
  assert.equal(await failing.resolve('opaque-ref:mem-hmac-secret', { label: 'hmac' }), 'file-value');
  const throwing = new SecretResolver({
    secretsDir: d,
    brokerUrl: 'http://broker:8080',
    fetchImpl: async () => {
      throw new Error('network down');
    },
  });
  assert.equal(await throwing.resolve('opaque-ref:mem-hmac-secret', { label: 'hmac' }), 'file-value');
  const nothing = new SecretResolver({ secretsDir: dir(), brokerUrl: '', fetchImpl: null });
  await assert.rejects(() => nothing.resolve('opaque-ref:absent', { label: 'kek' }), /cannot resolve absent/);
});

test('a ref name can never traverse outside the secrets directory', async () => {
  const d = dir();
  writeFileSync(join(d, '..', 'outside-secret'), 'do-not-read-me');
  const r = new SecretResolver({ secretsDir: d, brokerUrl: '' });
  await assert.rejects(() => r.resolve('opaque-ref:../outside-secret', { label: 'traversal' }), /cannot resolve/);
  await assert.rejects(() => r.resolve('opaque-ref:%2e%2eoutside', { label: 'traversal' }), /cannot resolve/);
});

test('resolution logs name the ref and length, never the value', async () => {
  const d = dir();
  writeFileSync(join(d, 'mem-kek'), 'super-secret-kek-value');
  const lines = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk, ...rest) => {
    lines.push(String(chunk));
    return true;
  };
  try {
    const r = new SecretResolver({ secretsDir: d, brokerUrl: '' });
    await r.resolve('opaque-ref:mem-kek', { label: 'kek' });
    await r.resolve('literal-value-xyz', { label: 'kek2' });
  } finally {
    process.stderr.write = original;
  }
  const text = lines.join('');
  assert.ok(!text.includes('super-secret-kek-value'), 'a resolved value must never reach the log');
  assert.ok(!text.includes('literal-value-xyz'), 'a literal value must never be echoed either');
  assert.match(text, /credential.resolve/);
  assert.match(text, /"ref":"mem-kek"/);
  assert.match(text, /"length":22/);
});

test('an audit sink receives the same record as stderr', async () => {
  const d = dir();
  writeFileSync(join(d, 'mem-kek'), 'kek-value-1234');
  const emitted = [];
  const r = new SecretResolver({ secretsDir: d, brokerUrl: '', audit: { emit: (type, fields) => emitted.push({ type, ...fields }) } });
  await r.resolve('opaque-ref:mem-kek', { label: 'kek' });
  assert.equal(emitted.length, 1);
  assert.equal(emitted[0].type, 'credential.resolve');
  assert.equal(emitted[0].ref, 'mem-kek');
  assert.equal(emitted[0].source, 'file');
  assert.ok(!JSON.stringify(emitted).includes('kek-value-1234'));
});
