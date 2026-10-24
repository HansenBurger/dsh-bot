import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditSink, AUDIT_TYPES, redact, textHash, preview } from '../src/index.mjs';

test('redact masks provider keys, assignments and long blobs (D5)', () => {
  const out = redact('DEEPSEEK_API_KEY=sk-abcdefghijklmnop1234 and Authorization: Bearer ghp_0123456789abcdefABCDEF');
  assert.ok(!out.includes('sk-abcdefghijklmnop1234'));
  assert.ok(!out.includes('ghp_0123456789abcdefABCDEF'));
  assert.ok(out.includes('[REDACTED]'));
});

test('redaction keeps triage context instead of blanking the whole line', () => {
  // Operators must be able to tell WHICH credential leaked; a full-line mask makes
  // the audit trail useless even though it is technically "safe".
  // `[` and `]` are regex metacharacters: an expected literal must be compared with
  // assert.equal, or escaped when used as a pattern.
  assert.equal(redact('Authorization: Bearer ghp_0123456789abcdefABCDEF'), 'Authorization: Bearer [REDACTED]');
  assert.equal(redact('password=hunter2hunter2'), 'password=[REDACTED]');
  assert.ok(redact('postgres://rw:hunter2@127.0.0.1:5432/dsh_companion').startsWith('postgres://rw:[REDACTED]@127.0.0.1'));
  assert.equal(redact('帮我看看构建有没有报错'), '帮我看看构建有没有报错');
  // A long run of one repeated character is not a secret; masking it would turn
  // every separator line into [REDACTED] and destroy readability.
  assert.equal(redact('x'.repeat(60)), 'x'.repeat(60));
  // Repeated application must be stable — never re-match our own marker.
  const once = redact('token=abcdefghij0123456789');
  assert.equal(redact(once), once);
});

test('preview bounds length and hashes separately', () => {
  assert.equal(preview('x'.repeat(500)).length, 200);
  assert.match(textHash('abc'), /^sha256:[0-9a-f]{64}$/);
});

test('audit sink writes append-only JSONL with the closed type vocabulary', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-'));
  const path = join(dir, 'ingress.jsonl');
  const sink = new AuditSink({ path, service: 'gateway' });
  sink.emit('authz.decision', { channel: 'onebot', chat_id: '123456', user_id: '777', rule: 'default-deny', result: 'denied' });
  sink.emit('external.message', { channel: 'telegram', text: '帮我看看构建有没有报错', textPreview: '帮我看看' });
  sink.emit('not-a-real-type', { foo: 'bar' });

  const lines = readFileSync(path, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(lines.length, 3);
  assert.equal(lines[0].type, 'authz.decision');
  assert.equal(lines[0].service, 'gateway');
  assert.ok(typeof lines[0].ts === 'number');
  // F1 class 1: message content is never stored verbatim, only hash + bounded preview
  assert.ok(!lines[1].text);
  assert.match(lines[1].text_hash, /^sha256:/);
  assert.equal(lines[1].text_preview, '帮我看看');
  assert.equal(lines[2].type, 'external.message');
});

test('credential.resolve records the ref name, never a value (D5)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-'));
  const path = join(dir, 'mem.jsonl');
  const sink = new AuditSink({ path, service: 'memory-service' });
  sink.emit('credential.resolve', { ref: 'mem-pg-rw', resolved_value: 'postgres://rw:hunter2@127.0.0.1:5432/dsh_companion', result: 'allowed' });
  const line = JSON.parse(readFileSync(path, 'utf8').trim());
  assert.equal(line.ref, 'mem-pg-rw');
  assert.ok(!JSON.stringify(line).includes('hunter2'), JSON.stringify(line));
});

test('the nine audit classes are exported for contract tests', () => {
  assert.deepEqual(AUDIT_TYPES.slice(0, 8), [
    'external.message', 'authz.decision', 'tool.call', 'approval.outcome',
    'sandbox.denied', 'credential.resolve', 'egress.connect', 'config.change',
  ]);
  assert.ok(AUDIT_TYPES.includes('memory.access'));
});
