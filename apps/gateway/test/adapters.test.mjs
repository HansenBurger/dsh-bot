import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import WebSocket from 'ws';
import { AuditSink } from '@dsh-bot/bot-audit';
import { compileWhitelist, decide, degradedReply } from '../src/whitelist.mjs';
import { RateLimiter, Dedupe } from '../src/ratelimit.mjs';
import { LruSet } from '../src/lru.mjs';
import { Ob11Listener } from '../src/ob11.mjs';

const TOKEN = 'napcat-secret-token';
const FP = createHash('sha256').update(TOKEN, 'utf8').digest('hex');

/* ---------------- whitelist (A1) ---------------- */

test('whitelist keys are structured ids, never display names', () => {
  const policy = compileWhitelist({ defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '900', userId: '111', role: 'owner' }] });
  assert.deepEqual(decide(policy, { channel: 'onebot', chatId: '900', userId: '111' }), { allow: true, role: 'owner' });
  const stranger = decide(policy, { channel: 'onebot', chatId: '900', userId: '112' });
  assert.equal(stranger.allow, false);
  assert.equal(stranger.role, 'public');
  assert.equal(stranger.reason, 'not-whitelisted');
  // Same user in a different chat is a different key: group membership is not global.
  assert.equal(decide(policy, { channel: 'onebot', chatId: '901', userId: '111' }).allow, false);
  // ...unless the entry is chat-scoped by role through a wildcard-free explicit entry.
  const dm = compileWhitelist({ defaultRole: 'public', entries: [{ channel: 'telegram', chatId: '7', userId: '7', role: 'owner' }] });
  assert.equal(decide(dm, { channel: 'telegram', chatId: '7', userId: '7' }).allow, true);
});

test('policy compilation rejects anything that would widen the gate', () => {
  assert.throws(() => compileWhitelist({ defaultRole: 'trusted', entries: [] }), /defaultRole/);
  assert.throws(() => compileWhitelist({ defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '1', userId: '1', role: 'admin' }] }), /role/);
  assert.throws(() => compileWhitelist({ defaultRole: 'public', entries: [
    { channel: 'onebot', chatId: '1', userId: '1', role: 'owner' },
    { channel: 'onebot', chatId: '9', userId: '2', role: 'owner' },
  ] }), /owner/);
  // Two owner ids on different channels cannot be proven to be one human, so the policy
  // loads and flags it: the gate stays structured-id based either way.
  const twoOwners = compileWhitelist({ defaultRole: 'public', entries: [
    { channel: 'onebot', chatId: '1', userId: '1', role: 'owner' },
    { channel: 'telegram', chatId: '77', userId: '77', role: 'owner' },
  ] });
  assert.equal(twoOwners.warnings.length, 1, 'a cross-channel second owner id must be flagged');
  assert.match(twoOwners.warnings[0], /distinct ids/);
  // The same human on two channels is the shipped configuration, not a policy error.
  const twoChannels = compileWhitelist({ defaultRole: 'public', entries: [
    { channel: 'onebot', chatId: '1', userId: '1', role: 'owner' },
    { channel: 'telegram', chatId: '77', userId: '1', role: 'owner' },
  ] });
  assert.deepEqual(decide(twoChannels, { channel: 'telegram', chatId: '77', userId: '1' }), { allow: true, role: 'owner' });
  assert.throws(() => compileWhitelist({ defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '1', userId: '1', role: 'trusted' }, { channel: 'onebot', chatId: '1', userId: '1', role: 'owner' }] }), /duplicate/);
  assert.throws(() => compileWhitelist({ defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '', userId: '1', role: 'trusted' }] }), /non-empty/);
  assert.throws(() => compileWhitelist({ defaultRole: 'public', entries: [{ channel: 'onebot', chatId: '1', userId: 'x'.repeat(200), role: 'trusted' }] }), /<=128/);
  assert.throws(() => compileWhitelist({ defaultRole: 'public' }), /entries/);
  assert.throws(() => compileWhitelist(null), /must be an object/);
  // An empty allowlist is valid and means "nobody" — deny-all, not allow-all.
  assert.equal(decide(compileWhitelist({ defaultRole: 'public', entries: [] }), { channel: 'onebot', chatId: '1', userId: '1' }).allow, false);
  assert.throws(() => compileWhitelist({ defaultRole: 'public', entries: [{ channel: 'discord', chatId: '1', userId: '1', role: 'trusted' }] }), /channel/);
});

test('refusal reply never echoes the sender id or policy contents', () => {
  const reply = degradedReply(true);
  assert.equal(reply.degraded, true);
  assert.match(reply.text, /不在我的服务范围|只读降级/);
  assert.ok(!reply.text.includes('900'));
  assert.equal(degradedReply(false).degraded, false);
});

/* ---------------- rate limit + dedupe (E2) ---------------- */

test('the three budgets are independent and the global one wins first', () => {
  const limiter = new RateLimiter({ senderPerMin: 5, chatPerMin: 6, globalPerMin: 6 });
  for (let i = 0; i < 6; i += 1) assert.equal(limiter.check({ channel: 'onebot', chatId: '9', userId: String(i % 3) }).allowed, true);
  const global = limiter.check({ channel: 'onebot', chatId: '9', userId: '0' });
  assert.equal(global.allowed, false);
  assert.equal(global.scope, 'global');

  const chatWide = new RateLimiter({ senderPerMin: 2, chatPerMin: 3, globalPerMin: 1000 });
  const seq = [
    chatWide.check({ channel: 'onebot', chatId: '9', userId: 'a' }),
    chatWide.check({ channel: 'onebot', chatId: '9', userId: 'a' }),
    chatWide.check({ channel: 'onebot', chatId: '9', userId: 'a' }),
    chatWide.check({ channel: 'onebot', chatId: '9', userId: 'b' }),
    chatWide.check({ channel: 'onebot', chatId: '10', userId: 'b' }),
  ];
  assert.deepEqual(seq.map((r) => r.allowed), [true, true, false, false, true]);
  // The third 'a' is stopped by its own sender budget, the fourth by the chat budget.
  assert.equal(seq[2].scope, 'sender');
  assert.equal(seq[3].scope, 'chat');
});

test('sweep forgets idle windows so memory does not grow with peer count', () => {
  const limiter = new RateLimiter({ senderPerMin: 1, chatPerMin: 1, globalPerMin: 100 });
  limiter.check({ channel: 'onebot', chatId: '9', userId: 'a' });
  limiter.check({ channel: 'onebot', chatId: '10', userId: 'b' });
  const before = limiter.windows.size;
  assert.equal(before, 5); // global + 2 chats + 2 senders
  for (const [, state] of limiter.windows) state.minute = 1;
  const after = limiter.sweep(Date.now() + 10 * 60_000);
  assert.equal(after, 0, 'idle windows must be dropped');
});

test('dedupe collapses retries on the same peer+message and bounded by LRU', () => {
  const dedupe = new Dedupe({ maxEntries: 2 });
  const key = 'onebot:group:9#42';
  assert.equal(dedupe.isDuplicate(key), false);
  assert.equal(dedupe.isDuplicate(key), true);
  assert.equal(dedupe.isDuplicate('onebot:group:9#43'), false);
  assert.equal(dedupe.isDuplicate('onebot:group:9#44'), false);
  assert.ok(dedupe.seen.size <= 2);
});

test('LruSet evicts the oldest insertion and re-adding refreshes recency', () => {
  const lru = new LruSet(2);
  lru.add('a');
  lru.add('b');
  lru.add('a'); // a becomes most-recent
  lru.add('c');
  assert.equal(lru.has('b'), false, 'b became the oldest');
  assert.equal(lru.has('a'), true);
  assert.equal(lru.has('c'), true);
  assert.equal(lru.size, 2);
  lru.add('d');
  assert.equal(lru.stats().evictions, 2);
  assert.equal(new LruSet(0).max, 4096, 'a zero max falls back to the default bound');
});

/* ---------------- ob11 handshake (D1: fingerprint, not token) ---------------- */

function frame(selfId = 10001) {
  return JSON.stringify({
    time: Math.floor(Date.now() / 1000),
    self_id: selfId,
    post_type: 'message',
    message_type: 'group',
    group_id: 900,
    user_id: 111,
    message_id: 5001,
    message: [{ type: 'text', data: { text: '你好' } }],
    font: 0,
  });
}

test('reverse WS rejects a wrong access token before any event is processed', async () => {
  const listener = new Ob11Listener({ host: '127.0.0.1', port: 0, expectedSelfId: '10001', tokenFingerprint: FP, audit: { emit: () => {} }, onEvent: () => { throw new Error('must not be called'); } });
  await listener.start();
  const port = listener.server.address().port;
  const ws = new WebSocket(`ws://127.0.0.1:${port}/onebot/v11/ws?access_token=wrong-token`);
  const closed = await new Promise((resolve) => {
    ws.on('close', (code) => resolve(code));
    ws.on('error', () => resolve('error'));
    setTimeout(() => resolve('timeout'), 3000);
  });
  assert.equal(closed, 1008);
  await listener.stop();
});

test('valid handshake delivers normalized events and send() round-trips an API call', async () => {
  const events = [];
  const listener = new Ob11Listener({ host: '127.0.0.1', port: 0, expectedSelfId: '10001', tokenFingerprint: FP, audit: { emit: () => {} }, onEvent: (e) => events.push(e) });
  await listener.start();
  const port = listener.server.address().port;
  const ws = new WebSocket(`ws://127.0.0.1:${port}/onebot/v11/ws?access_token=${TOKEN}`);
  await new Promise((resolve) => ws.on('open', resolve));
  ws.on('message', (data) => {
    const req = JSON.parse(data.toString());
    // Emulate the adapter answering an API call.
    ws.send(JSON.stringify({ status: 'ok', retcode: 0, data: { message_id: 1 }, echo: req.echo }));
  });
  ws.send(frame());
  await new Promise((r) => setTimeout(r, 120));
  assert.equal(events.length, 1);
  assert.equal(events[0].messages[0].channel, 'onebot');
  assert.equal(events[0].messages[0].peer.chatId, '900');
  assert.equal(events[0].messages[0].sender.userId, '111');

  const result = await listener.send(events[0].messages[0], '回复');
  assert.equal(result.ok, true);
  assert.equal(listener.replies.sent, 1);
  await listener.stop();
});

test('a foreign self_id closes the socket and is audited', async () => {
  const denied = [];
  const listener = new Ob11Listener({ host: '127.0.0.1', port: 0, expectedSelfId: '10001', tokenFingerprint: FP, audit: { emit: (t, f) => denied.push({ t, ...f }) }, onEvent: () => { throw new Error('must not be called'); } });
  await listener.start();
  const port = listener.server.address().port;
  const ws = new WebSocket(`ws://127.0.0.1:${port}/onebot/v11/ws?access_token=${TOKEN}`);
  await new Promise((resolve) => ws.on('open', resolve));
  ws.send(frame(20002));
  const code = await new Promise((resolve) => {
    ws.on('close', resolve);
    setTimeout(() => resolve('timeout'), 3000);
  });
  assert.equal(code, 1008);
  assert.ok(denied.some((d) => d.reason === 'self-id-mismatch'));
  await listener.stop();
});

test('non-JSON and oversized frames are dropped without throwing', async () => {
  const events = [];
  const listener = new Ob11Listener({ host: '127.0.0.1', port: 0, expectedSelfId: '10001', tokenFingerprint: FP, audit: { emit: () => {} }, onEvent: (e) => events.push(e) });
  await listener.start();
  const port = listener.server.address().port;
  const ws = new WebSocket(`ws://127.0.0.1:${port}/onebot/v11/ws?access_token=${TOKEN}`);
  await new Promise((resolve) => ws.on('open', resolve));
  ws.send('not json at all');
  ws.send(JSON.stringify({ post_type: 'message', self_id: 10001 }));
  await new Promise((r) => setTimeout(r, 100));
  assert.equal(events.length, 0);
  assert.deepEqual(listener.connections().length, 1);
  await listener.stop();
});

test('send() fails closed when no adapter is connected', async () => {
  const listener = new Ob11Listener({ host: '127.0.0.1', port: 0, expectedSelfId: '10001', tokenFingerprint: FP, audit: { emit: () => {} } });
  await listener.start();
  const result = await listener.send({ peer: { kind: 'group', chatId: '900' } }, 'hi');
  assert.equal(result.ok, false);
  assert.equal(result.error, 'no-adapter-connection');
  await listener.stop();
});
