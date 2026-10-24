/**
 * Telegram adapter tests: the polling loop, the A2 display-name strip, and the proxy
 * discipline. The transport is exercised against a local fake API server so the tests run
 * offline — and, importantly, so the "no silent direct fallback" rule can be proven by
 * pointing the adapter at a proxy port that is not listening.
 */

import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { TelegramAdapter } from '../src/telegram.mjs';

// A failing assertion inside a test that already started the poll loop would otherwise
// leave the fake server listening, and node --test then never exits: the suite looks
// hung instead of failed. Everything created is registered and torn down here.
const openServers = [];
const openAdapters = [];

function fakeApi(handler) {
  const requests = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body });
      handler(req, res, body, requests.length);
    });
  });
  return { server, requests, listen: async () => { server.listen(0, '127.0.0.1'); await once(server, 'listening'); return `http://127.0.0.1:${server.address().port}`; }, close: () => new Promise((r) => server.close(r)) };
}

// Offset-aware like the real Bot API: the adapter keeps polling, and a fake that answers
// every poll with the same batch would keep re-delivering updates.
const ok = (payload) => (req, res) => {
  const delivered = Number(new URL(req.url, 'http://x').searchParams.get('offset') || 0) > 0 ? [] : payload;
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ ok: true, result: delivered }));
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Wraps an adapter so the after() hook can stop its poll loop.
function track(adapter) {
  openAdapters.push(adapter);
  return adapter;
}

after(async () => {
  for (const a of openAdapters) a.stop();
  for (const s of openServers) {
    s.closeAllConnections?.();
    await new Promise((r) => s.close(r));
  }
});

// The poll loop is asynchronous and re-arms immediately; waiting for a condition is the
// only stable way to assert on it. A fixed sleep would fail on a loaded machine and pass
// by luck on an idle one.
async function waitFor(what, cond, ms = 3000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    if (cond()) return;
    await sleep(25);
  }
  assert.fail(`timed out waiting for ${what}`);
}

test('getUpdates is polled with the offset advanced past every delivered update', async () => {
  const api = fakeApi(ok([{ update_id: 7, message: { message_id: 1, chat: { id: 555, type: 'private' }, from: { id: 555, first_name: '主人', username: 'owner_alias' }, text: '你好' } }]));
  const base = await api.listen();
  const seen = [];
  const tg = track(new TelegramAdapter({ token: '123:secret-token-value', apiBase: base, onMessage: (m) => seen.push(m) }));
  assert.equal(tg.offset, 0);
  await tg.start();
  await waitFor('one delivered message', () => seen.length >= 1);
  tg.stop();
  assert.equal(seen.length, 1);
  assert.equal(tg.offset, 8, 'the next poll must not re-deliver update 7');
  assert.ok(tg.stats.polls >= 1, `expected at least one poll, got ${tg.stats.polls}`);
  assert.match(api.requests[0].url, /^\/bot123:secret-token-value\/getUpdates\?/);
  assert.match(api.requests[0].url, /allowed_updates=/, 'only message kinds are subscribed (C6)');
  await api.close();
});

test('display names never survive normalization (A2)', async () => {
  const api = fakeApi(ok([]));
  const base = await api.listen();
  const tg = track(new TelegramAdapter({ token: 't', apiBase: base }));
  const msg = tg.normalize({
    message_id: 42,
    chat: { id: 900, type: 'group', title: '家人群' },
    from: { id: 901, first_name: '大肥鱼', last_name: '主人', username: 'fishy_owner' },
    text: '买点菜',
    entities: [{ type: 'mention', url: 'http://t.me/bigfish_bot', offset: 0, length: 1 }],
  });
  const json = JSON.stringify(msg);
  assert.ok(!json.includes('大肥鱼') && !json.includes('fishy_owner') && !json.includes('家人群'), 'no display text may be carried');
  assert.equal(msg.peer.kind, 'group');
  assert.equal(msg.peer.chatId, '900');
  assert.equal(msg.sender.userId, '901');
  assert.equal(msg.channel, 'telegram');
  assert.equal(msg.atBot, true, 'a bot mention is structural, not a nickname match');
  await tg.stop();
  await api.close();
});

test('an update without chat or sender ids is refused, not guessed', async () => {
  const api = fakeApi(ok([]));
  const base = await api.listen();
  const emitted = [];
  const tg = track(new TelegramAdapter({ token: 't', apiBase: base, audit: { emit: (type, f) => emitted.push({ type, ...f }) } }));
  assert.throws(() => tg.normalize({ message_id: 1, chat: { id: 5 }, from: {} }), /chat\/from id/);
  // The poll loop routes the same failure into the audit trail instead of killing itself:
  // one malformed update must not stop the channel for the good one behind it.
  const bad = fakeApi(ok([
    { update_id: 3, message: { message_id: 1, chat: { id: 5 }, from: {} } },
    { update_id: 4, message: { message_id: 2, chat: { id: 6, type: 'private' }, from: { id: 6 }, text: '还在' } },
  ]));
  const badBase = await bad.listen();
  const seen = [];
  const tg2 = track(new TelegramAdapter({ token: 't', apiBase: badBase, audit: { emit: (type, f) => emitted.push({ type, ...f }) }, onMessage: (m) => seen.push(m) }));
  await tg2.start();
  await waitFor('the good update after a bad one', () => seen.length === 1);
  tg2.stop();
  assert.ok(emitted.some((e) => e.stage === 'tg-normalize' && e.result === 'denied'), 'the refusal is audited');
  assert.equal(tg2.offset, 5, 'the malformed update still consumes its id');
  await bad.close();
  await api.close();
  tg.stop();
});

test('non-message updates are counted away and never reach the pipeline', async () => {
  const api = fakeApi(ok([{ update_id: 11, callback_query: { id: 'x' } }, { update_id: 12 }]));
  const base = await api.listen();
  const seen = [];
  const tg = track(new TelegramAdapter({ token: 't', apiBase: base, onMessage: (m) => seen.push(m) }));
  await tg.start();
  await waitFor('the offset to advance past both updates', () => tg.offset === 13);
  tg.stop();
  assert.equal(seen.length, 0);
  assert.equal(tg.offset, 13, 'even an ignorable update consumes its id');
  await api.close();
});

test('sendMessage posts to the bot path and returns the API result', async () => {
  const api = fakeApi((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, result: { message_id: 99 } }));
  });
  const base = await api.listen();
  const tg = track(new TelegramAdapter({ token: '7:tok', apiBase: base }));
  const out = await tg.sendMessage('555', '我记住了');
  assert.equal(out.result.message_id, 99);
  assert.equal(api.requests[0].url, '/bot7:tok/sendMessage');
  assert.deepEqual(JSON.parse(api.requests[0].body), { chat_id: '555', text: '我记住了', disable_web_page_preview: true });
  await api.close();
});

test('a 5xx from the API surfaces as an error and the loop backs off', async () => {
  const api = fakeApi((req, res) => {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('bad gateway');
  });
  const base = await api.listen();
  const emitted = [];
  const tg = track(new TelegramAdapter({ token: 't', apiBase: base, audit: { emit: (type, f) => emitted.push({ type, ...f }) } }));
  await assert.rejects(() => tg.getUpdates(), /tg http 502/);
  await tg.start();
  await waitFor('a poll error', () => tg.stats.errors >= 1);
  assert.ok(tg.stats.errors >= 1);
  assert.ok(emitted.some((e) => e.stage === 'tg-poll'), 'poll failures are audited');
  tg.stop();
  await api.close();
});

test('a non-JSON body is an error, not a silently empty result', async () => {
  const api = fakeApi((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<html>login required</html>');
  });
  const base = await api.listen();
  const tg = track(new TelegramAdapter({ token: 't', apiBase: base }));
  await assert.rejects(() => tg.getUpdates(), /not JSON/);
  await api.close();
});

test('plain HTTP goes through the proxy in absolute form (C5)', async () => {
  const proxied = fakeApi((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, result: [] }));
  });
  const proxyBase = await proxied.listen();
  const tg = track(new TelegramAdapter({ token: '9:tok', apiBase: 'http://api.telegram.org', proxyUrl: proxyBase }));
  await tg.getUpdates();
  const url = decodeURIComponent(proxied.requests[0].url);
  assert.ok(url.startsWith('http://api.telegram.org/bot9:tok/getUpdates?'), `absolute-form expected, got ${url}`);
  assert.ok(url.includes('allowed_updates=["message","edited_message"'), 'only message kinds are subscribed');
  await proxied.close();
});

test('a dead proxy fails the request instead of falling back to a direct connection', async () => {
  // Reserve a port, then close it: connecting to it is a reliable ECONNREFUSED.
  const probe = createServer();
  probe.listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const deadPort = probe.address().port;
  await new Promise((r) => probe.close(r));

  const direct = fakeApi(ok([]));
  const directBase = await direct.listen();
  const emitted = [];
  const tg = track(new TelegramAdapter({
    token: 't',
    // https target + unreachable proxy: the only permitted outcome is an error.
    apiBase: 'https://127.0.0.1',
    proxyUrl: `http://127.0.0.1:${deadPort}`,
    audit: { emit: (type, f) => emitted.push({ type, ...f }) },
    timeoutMs: 2000,
  }));
  await assert.rejects(() => tg.sendMessage('1', 'x'), /proxy unreachable|ECONNREFUSED/);
  assert.equal(direct.requests.length, 0, 'no request may bypass the egress allowlist');
  await direct.close();
});

test('oversized responses are cut off rather than buffered without limit', async () => {
  const api = fakeApi((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    // Far beyond the 4 MiB cap the adapter sets on itself.
    res.write('{"ok":true,"result":[');
    const chunk = '{"update_id":1},'.repeat(200_000);
    for (let i = 0; i < 30; i += 1) res.write(chunk);
    res.end(']}');
  });
  const base = await api.listen();
  const tg = track(new TelegramAdapter({ token: 't', apiBase: base, timeoutMs: 4000 }));
  await assert.rejects(() => tg.getUpdates(), /tg request timeout|tg response too large|socket hang up|aborted|ECONNRESET/);
  await api.close();
});

test('text is truncated to the adapter ceiling before it goes anywhere', async () => {
  const api = fakeApi(ok([]));
  const base = await api.listen();
  const tg = track(new TelegramAdapter({ token: 't', apiBase: base }));
  const msg = tg.normalize({ message_id: 1, chat: { id: 2, type: 'private' }, from: { id: 2 }, text: 'x'.repeat(50_000) });
  assert.ok(msg.text.length <= 4096, `text was ${msg.text.length} chars`);
  await api.close();
});
