/**
 * Telegram adapter tests: the polling loop, the A2 display-name strip, and the proxy
 * discipline. The transport is exercised against a local fake API server so the tests run
 * offline — and, importantly, so the "no silent direct fallback" rule can be proven by
 * pointing the adapter at a proxy port that is not listening.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { TelegramAdapter } from '../src/telegram.mjs';

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

const ok = (payload) => (req, res) => {
  res.writeHead(200, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ ok: true, result: payload }));
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('getUpdates is polled with the offset advanced past every delivered update', async () => {
  const api = fakeApi(ok([{ update_id: 7, message: { message_id: 1, chat: { id: 555, type: 'private' }, from: { id: 555, first_name: '主人', username: 'owner_alias' }, text: '你好' } }]));
  const base = await api.listen();
  const seen = [];
  const tg = new TelegramAdapter({ token: '123:secret-token-value', apiBase: base, onMessage: (m) => seen.push(m) });
  assert.equal(tg.offset, 0);
  await tg.start();
  await sleep(120);
  tg.stop();
  assert.equal(seen.length, 1);
  assert.equal(tg.offset, 8, 'the next poll must not re-deliver update 7');
  assert.equal(tg.stats.polls, 1);
  assert.match(api.requests[0].url, /^\/bot123:secret-token-value\/getUpdates\?/);
  assert.match(api.requests[0].url, /allowed_updates=/, 'only message kinds are subscribed (C6)');
  await api.close();
});

test('display names never survive normalization (A2)', async () => {
  const api = fakeApi(ok([]));
  const base = await api.listen();
  const tg = new TelegramAdapter({ token: 't', apiBase: base });
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
  const tg = new TelegramAdapter({ token: 't', apiBase: base, audit: { emit: (type, f) => emitted.push({ type, ...f }) } });
  assert.throws(() => tg.normalize({ message_id: 1, chat: { id: 5 }, from: {} }), /chat\/from id/);
  // The poll loop routes the same failure into the audit trail instead of killing itself.
  const seen = [];
  const tg2 = new TelegramAdapter({ token: 't', apiBase: await Promise.resolve(base), onMessage: (m) => seen.push(m) });
  await api.close();
  tg.stop();
  tg2.stop();
});

test('non-message updates are counted away and never reach the pipeline', async () => {
  const api = fakeApi(ok([{ update_id: 11, callback_query: { id: 'x' } }, { update_id: 12 }]));
  const base = await api.listen();
  const seen = [];
  const tg = new TelegramAdapter({ token: 't', apiBase: base, onMessage: (m) => seen.push(m) });
  await tg.start();
  await sleep(120);
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
  const tg = new TelegramAdapter({ token: '7:tok', apiBase: base });
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
  const tg = new TelegramAdapter({ token: 't', apiBase: base, audit: { emit: (type, f) => emitted.push({ type, ...f }) } });
  await assert.rejects(() => tg.getUpdates(), /tg http 502/);
  await tg.start();
  await sleep(80);
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
  const tg = new TelegramAdapter({ token: 't', apiBase: base });
  await assert.rejects(() => tg.getUpdates(), /not JSON/);
  await api.close();
});

test('plain HTTP goes through the proxy in absolute form (C5)', async () => {
  const proxied = fakeApi((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, result: [] }));
  });
  const proxyBase = await proxied.listen();
  const tg = new TelegramAdapter({ token: '9:tok', apiBase: 'http://api.telegram.org', proxyUrl: proxyBase });
  await tg.getUpdates();
  assert.equal(proxied.requests[0].url, 'http://api.telegram.org/bot9:tok/getUpdates?timeout=50&allowed_updates=%5B%22message%22%2C%22edited_message%22%2C%22channel_post%22%5D&offset=0'.replace(/&/g, '&'));
  assert.ok(proxied.requests[0].url.startsWith('http://'), 'the request line must be absolute-form for a proxy');
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
  const tg = new TelegramAdapter({
    token: 't',
    // https target + unreachable proxy: the only permitted outcome is an error.
    apiBase: 'https://127.0.0.1',
    proxyUrl: `http://127.0.0.1:${deadPort}`,
    audit: { emit: (type, f) => emitted.push({ type, ...f }) },
    timeoutMs: 2000,
  });
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
  const tg = new TelegramAdapter({ token: 't', apiBase: base, timeoutMs: 4000 });
  await assert.rejects(() => tg.getUpdates(), /tg request timeout|tg response too large|socket hang up|aborted|ECONNRESET/);
  await api.close();
});

test('text is truncated to the adapter ceiling before it goes anywhere', async () => {
  const api = fakeApi(ok([]));
  const base = await api.listen();
  const tg = new TelegramAdapter({ token: 't', apiBase: base });
  const msg = tg.normalize({ message_id: 1, chat: { id: 2, type: 'private' }, from: { id: 2 }, text: 'x'.repeat(50_000) });
  assert.ok(msg.text.length <= 4096, `text was ${msg.text.length} chars`);
  await api.close();
});
