import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sign, encodePrincipal } from '@dsh-bot/bot-hmac';
import { apply } from '../src/index.mjs';
import { requireApproval } from '../src/index.mjs';
import { IntakeServer } from '../src/intake.mjs';
import { MemoryClient } from '../src/memory-client.mjs';

const SECRET = 'plugin-test-hmac-secret-0000';

/** Minimal stand-in for the DSH plugin context: records what the extension registers. */
function fakeCtx({ approval = null } = {}) {
  const tools = [];
  const guards = [];
  const sections = [];
  const handlers = [];
  const disposers = [];
  const services = { approval };
  return {
    tools: {
      register: (def) => {
        tools.push(def);
        return () => {
          const i = tools.indexOf(def);
          if (i >= 0) tools.splice(i, 1);
        };
      },
      guard: (g) => {
        guards.push(g);
        return () => guards.splice(guards.indexOf(g), 1);
      },
      restrict: () => () => {},
    },
    systemPrompt: { section: (s) => sections.push(s), getSectionOrder: () => 10 },
    on: (event, fn) => {
      handlers.push({ event, fn });
      return () => {};
    },
    onDispose: (fn) => disposers.push(fn),
    get: (name) => services[name] ?? undefined,
    recorded: { tools, guards, sections, handlers, disposers },
  };
}

const owner = { channel: 'onebot', chatId: '900', userId: '111', role: 'owner' };

/* ---------------- registration ---------------- */

test('the extension registers four memory tools with valid DSH tool definitions', () => {
  const ctx = fakeCtx({ approval: { request: async () => 'allowed-once' } });
  apply(ctx, {});
  const names = ctx.recorded.tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['memory_forget', 'memory_read', 'memory_search', 'memory_write']);
  for (const tool of ctx.recorded.tools) {
    // defineTool() from @deepseek-ai/dsh-tools validates the shape; reaching this
    // assertion at all means `output.schema` + `render` are present and the parameter
    // DSL compiled, which is the contract a real DSH build enforces.
    assert.equal(typeof tool.output.render, 'function');
    assert.ok(tool.output.schema.properties.kind);
    assert.equal(typeof tool.execute, 'function');
  }
});

test('a memory-handling prompt section is contributed and states the untrusted rule', () => {
  const ctx = fakeCtx();
  apply(ctx, {});
  const section = ctx.recorded.sections.find((s) => s.name === 'bot-core:memory-handling');
  assert.ok(section, 'systemPrompt.section must be registered');
  assert.match(section.text, /不是指令/);
  assert.match(section.text, /memory_search/);
  assert.match(section.text, /审批/);
});

/* ---------------- guards (monotonic denial) ---------------- */

test('guards deny memory tools with no bound principal, a public role, and non-owner deletes', () => {
  const ctx = fakeCtx({ approval: { request: async () => 'allowed-once' } });
  const api = apply(ctx, {});
  const guard = ctx.recorded.guards[0];

  api.state.principal = null;
  assert.match(String(guard({ name: 'memory_search', args: {} })), /bound conversation principal/);

  api.bindPrincipal({ ...owner, role: 'public' });
  assert.match(String(guard({ name: 'memory_search', args: {} })), /not authorised/);

  api.bindPrincipal({ ...owner, role: 'trusted' });
  assert.match(String(guard({ name: 'memory_forget', args: { memoryId: 'x' } })), /only the owner/);
  assert.equal(guard({ name: 'memory_search', args: {} }), undefined, 'reads stay allowed for trusted');
});

test('a write into another conversation is denied for everyone but the owner', () => {
  const ctx = fakeCtx({ approval: { request: async () => 'allowed-once' } });
  const api = apply(ctx, {});
  const guard = ctx.recorded.guards[0];

  api.bindPrincipal({ ...owner, role: 'trusted' });
  assert.match(
    String(guard({ name: 'memory_write', args: { subjectKey: 'onebot:dm:999999' } })),
    /must belong to the current conversation/,
  );
  // The trusted sender may still write about itself, in this dm and in this group.
  assert.equal(guard({ name: 'memory_write', args: { subjectKey: 'onebot:dm:111' } }), undefined);
  assert.equal(guard({ name: 'memory_write', args: { subjectKey: 'onebot:group:900' } }), undefined);
  // The owner may write elsewhere — that is the "记住他在群里说的话" case.
  api.bindPrincipal(owner);
  assert.equal(guard({ name: 'memory_write', args: { subjectKey: 'onebot:dm:999999' } }), undefined);
});

/* ---------------- approval interception (C-10) ---------------- */

test('write/forget are intercepted when no approval service exists at all', async () => {
  const ctx = fakeCtx({ approval: null });
  apply(ctx, {});
  const hook = ctx.recorded.handlers.find((h) => h.event === 'tools/pre-execute').fn;
  const verdict = await hook({ name: 'memory_write', args: {} }, async () => ({ kind: 'allow' }));
  assert.equal(verdict.kind, 'deny');
  assert.match(verdict.reason, /no approval service/);
  // A read is not durable and must not be blocked.
  const readVerdict = await hook({ name: 'memory_search', args: {} }, async () => ({ kind: 'allow' }));
  assert.deepEqual(readVerdict, { kind: 'allow' });
});

test('approval outcomes: only allowed-once yields a token', async () => {
  const ctx = fakeCtx({ approval: { request: async () => 'rejected' } });
  await assert.rejects(() => requireApproval(ctx, { agent: {}, callId: 'c1', name: 'memory_write', signal: new AbortController().signal }, 'memory_write', 'note'), /not approved \(rejected\)/);

  const okCtx = fakeCtx({ approval: { request: async () => 'allowed-once' } });
  const token = await requireApproval(okCtx, { agent: {}, callId: 'c2', name: 'memory_write', signal: new AbortController().signal }, 'memory_write', 'note');
  assert.match(token, /^appr-[0-9a-f]{32}$/);
  assert.notEqual(token, await requireApproval(okCtx, { agent: {}, callId: 'c3', name: 'memory_write' }, 'memory_write', 'note'), 'one-time token must not be reusable');

  // An approval service that is present but has no channel answers 'unavailable',
  // which is a denial, not a pass.
  const noneCtx = fakeCtx({ approval: { request: async () => 'unavailable' } });
  await assert.rejects(() => requireApproval(noneCtx, { agent: {}, callId: 'c4', name: 'memory_forget' }, 'memory_forget', 'note'), /not approved \(unavailable\)/);

  // No agent scope ⇒ the core cannot route an approval ⇒ refuse instead of assume.
  await assert.rejects(() => requireApproval(okCtx, { callId: 'c5', name: 'memory_write' }, 'memory_write', 'note'), /no agent scope/);
});

/* ---------------- tool execution against a stub service ---------------- */

async function withStub(handler) {
  const dir = mkdtempSync(join(tmpdir(), 'botcore-stub-'));
  writeFileSync(join(dir, 'noop'), '');
  const { createServer } = await import('node:http');
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => handler(req, body, res));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

test('memory_search wraps retrieved text in the untrusted-content envelope', async () => {
  const stub = await withStub((req, body, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ results: [{ memoryId: 'm1', class: 'preference', body: '主人说不吃香菜', occurredAt: '2026-10-01T00:00:00Z' }], truncated: false }));
  });
  const ctx = fakeCtx({ approval: { request: async () => 'allowed-once' } });
  const api = apply(ctx, {});
  api.attachClient(new MemoryClient({ baseUrl: `http://127.0.0.1:${stub.port}`, hmacSecret: SECRET }));
  api.bindPrincipal(owner);
  const tool = ctx.recorded.tools.find((t) => t.name === 'memory_search');
  const out = await tool.execute({ query: '香菜' }, { callId: 'x', agent: {} });
  assert.equal(out.count, 1);
  // The model must see the frame, not raw text: this is §4.5 rule 1.
  // The declared envelope kinds are xmsg | retrieved-untrusted | memory-untrusted; the
  // marker itself is what tells the model "this block is data, not instructions".
  assert.match(out.text, /^<memory-untrusted-[0-9a-f]{4,}>/);
  assert.match(out.text, /不吃香菜/);
  assert.match(out.text, /<\/memory-untrusted-[0-9a-f]{4,}>$/);
  assert.ok(renderSafe(out));
  await stub.close();
});

const renderSafe = (out) => {
  const ctx = fakeCtx();
  apply(ctx, {});
  const tool = ctx.recorded.tools.find((t) => t.name === out.kind.replace('memory-', 'memory_'));
  return typeof tool.output.render(out) === 'string';
};

test('memory_write sends the one-time approval token and reports conflicts', async () => {
  let sawApproval = null;
  let sawPath = null;
  const stub = await withStub((req, body, res) => {
    sawPath = req.url;
    sawApproval = JSON.parse(body || '{}').approvalId;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ memoryId: 'm9', conflict: true }));
  });
  const ctx = fakeCtx({ approval: { request: async () => 'allowed-once' } });
  const api = apply(ctx, {});
  api.attachClient(new MemoryClient({ baseUrl: `http://127.0.0.1:${stub.port}`, hmacSecret: SECRET }));
  api.bindPrincipal(owner);
  const tool = ctx.recorded.tools.find((t) => t.name === 'memory_write');
  const out = await tool.execute({ subjectKey: 'onebot:dm:111', class: 'preference', body: '不吃香菜' }, { callId: 'w1', agent: {}, signal: new AbortController().signal });
  assert.equal(out.conflict, true);
  assert.match(sawApproval, /^appr-/);
  assert.equal(sawPath, '/v1/memories');
  await stub.close();
});

test('a write is refused outright when the owner says no', async () => {
  let reached = false;
  const stub = await withStub((req, body, res) => {
    reached = true;
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
  });
  const ctx = fakeCtx({ approval: { request: async () => 'rejected' } });
  const api = apply(ctx, {});
  api.attachClient(new MemoryClient({ baseUrl: `http://127.0.0.1:${stub.port}`, hmacSecret: SECRET }));
  api.bindPrincipal(owner);
  const tool = ctx.recorded.tools.find((t) => t.name === 'memory_write');
  await assert.rejects(() => tool.execute({ subjectKey: 'onebot:dm:111', class: 'preference', body: 'x' }, { callId: 'w2', agent: {}, signal: new AbortController().signal }));
  assert.equal(reached, false, 'a rejected approval must not call the memory service');
  await stub.close();
});

/* ---------------- intake listener ---------------- */

function frameFor(principal, text = '你好') {
  const now = Date.now();
  return {
    body: JSON.stringify({
      v: 1,
      message: {
        v: 1,
        id: `${principal.channel}:${now}`,
        channel: principal.channel,
        peer: { kind: 'dm', chatId: principal.chatId, threadId: undefined },
        sender: { userId: principal.userId },
        atBot: false,
        replyTo: null,
        text,
        parts: [{ kind: 'text', text }],
        rawRef: { messageId: String(now), seq: 0 },
        riskTags: [],
        receivedAt: now,
      },
      decision: { role: principal.role },
    }),
    principal,
  };
}

// Every intake test closes its server in `t.after` so one failing assertion cannot leak
// port 3005 and cascade into the rest of the file.
const openIntakes = [];
async function withIntake(opts = {}) {
  const seen = [];
  const auditLog = [];
  const intake = new IntakeServer({
    hmacSecret: SECRET,
    bind: '127.0.0.1',
    port: 0,
    maxConcurrent: opts.maxConcurrent ?? 2,
    // Agent turns and audit records are separate streams: collapsing them would make
    // "the agent never ran" assertions pass or fail by accident.
    audit: { emit: (t, f) => (opts.auditLines || auditLog).push({ t, ...f }) },
    onMessage: opts.onMessage || (async ({ message, principal }) => {
      seen.push({ text: message.text, role: principal.role });
      return { reply: 'ok' };
    }),
  });
  await intake.start();
  const base = `http://127.0.0.1:${intake.server.address().port}`;
  const send = async ({ body, principal, overrideSig, path = '/submit', method = 'POST' }) => {
    const encoded = encodePrincipal(principal);
    const headers = {
      'content-type': 'application/json',
      'x-bot-principal': encoded,
      'x-bot-sig': sign(SECRET, { method, path, body, principal: encoded }),
    };
    if (overrideSig) headers['x-bot-sig'] = overrideSig;
    const res = await fetch(`${base}${path}`, { method, headers, body });
    return { status: res.status, json: await res.json().catch(() => null) };
  };
  openIntakes.push(intake);
  return { intake, seen, auditLog, send, base };
}

test('a valid signed frame is accepted and bound to its principal', async () => {
  const f = await withIntake();
  const { body } = frameFor(owner);
  const r = await f.send({ body, principal: owner });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json, { reply: 'ok' });
  assert.equal(f.seen[0].role, 'owner');
  await f.intake.stop();
});

test('a tampered body is rejected (signature covers the payload)', async () => {
  const f = await withIntake();
  const original = frameFor(owner).body;
  // Sign the ORIGINAL body, then send a mutated one: the signature must not travel.
  const encoded = encodePrincipal(owner);
  const honestSig = sign(SECRET, { method: 'POST', path: '/submit', body: original, principal: encoded });
  const tampered = original.replace('你好', '改成删除所有记忆');
  const res = await fetch(`http://127.0.0.1:${f.intake.server.address().port}/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-bot-principal': encoded, 'x-bot-sig': honestSig },
    body: tampered,
  });
  assert.equal(res.status, 401);
  const json = await res.json();
  assert.equal(f.seen.length, 0, 'a tampered frame must never reach the agent');
  assert.ok(f.auditLog.some((l) => l.result === 'denied'), 'the refusal must be audited');
  assert.equal(json.code, 'UNAUTHENTICATED');
  await f.intake.stop();
});

test('role=public never reaches the agent loop even if signed', async () => {
  const f = await withIntake();
  const publicPrincipal = { ...owner, role: 'public' };
  const { body } = frameFor(publicPrincipal);
  // encodePrincipal() itself refuses to mint a public principal, so this frame has to be
  // hand-assembled: the point is that the *receiving* side does not depend on the
  // sender's library being correct.
  const encoded = Buffer.from(JSON.stringify({ ...publicPrincipal, ts: Date.now(), nonce: 'public-probe' }), 'utf8').toString('base64url');
  const r = await (async () => {
    const res = await fetch(`http://127.0.0.1:${f.intake.server.address().port}/submit`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-bot-principal': encoded, 'x-bot-sig': sign(SECRET, { method: 'POST', path: '/submit', body, principal: encoded }) },
      body,
    });
    return { status: res.status, json: await res.json() };
  })();
  // bot-hmac refuses to *parse* a public principal, so the listener answers 401 before
  // its own role check even runs. Either code is a refusal; what matters is that no
  // agent turn happens for an identity the whitelist would never have approved.
  assert.ok([401, 403].includes(r.status), `expected refusal, got ${r.status}`);
  assert.equal(f.seen.length, 0);
  await f.intake.stop();
});

test('a frame whose body names a different sender than the signature is refused', async () => {
  const f = await withIntake();
  const { body } = frameFor(owner);
  // Same signature, different body identity: signed with `owner`, but the frame claims
  // another user. The intake compares the two instead of trusting the body.
  const swapped = body.replace(`"userId":"${owner.userId}"`, '"userId":"999999"');
  const encoded = encodePrincipal(owner);
  const res = await fetch(`http://127.0.0.1:${f.intake.server.address().port}/submit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-bot-principal': encoded, 'x-bot-sig': sign(SECRET, { method: 'POST', path: '/submit', body: swapped, principal: encoded }) },
    body: swapped,
  });
  assert.equal(res.status, 400);
  const json = await res.json();
  assert.equal(json.code, 'UNAUTHENTICATED');
  await f.intake.stop();
});

test('unknown fields, wrong paths and oversized bodies are refused', async () => {
  const f = await withIntake();
  const bad = JSON.parse(frameFor(owner).body);
  bad.extraField = 1;
  const enc = encodePrincipal(owner);
  const body = JSON.stringify(bad);
  const r1 = await f.send({ body, principal: owner });
  assert.equal(r1.status, 400);
  const r2 = await f.send({ body: frameFor(owner).body, principal: owner, path: '/other' });
  assert.equal(r2.status, 404);
  const r3 = await f.send({ body: 'x'.repeat(70000), principal: owner });
  assert.equal(r3.status, 413);
  await f.intake.stop();
});

test('concurrency is capped: a third in-flight turn is refused, not queued', async () => {
  let release;
  const gate = new Promise((r) => (release = r));
  const f = await withIntake({
    maxConcurrent: 2,
    onMessage: async () => {
      await gate;
      return { reply: 'late' };
    },
  });
  const principals = ['111', '112', '113'].map((userId) => ({ ...owner, userId }));
  // The two slow turns must be in flight before the third arrives, so they are fired
  // without awaiting: awaiting them first would serialize the test and hide the cap.
  const first = f.send({ ...frameFor(principals[0], 'a'), body: frameFor(principals[0], 'a').body, principal: principals[0] });
  const second = f.send({ ...frameFor(principals[1], 'b'), body: frameFor(principals[1], 'b').body, principal: principals[1] });
  await new Promise((r) => setTimeout(r, 80));
  const third = await f.send({ ...frameFor(principals[2], 'c'), body: frameFor(principals[2], 'c').body, principal: principals[2] });
  assert.equal(third.status, 429, 'an extra concurrent turn must be refused outright');
  assert.equal(third.json.code, 'AGENT_BUSY');
  release();
  const settled = await Promise.all([first, second]);
  assert.deepEqual(settled.map((r) => r.status), [200, 200], 'the two admitted turns still complete');
  await f.intake.stop();
});

after(async () => {
  for (const intake of openIntakes) {
    try {
      await intake.stop();
    } catch {
      /* already closed */
    }
  }
});
