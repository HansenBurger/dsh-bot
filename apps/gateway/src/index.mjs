/**
 * index — ingress gateway bootstrap (t3 §3 "L2 接入区：唯一下沉点").
 *
 * Pipeline, in the order the security baseline requires (docs/security/
 * t2-security-baseline.md A1/E1/E2, docs/design/t3-integration-architecture.md §SUB):
 *
 *   frame → normalize (display names dropped) → degraded? → dedupe
 *         → WHITELIST GATE → rate limit → mint principal → SUB (HMAC) → adapter reply
 *
 * The gate is before SUB, which is before the LLM: a non-whitelisted message costs one
 * map lookup and one audit line, and produces no model call, no tool call, and no
 * session state (A1's verification procedure is exactly this).
 *
 * Reply text is passed through `redactOutbound` on the way out (A4/A7): the agent side
 * sanitizes first, and the gateway re-checks because it is the last component that
 * speaks to a platform where the message becomes visible to other people.
 */

import { readFileSync, existsSync } from 'node:fs';
import { createServer } from 'node:http';
import { AuditSink } from '@dsh-bot/bot-audit';
import { redactOutbound } from '@dsh-bot/bot-sanitize';
import { SecretResolver } from '@dsh-bot/bot-secrets';
import { compileWhitelist, decide } from './whitelist.mjs';
import { RateLimiter, Dedupe } from './ratelimit.mjs';
import { Ob11Listener } from './ob11.mjs';
import { TelegramAdapter } from './telegram.mjs';
import { BotCoreSubmit } from './submit.mjs';

const REFUSAL_TEXT = '这条消息不在我的服务范围内。';
// Decided once at boot: an unauthorised sender is refused, and how loudly is a product
// choice with a security-relevant default.

const DEGRADED_TEXT = '伴侣暂时处于只读降级状态（安全熔断已触发），请稍后再试。';
const AGENT_DOWN_TEXT = '我现在连不上自己的思考进程，稍后再试。';

const LOG = (o) => process.stderr.write(`${JSON.stringify({ ts: Date.now(), service: 'gateway', ...o })}\n`);
const INT = (v, d) => (Number.isFinite(Number.parseInt(String(v ?? ''), 10)) ? Number.parseInt(String(v), 10) : d);

export async function createGateway(opts = {}) {
  const env = opts.env ?? process.env;
  const audit = new AuditSink({ path: env.AUDIT_SINK || '/var/log/dshbot/ingress.jsonl', service: 'gateway' });
  const resolver = new SecretResolver({ brokerUrl: env.BROKER_URL, secretsDir: env.SECRETS_DIR });

  // The signing secret is what makes SUB a trust boundary, so it is resolved as a ref
  // like every other credential.
  const hmacSecret = await resolver.resolve(env.SUBMIT_HMAC_KEY_REF || env.MEM_HMAC_SECRET_REF, {
    label: 'submit-hmac-secret',
    literalAllowed: env.NODE_ENV === 'test' ? undefined : false,
  });
  if (!hmacSecret) throw new Error('SUBMIT_HMAC_KEY_REF unresolved: submissions could not be signed');

  const policyPath = env.WHITELIST_PATH || '/etc/dshbot/whitelist.json';
  if (!existsSync(policyPath)) throw new Error(`whitelist policy ${policyPath} is missing — refusing to start with an open gate`);
  let policy;
  try {
    policy = compileWhitelist(JSON.parse(readFileSync(policyPath, 'utf8')));
  } catch (err) {
    // An unparsable policy must not degrade into "allow everything".
    throw new Error(`whitelist policy ${policyPath} is invalid: ${String(err.message).slice(0, 140)}`);
  }
  // Loud but non-fatal: the gate still closes on structured ids either way, and a
  // reviewer needs to see why a second owner id was accepted into the file.
  for (const warning of policy.warnings) LOG({ type: 'policy.warning', problem: warning });

  const limiter = new RateLimiter({
    senderPerMin: INT(env.RATE_SENDER_PER_MIN, 10),
    chatPerMin: INT(env.RATE_CHAT_PER_MIN, 30),
    globalPerMin: INT(env.RATE_GLOBAL_PER_MIN, 60),
  });
  const dedupe = new Dedupe({ maxEntries: INT(env.DEDUPE_MAX_ENTRIES, 4096) });
  const degradedFlagPath = env.DEGRADED_FLAG_PATH || '/state/degraded';
  const submit = new BotCoreSubmit({ url: env.BOT_CORE_SUBMIT_URL || 'http://172.28.0.11:3005/submit', hmacSecret, audit });

  const refuseReply = env.REFUSE_REPLY === 'polite' ? 'polite' : 'silent';
  const state = { startedAt: Date.now(), gate: { allowed: 0, refused: 0, deduped: 0, throttled: 0, degraded: 0 }, refuseReply };

  const isDegraded = () => {
    try {
      return existsSync(degradedFlagPath);
    } catch {
      return true; // unreadable flag ⇒ assume degraded (E3 fail-closed)
    }
  };

  /** Deliver a reply on whichever channel the message arrived on. */
  const deliver = async (message, text) => {
    const safe = redactOutbound(String(text ?? '')).text ?? '';
    if (!safe) return { ok: false, reason: 'empty-after-redaction' };
    if (message.channel === 'onebot' && ob11) {
      return ob11.send(message, safe);
    }
    if (message.channel === 'telegram' && tg) {
      return tg.sendMessage(message.peer.chatId, safe).then(() => ({ ok: true })).catch((err) => ({ ok: false, reason: String(err.message).slice(0, 60) }));
    }
    return { ok: false, reason: 'no-delivery-path' };
  };

  /**
   * The one pipeline every adapter feeds. Returns a receipt so adapters can log the
   * decision without re-deriving it.
   */
  const handleMessage = async (message) => {
    const ids = { channel: message.channel, chatId: message.peer.chatId, userId: message.sender.userId };
    const base = { stage: 'gate', peerKind: message.peer.kind, role: null };

    if (dedupe.isDuplicate(`${message.channel}:${message.peer.chatId}:${message.rawRef.messageId}`)) {
      state.gate.deduped += 1;
      audit.emit('authz.decision', { ...base, result: 'denied', reason: 'duplicate' });
      return { action: 'deduped' };
    }

    if (isDegraded()) {
      state.gate.degraded += 1;
      audit.emit('authz.decision', { ...base, result: 'denied', reason: 'degraded-flag' });
      await deliver(message, DEGRADED_TEXT);
      return { action: 'degraded' };
    }

    const verdict = decide(policy, ids);
    if (!verdict.allow) {
      // A1: the message stops here. No submission ⇒ no LLM call ⇒ no tool call.
      state.gate.refused += 1;
      audit.emit('authz.decision', { ...base, result: 'denied', reason: verdict.reason, structuredIds: true });
      // Silence by default. A polite refusal is still an oracle: it tells a stranger the
      // account is live, which endpoint is doing the filtering, and that probing with a
      // different id is worth trying. Set REFUSE_REPLY=polite where a visible "not my
      // human" answer is preferred (a family group, say).
      if (refuseReply === 'polite') await deliver(message, REFUSAL_TEXT);
      return { action: 'refused' };
    }

    const budget = limiter.check(ids);
    if (!budget.allowed) {
      state.gate.throttled += 1;
      audit.emit('ratelimit.exceeded', { ...base, result: 'denied', scope: budget.scope, limit: budget.limit, role: verdict.role });
      await deliver(message, '消息太快了，我先冷静一下再继续。');
      return { action: 'throttled' };
    }

    state.gate.allowed += 1;
    audit.emit('authz.decision', { ...base, result: 'allowed', role: verdict.role });
    const result = await submit.submit(message, { role: verdict.role });
    if (!result.ok) {
      await deliver(message, AGENT_DOWN_TEXT);
      return { action: 'submit-failed', reason: result.reason };
    }
    if (result.reply) await deliver(message, result.reply);
    return { action: 'submitted', role: verdict.role, replyDelivered: Boolean(result.reply) };
  };

  // --- adapters ---
  let ob11 = null;
  if (env.OB11_LISTEN !== 'off') {
    ob11 = new Ob11Listener({
      port: INT(env.OB11_PORT, 3001),
      host: env.OB11_BIND || '0.0.0.0',
      expectedSelfId: env.OB11_EXPECTED_SELF_ID || undefined,
      tokenFingerprint: env.OB11_ACCESS_TOKEN_FINGERPRINT || undefined,
      audit,
      onEvent: ({ messages, socketId }) => {
        for (const message of messages) void handleMessage({ ...message, rawRef: { ...message.rawRef, socketId } });
      },
    });
    await ob11.start();
    LOG({ type: 'session.lifecycle', event: 'ob11-listening', port: ob11.server.address().port, selfIdChecked: Boolean(ob11.expectedSelfId) });
  }

  let tg = null;
  if (env.TG_BOT_TOKEN_REF || env.TG_BOT_TOKEN) {
    const token = await resolver.resolve(env.TG_BOT_TOKEN_REF || env.TG_BOT_TOKEN, {
      label: 'tg-bot-token',
      literalAllowed: env.NODE_ENV === 'test' ? undefined : false,
    });
    if (token) {
      tg = new TelegramAdapter({ token, audit, onMessage: (m) => void handleMessage(m) });
      if (env.TG_POLL !== 'off') void tg.start();
    }
  }

  const healthServer = createServer((req, res) => {
    const path = new URL(req.url, 'http://gw').pathname.replace(/\/+$/, '') || '/';
    if (path !== '/healthz') {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end('{"code":"NOT_FOUND"}');
    }
    const body = JSON.stringify({
      status: submit.stats.errors > 0 && state.gate.allowed === 0 ? 'degraded' : 'ok',
      gate: state.gate,
      dedupe: dedupe.seen.stats(),
      adapters: { ob11: ob11 ? { connections: ob11.connections(), replies: ob11.replies } : null, telegram: tg ? tg.stats : null },
      degraded: isDegraded(),
      uptimeSeconds: Math.round((Date.now() - state.startedAt) / 1000),
    });
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(body);
  });
  await new Promise((resolve, reject) => {
    healthServer.once('error', reject);
    healthServer.listen(INT(env.GATEWAY_ADMIN_PORT, 8181), '127.0.0.1', resolve);
  });

  return {
    audit,
    policy,
    limiter,
    dedupe,
    submit,
    ob11,
    tg,
    healthServer,
    state,
    handleMessage,
    close: async () => {
      tg?.stop();
      if (ob11) await ob11.stop();
      await new Promise((r) => healthServer.close(r));
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let gw;
  try {
    gw = await createGateway();
  } catch (err) {
    process.stdout.write(`gateway: FATAL ${String(err.message).slice(0, 200)}\n`);
    process.exitCode = 1;
  }
  const stop = async (signal) => {
    LOG({ type: 'session.lifecycle', event: 'shutdown', signal });
    if (gw) await gw.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.on('SIGINT', () => void stop('SIGINT'));
}
