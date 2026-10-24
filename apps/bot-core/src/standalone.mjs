/**
 * standalone — the agent container's intake plane, runnable without a model key.
 *
 * Why this exists as a separate entrypoint: the DSH host process (`dsh --profile bot
 * web`) is the thing that actually thinks, and it cannot boot usefully on a machine
 * with no provider credential. The prototype still needs the *boundary* to be real and
 * health-checkable, so this process owns the SUB listener, verifies the signature,
 * binds the conversation principal, and hands the frame to whatever agent loop is
 * attached. `BOT_CORE_MODE=queue` (default) records the intake and returns
 * `queued: true`; `BOT_CORE_MODE=echo` answers with an acknowledgement that goes back
 * through the gateway, which is what the compose smoke test drives.
 *
 * The memory tools themselves are registered by `apply()` in ./index.mjs when the
 * plugin is loaded by DSH (deploy/profiles/bot/cordis.patch.yml); this file does not
 * reimplement them.
 */

import { createServer } from 'node:http';
import { AuditSink } from '@dsh-bot/bot-audit';
import { SecretResolver } from '@dsh-bot/bot-secrets';
import { IntakeServer } from './intake.mjs';
import { MemoryClient } from './memory-client.mjs';

const LOG = (o) => process.stderr.write(`${JSON.stringify({ ts: Date.now(), service: 'bot-core', ...o })}\n`);

export async function createStandalone(opts = {}) {
  const env = opts.env ?? process.env;
  const audit = new AuditSink({ path: env.AUDIT_SINK || '/var/log/dshbot/agent.jsonl', service: 'bot-core' });
  const resolver = new SecretResolver({ brokerUrl: env.BROKER_URL, secretsDir: env.SECRETS_DIR });
  const hmacSecret = await resolver.resolve(env.BOT_SUBMIT_HMAC_KEY_REF || env.SUBMIT_HMAC_KEY_REF, {
    label: 'submit-hmac-secret',
    literalAllowed: env.NODE_ENV === 'test' ? undefined : false,
  });
  if (!hmacSecret) throw new Error('submit HMAC secret unresolved: inbound frames could not be authenticated');

  const mode = env.BOT_CORE_MODE || 'queue';
  const memoryHmac = await resolver.resolve(env.MEM_HMAC_SECRET_REF || env.BOT_SUBMIT_HMAC_KEY_REF, { label: 'mem-hmac-secret', literalAllowed: env.NODE_ENV === 'test' ? undefined : false });
  const memory = memoryHmac ? new MemoryClient({ baseUrl: env.MEMORY_SERVICE_URL || 'http://172.28.0.50:8091', hmacSecret: memoryHmac, audit }) : null;

  const turns = [];
  const intake = new IntakeServer({
    hmacSecret,
    port: Number(env.SUBMIT_PORT || 3005),
    bind: env.SUBMIT_BIND || '0.0.0.0',
    maxConcurrent: Number(env.MAX_CONCURRENT_RUNS || 2),
    audit,
    onMessage: async ({ message, principal }) => {
      turns.push({ at: Date.now(), channel: message.channel, chatId: message.peer.chatId, userId: message.sender.userId, role: principal.role, text: message.text.slice(0, 200) });
      if (turns.length > 200) turns.shift();
      if (mode === 'echo') {
        return { reply: `收到（prototype intake，未调用模型）：${message.text.slice(0, 40)}`, queued: false };
      }
      return { queued: true };
    },
  });
  await intake.start();

  const health = createServer((req, res) => {
    const path = new URL(req.url, 'http://h').pathname.replace(/\/+$/, '') || '/';
    if (path !== '/healthz') {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end('{"code":"NOT_FOUND"}');
    }
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ status: 'ok', mode, stats: intake.stats, inflight: intake.inflight, memoryMounted: Boolean(memory), recentTurns: turns.slice(-5) }));
  });
  await new Promise((resolve, reject) => {
    health.once('error', reject);
    health.listen(Number(env.AGENT_ADMIN_PORT || 8185), '127.0.0.1', resolve);
  });

  return {
    intake,
    health,
    memory,
    turns,
    close: async () => {
      await intake.stop();
      await new Promise((r) => health.close(r));
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let app;
  try {
    app = await createStandalone();
  } catch (err) {
    process.stdout.write(`bot-core: FATAL ${String(err.message).slice(0, 200)}\n`);
    process.exitCode = 1;
  }
  const stop = async (signal) => {
    LOG({ type: 'session.lifecycle', event: 'shutdown', signal });
    if (app) await app.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.on('SIGINT', () => void stop('SIGINT'));
}
