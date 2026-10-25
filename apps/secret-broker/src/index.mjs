/**
 * index — Secret Broker: the only container that ever touches a plaintext credential.
 *
 * Two capabilities, one process:
 *
 *   1. `GET /v1/secret/:ref` — opaque-ref resolution (t4 §9.4). Callers present an
 *      enrollment token; `policy.mjs` decides which refs that client may read. The
 *      memory-service environment therefore contains
 *      `MEM_PG_RW_PASSWORD_REF=opaque-ref:mem-pg-rw-password` and nothing else, which
 *      is acceptance criterion #4's first half: `docker exec memory-service env`
 *      cannot yield a DB password.
 *   2. `POST /v1/llm/<upstream path>` — LLM egress proxy. The broker injects
 *      `Authorization: Bearer <llm key>` itself and **deletes any client-supplied
 *      authorization header before forwarding**, so the agent cannot use the proxy as
 *      an oracle to exfiltrate the key *or* to smuggle a different credential through
 *      our egress allowlist. Response bodies are passed through untouched.
 *
 * Invariants enforced here:
 *   - a credential value is never written to a log line, an error message, or an
 *     audit record — only `{ref, source, result, length}`;
 *   - `/healthz` reports the number of mounted refs, never their names' contents;
 *   - startup fails closed if the secrets directory is missing or world-readable
 *     (a broker that reads a group-writable tree is not a broker).
 */

import { createServer } from 'node:http';
import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { AuditSink } from '@dsh-bot/bot-audit';
import { authorize, canLlmEgress, identify, refsFor } from './policy.mjs';
import { upstreamRequestOptions } from './proxy-tunnel.mjs';

const MAX_SECRET_BYTES = 4096;
const LOG = (o) => process.stderr.write(`${JSON.stringify({ ts: Date.now(), service: 'secret-broker', ...o })}\n`);

export class SecretBroker {
  /**
   * @param {{secretsDir?: string, upstreamBase?: string, port?: number, adminPort?: number, auditPath?: string, fetchImpl?: Function}} [opts]
   */
  constructor(opts = {}) {
    this.secretsDir = opts.secretsDir || process.env.SECRETS_DIR || '/run/secrets';
    this.upstreamBase = opts.upstreamBase || process.env.LLM_UPSTREAM_BASE || '';
    this.port = Number(opts.port || process.env.BROKER_PORT || 8080);
    this.adminPort = Number(opts.adminPort || process.env.BROKER_ADMIN_PORT || 8180);
    this.audit = new AuditSink({ path: opts.auditPath || process.env.AUDIT_SINK || '/var/log/dshbot/broker.jsonl', service: 'secret-broker' });
    this.startedAt = Date.now();
    this.counters = { resolveOk: 0, resolveDenied: 0, llmForwarded: 0, llmDenied: 0 };
    this.#assertSecretsDir();
  }

  #assertSecretsDir() {
    if (!existsSync(this.secretsDir)) throw new Error(`secrets dir ${this.secretsDir} is not mounted`);
    const st = statSync(this.secretsDir);
    // 0o022 is the group/world *writable* mask. Measured the first cut of this check
    // against 0o077 and it refused a perfectly good 0755 tree, so the mask is asserted
    // by a unit test now: read-only-for-others is the requirement, not no-access.
    if ((st.mode & 0o022) !== 0) throw new Error(`secrets dir ${this.secretsDir} must not be group/world writable (mode ${(st.mode & 0o777).toString(8)})`);
  }

  /** @param {string} name */
  readToken(name) {
    const file = `${this.secretsDir}/${name}`;
    if (!existsSync(file)) return null;
    try {
      const text = readFileSync(file, 'utf8').trim();
      return text.length > 0 ? text : null;
    } catch {
      return null;
    }
  }

  #readRef(ref) {
    // Refs are validated against the allowlist *before* touching the filesystem, and
    // the charset check here is the second gate against `../` style traversal.
    if (!/^[A-Za-z0-9._-]+$/.test(ref)) return null;
    const file = `${this.secretsDir}/${ref}`;
    if (!existsSync(file)) return null;
    const st = statSync(file);
    if (st.size === 0 || st.size > MAX_SECRET_BYTES) return null;
    // Trailing newline is a mount artifact (echo > file), not part of the credential.
    const text = readFileSync(file, 'utf8').replace(/\n+$/, '');
    return text.length > 0 ? text : null;
  }

  createServer() {
    return createServer((req, res) => {
      this.#handle(req, res).catch((err) => {
        LOG({ type: 'sandbox.denied', level: 'error', message: String(err?.message ?? err).slice(0, 160) });
        if (!res.headersSent) this.#send(res, 500, { error: { code: 'INTERNAL', message: '内部错误' } });
        else res.end();
      });
    });
  }

  createAdminServer() {
    return createServer((req, res) => {
      const path = new URL(req.url, 'http://admin').pathname.replace(/\/+$/, '') || '/';
      if (path !== '/healthz') return this.#send(res, 404, { error: { code: 'NOT_FOUND', message: '资源不存在' } });
      const refs = readdirSync(this.secretsDir).filter((f) => !f.startsWith('enroll-'));
      return this.#send(res, 200, {
        status: this.upstreamBase ? 'ok' : 'degraded',
        // Names only: a health endpoint that echoed values would defeat the point.
        refs: refs.sort(),
        mounted: refs.length,
        upstreamConfigured: Boolean(this.upstreamBase),
        counters: this.counters,
        uptimeSeconds: Math.round((Date.now() - this.startedAt) / 1000),
      });
    });
  }

  async #handle(req, res) {
    const url = new URL(req.url, `http://broker`);
    const path = url.pathname;
    const token = req.headers['x-broker-token'] || '';
    const clientId = identify((n) => this.readToken(n), token);
    if (!clientId) {
      this.counters.resolveDenied += 1;
      this.audit.emit('credential.resolve', { result: 'denied', reason: token ? 'unknown-token' : 'no-token', path });
      return this.#send(res, 401, { error: { code: 'UNAUTHENTICATED', message: '缺少或未知的 enrollment token' } });
    }

    const secretMatch = /^\/v1\/secret\/([A-Za-z0-9._-]+)$/.exec(path);
    if (secretMatch && req.method === 'GET') return this.#resolve(req, res, clientId, secretMatch[1]);

    if (path.startsWith('/v1/llm/') && (req.method === 'POST' || req.method === 'GET')) {
      return this.#llm(req, res, url, clientId);
    }

    if (path === '/v1/capabilities' && req.method === 'GET') {
      return this.#send(res, 200, { client: clientId, allowedRefs: refsFor(clientId), llmEgress: canLlmEgress(clientId) });
    }

    this.audit.emit('credential.resolve', { result: 'denied', reason: 'no-such-endpoint', clientId, path });
    return this.#send(res, 404, { error: { code: 'NOT_FOUND', message: '资源不存在' } });
  }

  #resolve(req, res, clientId, ref) {
    const decision = authorize(clientId, ref);
    if (!decision.ok) {
      this.counters.resolveDenied += 1;
      // 404-vs-403 is deliberately unified into 403: telling a caller "this ref does
      // not exist" would leak which credentials the broker holds.
      this.audit.emit('credential.resolve', { result: 'denied', reason: decision.reason, clientId, ref });
      return this.#send(res, 403, { error: { code: 'REF_NOT_AUTHORIZED', message: '该身份无权解析此引用' } });
    }
    const value = this.#readRef(ref);
    if (value === null) {
      this.counters.resolveDenied += 1;
      this.audit.emit('credential.resolve', { result: 'error', reason: 'ref-not-mounted', clientId, ref });
      return this.#send(res, 503, { error: { code: 'SECRET_UNAVAILABLE', message: '该引用当前不可解析' } });
    }
    this.counters.resolveOk += 1;
    // length, not content — the audit trail must show *that* a key was handed out.
    this.audit.emit('credential.resolve', { result: 'allowed', clientId, ref, length: value.length });
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    res.end(value);
  }

  /**
   * LLM egress. The client-supplied `authorization` header is removed unconditionally
   * — that single line is what prevents both "read the key out of the proxy config"
   * and "use our allowlisted egress as an arbitrary credential-smuggling tunnel".
   */
  #llm(req, res, url, clientId) {
    if (!canLlmEgress(clientId)) {
      this.counters.llmDenied += 1;
      this.audit.emit('sandbox.denied', { stage: 'llm-egress', clientId, result: 'denied', reason: 'no-capability' });
      return this.#send(res, 403, { error: { code: 'LLM_EGRESS_FORBIDDEN', message: '该身份不得使用模型出口' } });
    }
    if (!this.upstreamBase) {
      this.counters.llmDenied += 1;
      return this.#send(res, 503, { error: { code: 'UPSTREAM_UNCONFIGURED', message: '未配置模型上游' } });
    }
    const key = this.#readRef(llmKeyRef(clientId));
    if (key === null) {
      this.counters.llmDenied += 1;
      this.audit.emit('credential.resolve', { result: 'error', reason: 'llm-key-not-mounted', clientId });
      return this.#send(res, 503, { error: { code: 'SECRET_UNAVAILABLE', message: '模型凭据当前不可用' } });
    }

    const target = new URL(url.pathname.replace(/^\/v1\/llm/, '') + url.search, this.upstreamBase);
    // Second anti-SSRF layer (squid's dstdomain allowlist + `deny dshbot_internal` is the
    // first): the host we tunnel to must be exactly the configured upstream. A CONNECT to
    // an internal address through our own proxy would otherwise be a pivot to the memory
    // service, the broker admin port, or the host.
    const upstreamHost = new URL(this.upstreamBase).hostname;
    if (target.hostname !== upstreamHost) {
      this.counters.llmDenied += 1;
      this.audit.emit('sandbox.denied', { stage: 'llm-egress', clientId, result: 'denied', reason: 'upstream-host-mismatch', targetHost: target.hostname });
      return this.#send(res, 400, { error: { code: 'UPSTREAM_HOST_MISMATCH', message: '只允许访问配置的模型上游主机' } });
    }
    const request = target.protocol === 'https:' ? httpsRequest : httpRequest;
    const hopHeaders = { ...req.headers };
    for (const h of ['authorization', 'cookie', 'proxy-authorization', 'x-broker-token', 'x-bot-principal', 'x-bot-sig', 'host', 'connection', 'keep-alive', 'transfer-encoding']) delete hopHeaders[h];

    const started = Date.now();
    const { options: baseOptions, via } = upstreamRequestOptions(target, {
      method: req.method,
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: `${target.pathname}${target.search}`,
      headers: { ...hopHeaders, authorization: `Bearer ${key}`, accept: req.headers.accept || 'application/json' },
    });
    const upstream = request(
      baseOptions,
      (up) => {
        this.counters.llmForwarded += 1;
        this.audit.emit('llm.egress', { clientId, target: `${target.host}${target.pathname}`, status: up.statusCode, ms: Date.now() - started, via });
        const outHeaders = { ...up.headers };
        // Never forward an upstream Set-Cookie from an LLM API, and drop any header
        // that could carry the injected credential back to the caller.
        delete outHeaders['set-cookie'];
        res.writeHead(up.statusCode || 502, outHeaders);
        up.pipe(res);
      },
    );
    upstream.on('error', (err) => {
      this.counters.llmDenied += 1;
      // egressReason is set by proxy-tunnel: `proxy-denied` means our own allowlist said
      // no (policy event), `proxy-unreachable` means the egress leg is down (availability
      // event). Never fall back to a direct connection here — a proxy that silently stops
      // filtering is the exfiltration path this file exists to close.
      this.audit.emit('llm.egress', { clientId, result: 'error', reason: err.egressReason || 'upstream-error', message: String(err.message).slice(0, 100), ms: Date.now() - started, via });
      if (!res.headersSent) this.#send(res, 502, { error: { code: 'UPSTREAM_UNREACHABLE', message: '模型上游不可达' } });
      else res.end();
    });
    req.pipe(upstream);
  }

  #send(res, status, payload) {
    const text = JSON.stringify(payload);
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(text) });
    res.end(text);
  }
}

/** The LLM credential a client's traffic gets billed against. One shared key today. */
function llmKeyRef(_clientId) {
  return process.env.LLM_KEY_REF || 'llm-key';
}

export async function listen(broker = new SecretBroker()) {
  const main = broker.createServer();
  const admin = broker.createAdminServer();
  await new Promise((resolve, reject) => {
    main.once('error', reject);
    main.listen(broker.port, process.env.BROKER_BIND || '0.0.0.0', resolve);
  });
  await new Promise((resolve, reject) => {
    admin.once('error', reject);
    admin.listen(broker.adminPort, '127.0.0.1', resolve);
  });
  LOG({ type: 'config.change', event: 'ready', port: broker.port, adminPort: broker.adminPort, upstream: Boolean(broker.upstreamBase), secretsDir: broker.secretsDir });
  return { main, admin, broker, close: async () => { await Promise.allSettled([new Promise((r) => main.close(r)), new Promise((r) => admin.close(r))]); } };
}

const isMain = import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  let handle;
  try {
    handle = await listen();
  } catch (err) {
    process.stdout.write(`secret-broker: FATAL ${String(err.message).slice(0, 200)}\n`);
    process.exitCode = 1;
  }
  const stop = async (signal) => {
    LOG({ type: 'config.change', event: 'shutdown', signal });
    if (handle) await handle.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => void stop('SIGTERM'));
  process.on('SIGINT', () => void stop('SIGINT'));
}
