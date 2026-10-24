/**
 * http — REST surface for the memory service (openapi/memory-service.yaml).
 *
 * Two listeners, one process:
 *   - internal 8091 on net-agent only: the seven /v1 paths, every request HMAC-signed
 *   - admin 8190 published to 127.0.0.1: /healthz + job triggers, no memory data
 *
 * Request discipline carried over from the design:
 *   - body ≤ 32 KiB, response ≤ 16 KiB (TM-012 flood resistance, arch §6.3)
 *   - strict schema: unknown field ⇒ 400 UNKNOWN_FIELD, never a lenient parse (C-23)
 *   - role 'public' ⇒ 403 FORBIDDEN_ROLE before any query runs (U1)
 *   - error bodies use the closed code vocabulary and never echo input text (D5/A7)
 */

import { createServer } from 'node:http';
import fs from 'node:fs';
import { verify, NonceCache, HmacError } from '@dsh-bot/bot-hmac';
import { ServiceError, MEMORY_CLASSES, SENSITIVITIES, VISIBILITIES } from './repository.mjs';
import { RISK_TAGS } from '@dsh-bot/bot-normalize';

const MAX_BODY_BYTES = 32 * 1024;
const MAX_RESPONSE_CHARS = 16 * 1024;
const CONTEXT_SLOTS = Object.freeze(['topic_stack', 'pending_question', 'entity_alias', 'last_intent']);

export class MemoryHttp {
  /**
   * @param {{repo: import('./repository.mjs').MemoryRepository, config:{hmacSecret:string}, jobs?: object, audit?: object}} deps
   */
  constructor(deps) {
    this.repo = deps.repo;
    this.config = deps.config;
    this.jobs = deps.jobs || null;
    this.audit = deps.audit || null;
    this.nonces = new NonceCache();
  }

  /** @returns {import('node:http').Server} */
  createInternalServer() {
    return createServer((req, res) => {
      this.#handle(req, res, { signed: true }).catch((err) => this.#send(res, 500, { code: 'INTERNAL', message: '内部错误' }, err));
    });
  }

  createAdminServer({ startedAt }) {
    return createServer((req, res) => {
      this.#handleAdmin(req, res, startedAt).catch((err) => this.#send(res, 500, { code: 'INTERNAL', message: '内部错误' }, err));
    });
  }

  /* ---------------------------------------------------------------- */

  async #handle(req, res, { signed }) {
    const url = new URL(req.url, 'http://internal');
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = req.method.toUpperCase();

    let raw = '';
    try {
      raw = await readBody(req);
    } catch (err) {
      return this.#send(res, 413, { code: 'BODY_TOO_LARGE', message: '请求体超过 32 KiB' });
    }

    if (path === '/healthz') {
      // Health lives on the admin port; answering here would let an internal-network
      // peer probe dependency state without a signature.
      return this.#send(res, 404, { code: 'BAD_REQUEST', message: '资源不存在' });
    }

    let principal;
    try {
      if (signed) {
        // The signature covers the request target *with* its query string, plus the
        // approval header when present — see canonicalString() in @dsh-bot/bot-hmac.
        const verified = verify(this.config.hmacSecret, {
          method,
          path: url.pathname + url.search,
          body: raw.length ? raw : undefined,
          headers: req.headers,
          nonces: this.nonces,
          bind: headerOf(req.headers, 'x-bot-approval'),
        });
        principal = verified.principal;
      }
    } catch (err) {
      const code = err instanceof HmacError ? err.code : 'UNAUTHENTICATED';
      this.audit?.emit('authz.decision', { stage: 'memory-hmac', result: 'denied', code, path });
      return this.#send(res, code === 'NONCE_REPLAY' ? 401 : 401, { code, message: '身份签名校验失败' });
    }

    // U1: nothing that reaches this service may carry role=public.
    if (principal && principal.role === 'public') {
      await this.safeLog({ principal, operation: 'search', result: 'denied', riskTags: [] });
      return this.#send(res, 403, { code: 'FORBIDDEN_ROLE', message: '该身份不可访问记忆服务' });
    }

    let body = {};
    if (raw.length > 0) {
      try {
        body = JSON.parse(raw);
      } catch {
        return this.#send(res, 400, { code: 'BAD_REQUEST', message: '请求体不是合法 JSON' });
      }
    }

    try {
      const route = matchRoute(method, path);
      if (!route) return this.#send(res, 404, { code: 'BAD_REQUEST', message: '资源不存在' });
      // Route names are data, not callables: resolve against the instance and refuse
      // to invoke anything that is not a method, so a typo is a 404 rather than a 500.
      const handler = this[route.handler];
      if (typeof handler !== 'function') return this.#send(res, 404, { code: 'BAD_REQUEST', message: '资源不存在' });
      const result = await handler.call(this, { body, query: url.searchParams, principal, params: route.params, headers: req.headers });
      return this.#send(res, result.status ?? 200, result.payload);
    } catch (err) {
      return this.#fail(res, err, principal);
    }
  }

  /* ---------------- routes ---------------- */

  /** POST /v1/memories/search */
  async routeSearch({ body, principal }) {
    rejectUnknown(body, ['query', 'principal', 'class', 'limit', 'since', 'until', 'includeExpired']);
    requireFields(body, ['query']);
    validateSearch(body);
    // The body may also carry a principal (openapi SearchRequest.principal); it must
    // agree with the signed assertion, otherwise a caller could pair one identity with
    // another's signature.
    if (body.principal !== undefined) assertPrincipalMatch(body.principal, principal);
    const out = await this.repo.search(
      { query: body.query, class: body.class, limit: body.limit, since: body.since, until: body.until },
      principal,
    );
    return { status: 200, payload: out };
  }

  /** GET /v1/memories/:id */
  async routeRead({ params, principal }) {
    const memory = await this.repo.read(params.id, principal);
    return { status: 200, payload: memory };
  }

  /** POST /v1/memories */
  async routeWrite({ body, principal, headers }) {
    rejectUnknown(body, ['subjectKey', 'class', 'scope', 'scopePeer', 'body', 'attrKey', 'sensitivity', 'visibility', 'confidence', 'occurredAt', 'sourceRef', 'riskTags', 'idempotencyKey', 'ttlDays', 'approvalId']);
    requireFields(body, ['subjectKey', 'class', 'body']);
    validateWrite(body);
    if (body.principal !== undefined) assertPrincipalMatch(body.principal, principal);
    const approvalId = headerOf(headers, 'x-bot-approval') || body.approvalId;
    const policy = await this.repo.policyFor(body.class);
    if (policy?.requires_approval && !approvalId) {
      throw new ServiceError('APPROVAL_REQUIRED', '写入长期记忆需要一次性审批令牌', 403);
    }
    const result = await this.repo.write({ ...body, approvalId }, principal);
    return { status: result.conflict ? 200 : 201, payload: result };
  }

  /** POST /v1/memories/:id/forget */
  async routeForget({ params, query, principal, headers }) {
    const dryRun = !(query.get('dryRun') === 'false' || query.get('dry_run') === 'false');
    const approvalId = headerOf(headers, 'x-bot-approval');
    const result = await this.repo.forget(params.id, { principal, dryRun, approvalId });
    return { status: 200, payload: result };
  }

  /** POST /v1/subjects/:key/forget-all */
  async routeForgetSubject({ params, query, principal, headers }) {
    const dryRun = !(query.get('dryRun') === 'false' || query.get('dry_run') === 'false');
    const approvalId = headerOf(headers, 'x-bot-approval');
    const result = await this.repo.forgetSubject(decodeURIComponent(params.key), { principal, dryRun, approvalId });
    return { status: 200, payload: result };
  }

  /** GET /v1/context/:peerKey */
  async routeGetContext({ params, principal }) {
    return { status: 200, payload: this.repo.getContext(decodeURIComponent(params.peerKey), principal) };
  }

  /** PUT /v1/context/:peerKey */
  async routePutContext({ params, body, principal }) {
    rejectUnknown(body, ['slot', 'value', 'sensitivity', 'sourceMsgId']);
    requireFields(body, ['slot', 'value']);
    if (!CONTEXT_SLOTS.includes(body.slot)) throw new ServiceError('BAD_REQUEST', 'slot 不在封闭枚举内', 400, { slot: body.slot });
    if (body.sensitivity !== undefined && !['public', 'internal'].includes(body.sensitivity)) {
      throw new ServiceError('MEMORY_REFUSED_CATEGORY', 'L1 不承载 pii/secret 级内容', 422);
    }
    const result = this.repo.putContext(decodeURIComponent(params.peerKey), body, principal);
    return { status: 200, payload: result };
  }

  /* ---------------- admin ---------------- */

  async #handleAdmin(req, res, startedAt) {
    const url = new URL(req.url, 'http://admin');
    const path = url.pathname.replace(/\/+$/, '') || '/';
    if (req.method !== 'GET' && req.method !== 'POST') return this.#send(res, 405, { code: 'BAD_REQUEST', message: '方法不允许' });

    if (path === '/healthz') {
      const health = await this.health(startedAt);
      return this.#send(res, health.status === 'ok' ? 200 : 503, health);
    }
    const jobMatch = /^\/jobs\/([a-z_]+)\/run$/.exec(path);
    if (jobMatch && req.method === 'POST') {
      if (!this.jobs) return this.#send(res, 503, { code: 'DEPENDENCY_UNAVAILABLE', message: '调度器未就绪' });
      const result = await this.jobs.runNow(jobMatch[1]);
      return this.#send(res, result.ok ? 200 : 500, result);
    }
    if (path === '/jobs') {
      const list = this.jobs ? this.jobs.status() : [];
      return this.#send(res, 200, { jobs: list });
    }
    return this.#send(res, 404, { code: 'BAD_REQUEST', message: '资源不存在' });
  }

  async health(startedAt) {
    const pg = await this.repo.pg.health();
    let sqlite = { up: false };
    try {
      sqlite = this.repo.l1.health();
    } catch (err) {
      sqlite = { up: false, error: String(err.message).slice(0, 80) };
    }
    const degradedFlag = this.config.degradedFlagPath ? isFile(this.config.degradedFlagPath) : false;
    const status = !pg.up || !sqlite.up ? 'down' : degradedFlag ? 'degraded' : 'ok';
    const jobs = this.jobs ? this.jobs.heartbeat() : [];
    return {
      status,
      pg: { up: pg.up, latencyMs: pg.latencyMs ?? null, error: pg.error ?? null },
      sqlite: { up: sqlite.up, dbBytes: sqlite.dbBytes ?? 0, pageCapPct: sqlite.pageCapPct ?? 0, integrity: sqlite.integrity },
      jobs,
      uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
      version: '0.1.0',
    };
  }

  async safeLog(entry) {
    try {
      await this.repo.logAccess(entry);
    } catch {
      /* never let audit failure mask the original error */
    }
  }

  /* ---------------- plumbing ---------------- */

  #fail(res, err, principal) {
    if (err instanceof ServiceError) {
      void this.safeLog({ principal, operation: 'read', result: err.status >= 500 ? 'error' : 'denied', riskTags: [] });
      return this.#send(res, err.status, { code: err.code, message: err.message, details: err.details });
    }
    if (err instanceof HmacError) return this.#send(res, 401, { code: err.code, message: '身份签名校验失败' });
    process.stderr.write(`${JSON.stringify({ ts: Date.now(), type: 'sandbox.denied', service: 'memory-service', level: 'error', message: String(err?.message ?? err).slice(0, 200) })}\n`);
    // A7/TM-011: no stack, no path, no SQL in the response body.
    return this.#send(res, 500, { code: 'INTERNAL', message: '内部错误' });
  }

  #send(res, status, payload, cause) {
    void cause;
    let text = JSON.stringify(payload);
    if (text.length > MAX_RESPONSE_CHARS) {
      // Truncate structurally rather than emitting invalid JSON.
      text = JSON.stringify({ code: 'INTERNAL', message: '响应超过 16 KiB', truncated: true }).slice(0, MAX_RESPONSE_CHARS);
      status = status >= 500 ? status : 500;
    }
    res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(text) });
    res.end(text);
  }
}

/* ------------------------------------------------------------------ *
 * helpers
 * ------------------------------------------------------------------ */

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        req.destroy();
        reject(new Error('body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

/**
 * Route table. Each entry declares its own parameter names so nothing has to be
 * guessed from regex source text — a mis-parsed `re.source` would silently bind the
 * wrong id into an ACL check.
 */
const ROUTES = [
  { method: 'POST', pattern: /^\/v1\/memories\/search$/, handler: 'routeSearch' },
  { method: 'GET', pattern: /^\/v1\/memories\/(?<id>[0-9a-fA-F-]{36})$/, handler: 'routeRead' },
  { method: 'POST', pattern: /^\/v1\/memories$/, handler: 'routeWrite' },
  { method: 'POST', pattern: /^\/v1\/memories\/(?<id>[0-9a-fA-F-]{36})\/forget$/, handler: 'routeForget' },
  { method: 'POST', pattern: /^\/v1\/subjects\/(?<key>[^/]+)\/forget-all$/, handler: 'routeForgetSubject' },
  { method: 'GET', pattern: /^\/v1\/context\/(?<peerKey>[^/]+)$/, handler: 'routeGetContext' },
  { method: 'PUT', pattern: /^\/v1\/context\/(?<peerKey>[^/]+)$/, handler: 'routePutContext' },
];

function matchRoute(method, path) {
  for (const route of ROUTES) {
    if (route.method !== method) continue;
    const match = route.pattern.exec(path);
    if (!match) continue;
    return { handler: route.handler, params: { ...(match.groups || {}) } };
  }
  return null;
}

function headerOf(headers, name) {
  return headers?.[String(name).toLowerCase()];
}

function rejectUnknown(obj, known) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) throw new ServiceError('BAD_REQUEST', '请求体必须是 JSON 对象', 400);
  const extra = Object.keys(obj).filter((k) => !known.includes(k));
  if (extra.length > 0) throw new ServiceError('UNKNOWN_FIELD', '请求包含未知字段', 400, { fields: extra.slice(0, 8) });
}

function requireFields(obj, fields) {
  for (const f of fields) {
    if (obj[f] === undefined || obj[f] === null || obj[f] === '') throw new ServiceError('BAD_REQUEST', `缺少必填字段 ${f}`, 400, { field: f });
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SUBJECT_KEY_RE = /^[a-z0-9_]+:[a-z]+:.+$/;

function validateSearch(body) {
  if (typeof body.query !== 'string' || body.query.length < 1 || body.query.length > 512) {
    throw new ServiceError('BAD_REQUEST', 'query 长度需在 1..512', 400);
  }
  if (body.limit !== undefined && (!Number.isInteger(body.limit) || body.limit < 1 || body.limit > 20)) {
    throw new ServiceError('BAD_REQUEST', 'limit 需在 1..20', 400);
  }
  if (Array.isArray(body.class)) {
    for (const c of body.class) if (!MEMORY_CLASSES.includes(c)) throw new ServiceError('UNKNOWN_CLASS', 'class 不在封闭枚举内', 400, { class: c });
  }
}

function validateWrite(body) {
  if (!SUBJECT_KEY_RE.test(body.subjectKey)) throw new ServiceError('BAD_REQUEST', 'subjectKey 需形如 channel:kind:id', 400);
  if (!MEMORY_CLASSES.includes(body.class)) throw new ServiceError('UNKNOWN_CLASS', 'class 不在封闭枚举内', 400, { class: body.class });
  if (typeof body.body !== 'string' || body.body.length < 1 || body.body.length > 2000) {
    throw new ServiceError('BAD_REQUEST', 'body 长度需在 1..2000', 400);
  }
  if (body.sensitivity !== undefined && !SENSITIVITIES.includes(body.sensitivity)) throw new ServiceError('BAD_REQUEST', 'sensitivity 非法', 400);
  if (body.visibility !== undefined && !VISIBILITIES.includes(body.visibility)) throw new ServiceError('BAD_REQUEST', 'visibility 非法', 400);
  if (body.scope !== undefined && !['global', 'dm', 'group'].includes(body.scope)) throw new ServiceError('BAD_REQUEST', 'scope 非法', 400);
  if (body.attrKey !== undefined && (typeof body.attrKey !== 'string' || body.attrKey.length > 128)) throw new ServiceError('BAD_REQUEST', 'attrKey 非法', 400);
  if (body.confidence !== undefined && (typeof body.confidence !== 'number' || body.confidence < 0 || body.confidence > 1)) {
    throw new ServiceError('BAD_REQUEST', 'confidence 需在 0..1', 400);
  }
  if (body.ttlDays !== undefined && (!Number.isInteger(body.ttlDays) || body.ttlDays < 1 || body.ttlDays > 3650)) {
    throw new ServiceError('BAD_REQUEST', 'ttlDays 需在 1..3650（只能缩短，不能延长）', 400);
  }
  if (Array.isArray(body.riskTags)) {
    for (const t of body.riskTags) if (!RISK_TAGS.includes(t)) throw new ServiceError('BAD_REQUEST', 'riskTag 不在封闭枚举内', 400, { tag: t });
  }
  if ((body.class === 'profile' || body.class === 'pii_raw' || body.class === 'preference') && !body.attrKey) {
    throw new ServiceError('BAD_REQUEST', 'L2 写入必须给出 attrKey', 400);
  }
}

/**
 * openapi allows a principal inside the body for readability; it MUST equal the
 * signed one, or a caller could pair a valid signature with a different identity.
 */
function assertPrincipalMatch(bodyPrincipal, signed) {
  if (!bodyPrincipal || typeof bodyPrincipal !== 'object') return;
  for (const key of ['channel', 'chatId', 'userId', 'role']) {
    if (bodyPrincipal[key] !== undefined && bodyPrincipal[key] !== signed[key]) {
      throw new ServiceError('UNAUTHENTICATED', '请求体内身份与签名断言不一致', 401);
    }
  }
}

/** Admin-side degraded flag probe (E2/E3): watcher owns this file, we only read it. */
function isFile(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}
