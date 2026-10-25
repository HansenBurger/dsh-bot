/**
 * intake — the SUB listener inside the agent container (t3 §SUB, port 3005).
 *
 * Direction check, stated plainly because t3's own port table is inconsistent about
 * it: the table labels `172.28.0.10:3005` as "normalized 帧提交口（ingress → bot-core）"
 * while 172.28.0.10 is the *ingress* container's own net-ingress address, and the same
 * document gives the dsh container `BOT_SUBMIT_URL: http://172.28.0.10:3005/submit`
 * (a sender pointing at itself). Only one reading makes the pipeline work: ingress
 * sends, bot-core receives. This implementation therefore listens on the agent side,
 * pinned to 172.28.0.11 on net-ingress in compose, and the deviation is recorded in
 * docs/validation/core-impl.md rather than silently "fixed" in the docs.
 *
 * What happens to a frame here is exactly the trust transition the design talks about:
 *   1. verify signature (method+path+body+principal) + freshness + nonce replay,
 *   2. require an authorized role — `public` is refused here too (U1), even though the
 *      gateway already dropped those messages: this listener is reachable by anything
 *      on net-ingress, so it cannot assume the sender ran the gate,
 *   3. re-validate the payload against the normalized schema (`rejectUnknownFields`),
 *   4. bind the principal for the turn and hand the message to the agent.
 *
 * Step 2 is why the gate is not the security boundary by itself: the boundary is the
 * signature *plus* the re-check, on the receiving side.
 */

import { createServer } from 'node:http';
import { verify, HmacError, NonceCache } from '@dsh-bot/bot-hmac';
import { rejectUnknownFields, NormalizeError } from '@dsh-bot/bot-normalize';

const MAX_BODY_BYTES = 64 * 1024;
const ALLOWED_ROLES = Object.freeze(['owner', 'trusted']);

export class IntakeServer {
  /**
   * @param {{hmacSecret:string, port?:number, bind?:string, audit?:{emit:(t:string,f:object)=>void},
   *          onMessage:(frame:{message:object, principal:object, decision:object})=>Promise<object>|object,
   *          maxConcurrent?: number, log?:(o:object)=>void}} opts
   */
  constructor(opts) {
    this.hmacSecret = opts.hmacSecret;
    this.port = Number(opts.port ?? 3005);
    this.bind = opts.bind || '0.0.0.0';
    this.audit = opts.audit;
    this.onMessage = opts.onMessage || (async () => ({ queued: true }));
    this.nonces = new NonceCache();
    this.log = opts.log || ((o) => process.stderr.write(`${JSON.stringify({ ts: Date.now(), service: 'bot-core', ...o })}\n`));
    this.stats = { received: 0, accepted: 0, denied: 0, errors: 0 };
    this.inflight = 0;
    this.maxConcurrent = Number(opts.maxConcurrent || 2);
    this.server = null;
  }

  createServer() {
    return createServer((req, res) => {
      this.#handle(req, res).catch((err) => {
        this.stats.errors += 1;
        this.#send(res, 500, { code: 'INTERNAL' });
        this.log({ type: 'sandbox.denied', stage: 'intake', message: String(err?.message ?? err).slice(0, 120) });
      });
    });
  }

  async start() {
    this.server = this.createServer();
    await new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.port, this.bind, resolve);
    });
    this.log({ type: 'session.lifecycle', event: 'intake-listening', port: this.port, bind: this.bind });
    return this;
  }

  async stop() {
    if (!this.server) return;
    await new Promise((r) => this.server.close(r));
    this.server = null;
  }

  async #handle(req, res) {
    const url = new URL(req.url, `http://intake`);
    const path = url.pathname;
    if (req.method !== 'POST' || path !== '/submit') return this.#send(res, 404, { code: 'NOT_FOUND' });

    // Refuse on the declared size before touching the body: a request that has already
    // been fully buffered would have paid the memory cost we are trying to avoid, and
    // answering after the client is still streaming tends to end in a reset instead of
    // a readable 413.
    const declared = Number(req.headers['content-length'] || 0);
    if (declared > MAX_BODY_BYTES) {
      this.stats.denied += 1;
      this.audit?.emit('authz.decision', { stage: 'intake', result: 'denied', code: 'BODY_TOO_LARGE', declared });
      return this.#send(res, 413, { code: 'BODY_TOO_LARGE' });
    }

    let raw = '';
    try {
      raw = await readBody(req);
    } catch (err) {
      this.stats.denied += 1;
      this.audit?.emit('authz.decision', { stage: 'intake', result: 'denied', code: err?.code || 'BODY_TOO_LARGE' });
      req.destroy();
      return this.#send(res, 413, { code: 'BODY_TOO_LARGE' });
    }
    this.stats.received += 1;

    let principal;
    try {
      const verified = verify(this.hmacSecret, {
        method: req.method,
        path: url.pathname + url.search,
        body: raw || undefined,
        headers: req.headers,
        nonces: this.nonces,
      });
      principal = verified.principal;
    } catch (err) {
      const code = err instanceof HmacError ? err.code : 'UNAUTHENTICATED';
      this.stats.denied += 1;
      this.audit?.emit('authz.decision', { stage: 'intake', result: 'denied', code, path });
      return this.#send(res, 401, { code });
    }

    if (!ALLOWED_ROLES.includes(principal.role)) {
      // U1 again, on the receiving side: a submission carrying role=public means the
      // gateway's gate was bypassed, and this listener is reachable from net-ingress.
      this.stats.denied += 1;
      this.audit?.emit('authz.decision', { stage: 'intake', result: 'denied', reason: 'role-not-authorized', role: principal.role });
      return this.#send(res, 403, { code: 'FORBIDDEN_ROLE' });
    }

    let frame;
    try {
      frame = JSON.parse(raw);
      rejectUnknownFields(frame, ['v', 'message', 'decision'], 'submit frame');
      if (frame.v !== 1) throw new NormalizeError('BAD_REQUEST', 'unsupported submit version');
      rejectUnknownFields(frame.message, ['v', 'id', 'channel', 'peer', 'sender', 'atBot', 'replyTo', 'text', 'parts', 'rawRef', 'riskTags', 'receivedAt'], 'message');
      // The signed principal, not the body, decides whose conversation this is; a
      // mismatch means the frame was edited between gate and submit.
      if (frame.message?.channel !== principal.channel || String(frame.message?.peer?.chatId) !== String(principal.chatId) || String(frame.message?.sender?.userId) !== String(principal.userId)) {
        throw new NormalizeError('UNAUTHENTICATED', 'frame identity does not match the signed principal');
      }
      if (frame.decision?.role !== principal.role) throw new NormalizeError('UNAUTHENTICATED', 'decision role does not match the signed principal');
    } catch (err) {
      this.stats.denied += 1;
      const code = err instanceof NormalizeError ? err.code : 'BAD_REQUEST';
      this.audit?.emit('authz.decision', { stage: 'intake-normalize', result: 'denied', code, reason: String(err.message).slice(0, 80) });
      return this.#send(res, 400, { code });
    }

    if (this.inflight >= this.maxConcurrent) {
      // MAX_CONCURRENT_RUNS (E1): refuse instead of queueing unbounded work into the loop.
      this.audit?.emit('ratelimit.exceeded', { stage: 'intake', result: 'denied', scope: 'agent', limit: this.maxConcurrent });
      return this.#send(res, 429, { code: 'AGENT_BUSY' });
    }

    this.inflight += 1;
    try {
      const result = await this.onMessage({ message: frame.message, principal, decision: frame.decision });
      this.stats.accepted += 1;
      this.audit?.emit('authz.decision', { stage: 'intake', result: 'allowed', role: principal.role });
      return this.#send(res, 200, result);
    } catch (err) {
      this.stats.errors += 1;
      this.log({ type: 'sandbox.denied', stage: 'intake-agent', message: String(err?.message ?? err).slice(0, 120) });
      return this.#send(res, 503, { code: 'AGENT_UNAVAILABLE' });
    } finally {
      this.inflight -= 1;
    }
  }

  #send(res, status, payload) {
    const text = JSON.stringify(payload);
    res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(text) });
    res.end(text);
  }
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY_BYTES) {
        // Reject the *excess*, not the connection: destroying the socket here would
        // strand the client with "fetch failed" and no audit-visible reason. The
        // request is answered 413 and the stream is then aborted.
        req.pause();
        reject(Object.assign(new Error('body too large'), { code: 'BODY_TOO_LARGE' }));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
