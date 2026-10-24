/**
 * submit — the SUB hop (t3 integration §SUB): the only channel through which a byte
 * controlled by a remote user can reach the agent process.
 *
 * What makes it a trust boundary rather than an HTTP call:
 *   - the principal is **minted here**, from the already-adjudicated whitelist role.
 *     The agent cannot upgrade its own audience, and `role=public` is never submitted
 *     at all (U1) — a non-whitelisted sender does not get an LLM call, so there is no
 *     prompt-injection budget spent on them;
 *   - the signature covers method + path + body hash + principal (bot-hmac), with a
 *     fresh nonce per submission so a captured request cannot be replayed;
 *   - the payload is the normalized object, never the adapter's raw frame: display
 *     names were already dropped by the normalizer (A2).
 */

import { signedHeaders } from '@dsh-bot/bot-hmac';

export class BotCoreSubmit {
  /**
   * @param {{url: string, hmacSecret: string, timeoutMs?: number, audit?: {emit:(t:string,f:object)=>void}, fetchImpl?: Function}} opts
   */
  constructor(opts) {
    this.url = opts.url;
    this.hmacSecret = opts.hmacSecret;
    this.timeoutMs = opts.timeoutMs ?? 20_000;
    this.audit = opts.audit;
    this.fetch = opts.fetchImpl || globalThis.fetch;
    this.stats = { submitted: 0, accepted: 0, rejected: 0, errors: 0 };
  }

  /**
   * @param {object} message - NormalizedMessage (frozen, from the adapter)
   * @param {{role: string}} decision
   * @returns {Promise<{ok: boolean, status?: number, reply?: string, reason?: string}>}
   */
  async submit(message, decision) {
    if (decision.role === 'public') {
      // Belt and braces: the whitelist already refused this sender. Submitting would
      // turn "policy says no" into "the LLM decides".
      this.stats.rejected += 1;
      this.audit?.emit('authz.decision', { stage: 'submit', result: 'denied', reason: 'public-role-not-submittable' });
      return { ok: false, reason: 'public-role-not-submittable' };
    }

    const body = JSON.stringify({ v: 1, message, decision: { role: decision.role, gatedAt: Date.now() } });
    const target = new URL(this.url);
    const path = `${target.pathname}${target.search}`;
    const headers = { 'content-type': 'application/json', ...signedHeaders(this.hmacSecret, { method: 'POST', path, body, channel: message.channel, chatId: message.peer.chatId, userId: message.sender.userId, role: decision.role }) };

    this.stats.submitted += 1;
    const started = Date.now();
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      const res = await this.fetch(this.url, { method: 'POST', headers, body, signal: controller.signal });
      clearTimeout(timer);
      const text = await res.text();
      let json = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        json = null;
      }
      if (!res.ok) {
        this.stats.errors += 1;
        this.audit?.emit('authz.decision', { stage: 'submit', result: 'error', status: res.status, ms: Date.now() - started });
        return { ok: false, status: res.status, reason: json?.code || `http-${res.status}` };
      }
      this.stats.accepted += 1;
      this.audit?.emit('authz.decision', { stage: 'submit', result: 'allowed', status: res.status, ms: Date.now() - started, role: decision.role });
      return { ok: true, status: res.status, reply: json?.reply ?? json?.text, queued: json?.queued === true, reason: json?.reason };
    } catch (err) {
      this.stats.errors += 1;
      this.audit?.emit('sandbox.denied', { stage: 'submit', result: 'error', message: String(err.message || err.name).slice(0, 90) });
      // Fail closed on the *reply*, not on the decision: an unreachable agent must not
      // look like "the message was never sent", because the user would resend and the
      // dedupe window would then swallow the legitimate retry.
      return { ok: false, reason: 'agent-unreachable' };
    }
  }
}
