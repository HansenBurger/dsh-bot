/**
 * memory-client — the agent-side half of the memory REST contract
 * (docs/memory/openapi/memory-service.yaml, 7 paths).
 *
 * Every call is signed as the **current conversation's** principal, minted from the
 * intake frame the gateway submitted (`channel/chatId/userId/role`). That is what
 * makes the peer boundary hold inside the agent: the plugin cannot ask for another
 * chat's memory because the signature — not a tool argument — decides the ACL, and
 * `assertPrincipalMatch` on the service side rejects any request whose body names a
 * subject the principal cannot see.
 *
 * No credential material is stored on this object beyond the HMAC secret resolved by
 * the caller, and no response body is ever logged (D5).
 */

import { signedHeaders } from '@dsh-bot/bot-hmac';

export class MemoryClientError extends Error {
  constructor(code, message, status) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export class MemoryClient {
  /**
   * @param {{baseUrl: string, hmacSecret: string, fetchImpl?: Function, timeoutMs?: number, audit?: {emit:(t:string,f:object)=>void}}} opts
   */
  constructor(opts) {
    this.baseUrl = String(opts.baseUrl || '').replace(/\/+$/, '');
    this.hmacSecret = opts.hmacSecret;
    this.fetch = opts.fetchImpl || globalThis.fetch;
    this.timeoutMs = opts.timeoutMs ?? 8000;
    this.audit = opts.audit || null;
    if (!this.baseUrl) throw new MemoryClientError('CONFIG', 'memory client needs a base url');
    if (!this.hmacSecret || this.hmacSecret.length < 16) throw new MemoryClientError('CONFIG', 'memory client HMAC secret missing or too short');
  }

  /**
   * @param {string} method
   * @param {string} path - including the query string when the contract uses one
   * @param {object|undefined} body
   * @param {{channel:string, chatId:string, userId:string, role:string}} principal
   * @param {{approvalId?: string}} [opts]
   */
  async request(method, path, body, principal, opts = {}) {
    const raw = body === undefined ? undefined : JSON.stringify(body);
    const headers = {
      accept: 'application/json',
      ...signedHeaders(this.hmacSecret, {
        method,
        path,
        body: raw,
        channel: principal.channel,
        chatId: principal.chatId,
        userId: principal.userId,
        role: principal.role,
        // The approval token is bound into the signature so it cannot be attached to
        // a request that was built before the owner approved anything.
        ...(opts.approvalId ? { bind: opts.approvalId } : {}),
      }),
    };
    if (raw !== undefined) headers['content-type'] = 'application/json';
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let res;
    try {
      res = await this.fetch(`${this.baseUrl}${path}`, { method, headers, body: raw, signal: controller.signal });
    } catch (err) {
      this.audit?.emit('sandbox.denied', { stage: 'memory-client', path, result: 'error', message: String(err.name || err.message).slice(0, 60) });
      throw new MemoryClientError('MEMORY_UNREACHABLE', '记忆服务不可达', 503);
    } finally {
      clearTimeout(timer);
    }
    let json = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    if (res.ok && json === null) {
      // A 200 that is not JSON (a proxy error page, a truncated body) must not be handed
      // to the model as `null` — the tool would report "no results" for a broken pipe.
      this.audit?.emit('authz.decision', { stage: 'memory-client', path, result: 'error', code: 'MEMORY_BAD_RESPONSE', status: res.status });
      throw new MemoryClientError('MEMORY_BAD_RESPONSE', '记忆服务响应格式异常', 502);
    }
    if (!res.ok) {
      const code = json?.code || `HTTP_${res.status}`;
      // The service's error text is user-facing Chinese and already free of internals;
      // still, only the code is surfaced to the model to keep A7's "no leakage" rule.
      this.audit?.emit('authz.decision', { stage: 'memory-client', path, result: 'denied', code, status: res.status });
      throw new MemoryClientError(code, json?.message || '记忆服务拒绝了该请求', res.status);
    }
    return json;
  }

  search(params, principal) {
    return this.request('POST', '/v1/memories/search', params, principal);
  }

  read(memoryId, principal) {
    return this.request('GET', `/v1/memories/${encodeURIComponent(memoryId)}`, undefined, principal);
  }

  write(params, principal) {
    return this.request('POST', '/v1/memories', params, principal);
  }

  forget(memoryId, principal, { dryRun = false, approvalId } = {}) {
    const query = `?dryRun=${dryRun ? 'true' : 'false'}`;
    return this.request('POST', `/v1/memories/${encodeURIComponent(memoryId)}/forget${query}`, undefined, principal, { approvalId });
  }

  forgetSubject(subjectKey, principal, { dryRun = false, approvalId } = {}) {
    const query = `?dryRun=${dryRun ? 'true' : 'false'}`;
    return this.request('POST', `/v1/subjects/${encodeURIComponent(subjectKey)}/forget-all${query}`, undefined, principal, { approvalId });
  }

  getContext(peerKey, principal) {
    return this.request('GET', `/v1/context/${encodeURIComponent(peerKey)}`, undefined, principal);
  }

  putContext(peerKey, params, principal) {
    return this.request('PUT', `/v1/context/${encodeURIComponent(peerKey)}`, params, principal);
  }
}
