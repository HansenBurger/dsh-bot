/**
 * @dsh-bot/bot-hmac
 *
 * Request signing for the two internal hops that cross the trust boundary:
 *   - ingress -> bot-core  (`SUB` hop, t3 deploy §2 port 3005)
 *   - bot-core -> memory-service (arch §6.4, port 8091)
 *
 * Why HMAC and not mTLS: both hops live inside `internal: true` networks with no
 * default gateway, so transport confidentiality is already constrained; what
 * remains to be proven is *authorship*. The signature plus a structured
 * principal assertion gives that without a certificate lifecycle (t3 O-8).
 *
 * Anti-forgery property relied on by C-05 / M-14: the model never sees this
 * secret, so it cannot produce these bytes — a prompt-injected agent cannot
 * claim `role: owner` unless the ingress decision actually granted it.
 *
 * Replay defence: timestamp window (±5 s) + nonce LRU (10k), per arch §6.4.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const B64URL = (buf) => buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64URL = (s) => Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64');

export const TS_SKEW_MS = 5000;
export const NONCE_CACHE_SIZE = 10_000;

/** Roles accepted by the memory service (openapi Principal.role enum). */
export const ROLES = Object.freeze(['owner', 'trusted']);

export class HmacError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'HmacError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Mint a principal assertion (base64url JSON, the wire format of arch §6.4).
 *
 * `ts` / `nonce` are overridable **for tests only** — production callers omit
 * them so freshness and replay state come from this module. The payload travels
 * encoded, which is why a test cannot string-replace `"ts":…` after the fact.
 */
export function encodePrincipal(principal, overrides = {}) {
  if (!principal || typeof principal !== 'object') throw new HmacError('BAD_REQUEST', 'principal must be an object');
  const { channel, chatId, userId, role, sessionId } = principal;
  if (!/^[a-z0-9_]+$/.test(String(channel))) throw new HmacError('BAD_REQUEST', 'principal.channel malformed');
  if (typeof chatId !== 'string' || chatId.length === 0 || chatId.length > 128) throw new HmacError('BAD_REQUEST', 'principal.chatId malformed');
  if (typeof userId !== 'string' || userId.length === 0 || userId.length > 128) throw new HmacError('BAD_REQUEST', 'principal.userId malformed');
  // C-03/A2: displayName has no place in a principal at all.
  if ('displayName' in principal || 'nickname' in principal || 'card' in principal) {
    throw new HmacError('UNKNOWN_FIELD', 'principal must not carry display text');
  }
  // public must never reach this layer (U1): the gate denies it before submission.
  if (!ROLES.includes(role)) throw new HmacError('FORBIDDEN_ROLE', 'principal.role must be owner|trusted');
  const ts = Number.isFinite(overrides.ts) ? overrides.ts : Date.now();
  const nonce = typeof overrides.nonce === 'string' && overrides.nonce.length > 0 ? overrides.nonce : B64URL(randomBytes(16));
  const payload = { channel, chatId, userId, role, ts, nonce };
  if (typeof sessionId === 'string') payload.sessionId = sessionId;
  return B64URL(Buffer.from(JSON.stringify(payload), 'utf8'));
}

export function decodePrincipal(encoded) {
  let json;
  try {
    json = fromB64URL(encoded).toString('utf8');
  } catch {
    throw new HmacError('UNAUTHENTICATED', 'principal is not base64url');
  }
  let obj;
  try {
    obj = JSON.parse(json);
  } catch {
    throw new HmacError('UNAUTHENTICATED', 'principal is not JSON');
  }
  if (!obj || typeof obj !== 'object') throw new HmacError('UNAUTHENTICATED', 'principal malformed');
  const extra = Object.keys(obj).filter((k) => !['channel', 'chatId', 'userId', 'role', 'ts', 'nonce', 'sessionId'].includes(k));
  if (extra.length) throw new HmacError('UNKNOWN_FIELD', 'principal carries unknown field(s)', { fields: extra });
  if (!ROLES.includes(obj.role)) throw new HmacError('FORBIDDEN_ROLE', 'principal.role must be owner|trusted');
  return obj;
}

const BIND_SEP = 'bind\n';

/**
 * Canonical string-to-sign: method || path || bodySha256 || principal [|| bindHash].
 * Hashing the body keeps the signed string bounded regardless of payload size.
 *
 * ⚠ `path` must be the **request target as it goes on the wire**, query string
 * included. Dropping the query is not cosmetic: `POST /v1/memories/{id}/forget`
 * carries its `dryRun` flag there, so a signature over the bare path would let an
 * on-path attacker turn a signed *preview* into a signed *delete* without breaking
 * the signature.
 *
 * `bind` is the optional third channel-binding (typically the value of
 * `X-Bot-Approval`). Unbound headers are mutable by anyone who can see the request,
 * and an approval token is exactly the field that must not be attachable after the
 * fact: with the token inside the signature, "approval present" means "approval was
 * granted before this request was built". Callers that do not bind produce byte-identical
 * strings to the previous version, so this stays compatible.
 *
 * @param {{method:string, path:string, body:string|Buffer|undefined, principal:string, bind?:string}} input
 */
export function canonicalString({ method, path, body, principal, bind }) {
  const bodyHash = createHmac('sha256', 'body-domain-separator')
    .update(body === undefined || body === null ? Buffer.alloc(0) : Buffer.from(body))
    .digest('hex');
  const base = [String(method).toUpperCase(), String(path), bodyHash, String(principal ?? '')].join('\n');
  if (typeof bind !== 'string' || bind.length === 0) return base;
  const bindHash = createHmac('sha256', BIND_SEP).update(Buffer.from(bind)).digest('hex');
  return `${base}\n${bindHash}`;
}

/**
 * @param {string} secret
 * @param {object} parts - see {@link canonicalString}
 * @returns {string} base64url signature for the X-Bot-Sig header
 */
export function sign(secret, parts) {
  if (typeof secret !== 'string' || secret.length < 16) {
    throw new HmacError('INTERNAL', 'signing secret missing or too short (D4 requires >=32 bytes)');
  }
  return B64URL(createHmac('sha256', secret).update(canonicalString(parts)).digest());
}

/** Constant-time compare that tolerates differing lengths. */
function safeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/**
 * Small insertion-ordered LRU used for nonce replay detection.
 */
export class NonceCache {
  constructor(max = NONCE_CACHE_SIZE) {
    this.max = max;
    this.map = new Map();
  }
  /** @returns {boolean} true when the nonce was already present */
  seen(nonce) {
    if (this.map.has(nonce)) {
      // refresh recency
      this.map.delete(nonce);
      this.map.set(nonce, true);
      return true;
    }
    this.map.set(nonce, true);
    if (this.map.size > this.max) this.map.delete(this.map.keys().next().value);
    return false;
  }
  get size() {
    return this.map.size;
  }
}

/** Lower-case every header key once so lookups are casing-insensitive. */
function normalizeHeaders(raw) {
  const out = {};
  for (const [k, v] of Object.entries(raw)) out[String(k).toLowerCase()] = v;
  return out;
}

/**
 * Verify an inbound signed request.

 *
 * @param {string} secret
 * @param {{method:string, path:string, body?:string|Buffer, headers:Record<string,string|undefined>, nonces?:NonceCache, now?:number}} req
 * @returns {{principal: object}} verified principal, or throws HmacError
 */
export function verify(secret, req) {
  // Node's http server lowercases inbound header names while hand-built objects
  // (tests, fetch callers) keep the canonical casing — accept both instead of
  // silently failing every signed request because of a casing mismatch.
  const headers = normalizeHeaders(req.headers || {});
  const encoded = headers['x-bot-principal'];
  const signature = headers['x-bot-sig'];
  if (!encoded || !signature) throw new HmacError('UNAUTHENTICATED', 'missing signature headers');

  const principal = decodePrincipal(encoded);

  // Freshness is checked BEFORE the signature so an expired-but-genuine request
  // reports the real reason instead of looking like a forgery.
  const now = req.now ?? Date.now();
  if (Math.abs(now - Number(principal.ts)) > TS_SKEW_MS) throw new HmacError('UNAUTHENTICATED', 'timestamp outside ±5s window');

  const expected = sign(secret, { method: req.method, path: req.path, body: req.body, principal: encoded, bind: req.bind });
  if (!safeEqual(expected, signature)) throw new HmacError('UNAUTHENTICATED', 'signature mismatch');

  if (req.nonces && req.nonces.seen(principal.nonce)) throw new HmacError('NONCE_REPLAY', 'nonce already used');

  return { principal };
}

/**
 * Attach signature headers to an outbound request.
 *
 * `principal` may be given pre-encoded; otherwise it is minted from the caller's
 * structured identity fields (channel/chatId/userId/role), so callers never hand
 * a raw JSON blob onto the wire.
 *
 * @param {string} secret
 * @param {{method:string, path:string, body?:string|Buffer, principal?:string, channel?:string, chatId?:string, userId?:string, role?:string, sessionId?:string}} parts
 * @returns {{'X-Bot-Principal': string, 'X-Bot-Sig': string}}
 */
export function signedHeaders(secret, parts) {
  const encoded =
    typeof parts.principal === 'string' ? parts.principal : encodePrincipal(parts);
  const sig = sign(secret, { method: parts.method, path: parts.path, body: parts.body, principal: encoded, bind: parts.bind });
  const headers = { 'X-Bot-Principal': encoded, 'X-Bot-Sig': sig };
  // A bound header must be *sent*, otherwise the verifier recomputes a different
  // string-to-sign; returning it here keeps bind/emit in one place.
  if (typeof parts.bind === 'string' && parts.bind.length > 0) headers['X-Bot-Approval'] = parts.bind;
  return headers;
}
