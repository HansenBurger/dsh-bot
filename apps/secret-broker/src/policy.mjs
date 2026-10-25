/**
 * policy — who may resolve which opaque ref (Secret Broker, t4 §9.4 / D-09).
 *
 * The broker is the only container holding real credentials. Its job is not to
 * "store secrets nicely" but to make the *blast radius* of a compromised container
 * equal to that container's own authorisation: bot-core can obtain the HMAC secret it
 * needs to sign requests, and nothing else — it must never be able to read the PG
 * password or the memory KEK, because the agent process is the thing most exposed to
 * prompt injection.
 *
 * Two client classes exist:
 *   - `memory-service` (pinned 172.28.0.50): needs the DB credentials + KEK;
 *   - `bot-core` (dsh container): needs only the shared HMAC secret.
 * Selection is by enrollment token → identity, and the LLM egress path is a separate
 * capability from secret read (see `CAP_LLM`).
 */

import { timingSafeEqual } from 'node:crypto';

export const CLIENTS = Object.freeze({
  'memory-service': {
    id: 'memory-service',
    // Refs this client may resolve. `mem-pg-*` are the DB credentials injected at
    // container start; the KEK stays here because only the service may decrypt.
    refs: ['mem-pg-rw-password', 'mem-pg-ro-password', 'mem-kek', 'mem-hmac-secret'],
    caps: ['secret-read', 'llm-egress'],
  },
  'bot-core': {
    id: 'bot-core',
    // Deliberately excludes mem-pg-* and mem-kek: acceptance #4 ("broker 阻断 agent
    // 读取 LLM key / PG 密码明文") is enforced here, not by obscurity.
    refs: ['mem-hmac-secret'],
    caps: ['secret-read', 'llm-egress'],
  },
  'ingress': {
    id: 'ingress',
    refs: ['mem-hmac-secret', 'ingress-tg-token'],
    caps: ['secret-read'],
  },
});

/** Refs that must never be resolvable by any client, as a belt-and-braces list. */
export const NEVER_RESOLVE = Object.freeze(['llm-api-key', 'dsh-master-key', 'ssh-key', 'docker-config']);

/** @returns {{ok: boolean, reason?: string, ref?: string}} */
export function authorize(clientId, ref) {
  const client = CLIENTS[clientId];
  if (!client) return { ok: false, reason: 'unknown-client' };
  if (NEVER_RESOLVE.includes(ref)) return { ok: false, reason: 'never-resolvable' };
  if (!client.refs.includes(ref)) return { ok: false, reason: 'ref-not-authorized', ref };
  return { ok: true, ref };
}

/** The refs a client may resolve — derived, never copied, so the server cannot drift
 * from this table (a duplicated allowlist is how an "extended" entry gets forgotten). */
export function refsFor(clientId) {
  const client = CLIENTS[clientId];
  return client ? [...client.refs] : [];
}

/** LLM proxy permission is a capability check, separate from ref read. */
export function canLlmEgress(clientId) {
  const client = CLIENTS[clientId];
  return Boolean(client && client.caps.includes('llm-egress'));
}

/**
 * Resolve a client id from its enrollment token. Tokens are opaque random strings
 * mounted into the broker as `/run/secrets/enroll-<id>`; the *file name* carries the
 * identity, so a leaked token for one client cannot be replayed as another without
 * also having written a file (which requires the host).
 *
 * @param {string} token
 * @param {{readToken:(name:string)=>string|null}} store
 */
export function identify(store, token) {
  if (typeof token !== 'string' || token.length === 0) return null;
  for (const client of Object.values(CLIENTS)) {
    const expected = store(`enroll-${client.id}`);
    if (expected && constantEqual(expected, token)) return client.id;
  }
  return null;
}

/** Length-safe constant-time compare; unequal lengths still return without leaking. */
export function constantEqual(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  // timingSafeEqual throws on unequal lengths, hence the guard above.
  return timingSafeEqual(ba, bb);
}
