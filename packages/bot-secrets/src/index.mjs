/**
 * bot-secrets — opaque-ref resolution for containers that must never carry a
 * plaintext credential in their environment (t4 §9.4, D1).
 *
 * The environment holds only a reference:
 *
 *   MEM_PG_RW_PASSWORD_REF=opaque-ref:mem-pg-rw-password   (memory-service)
 *   INGRESS_TG_TOKEN_REF=opaque-ref:ingress-tg-token       (gateway)
 *
 * Resolution order, both paths fail-closed:
 *
 *   1. **Secret broker** (`BROKER_URL`): `GET /v1/secret/:ref`, authenticated either
 *      by this service's bot-HMAC principal (when the caller already holds the
 *      signing secret) or by a *bootstrap enrollment token* read from a file
 *      (`/run/secrets/<BROKER_ENROLLMENT_FILE>`). The file is what breaks the
 *      chicken-and-egg: the broker cannot be the source of the credential required to
 *      authenticate to the broker.
 *   2. **Mounted secret file** (`/run/secrets/<ref>`): the fallback when the broker is
 *      down and the path used by tests. Read-only tmpfs mount in compose.
 *
 * Guarantees:
 *   - a resolved value is returned to the caller and never written back into
 *     `process.env`, so `docker exec <c> env` yields refs only;
 *   - values are never logged: the record carries `{ref, source, result, length}`;
 *   - an unresolvable ref throws instead of degrading to an empty string — an empty
 *     password against a shared host PG surfaces as a confusing auth bug (D2);
 *   - a literal value is accepted only when the caller does not forbid it
 *     (`literalAllowed: false` in production) and is always reported.
 */

import { readFileSync, existsSync } from 'node:fs';
import { sign, encodePrincipal } from '@dsh-bot/bot-hmac';

export const OPAQUE_PREFIX = 'opaque-ref:';

/** @param {string|undefined} value @returns {string|null} the bare ref, or null when it is not a ref */
export function refOf(value) {
  if (typeof value !== 'string') return null;
  // Leading/trailing whitespace is an env-file artifact, not part of the scheme.
  const text = value.trim();
  if (!text.startsWith(OPAQUE_PREFIX)) return null;
  const ref = text.slice(OPAQUE_PREFIX.length).trim();
  return ref.length > 0 ? ref : null;
}

export class SecretResolver {
  /**
   * @param {{brokerUrl?: string, secretsDir?: string, enrollmentFile?: string, hmacSecret?: string,
   *          principal?: object, audit?: {emit:(type:string,fields:object)=>void},
   *          fetchImpl?: Function, timeoutMs?: number}} [opts]
   */
  constructor(opts = {}) {
    this.brokerUrl = opts.brokerUrl || process.env.BROKER_URL || '';
    this.secretsDir = opts.secretsDir || process.env.SECRETS_DIR || '/run/secrets';
    this.enrollmentFile = opts.enrollmentFile || process.env.BROKER_ENROLLMENT_FILE || 'enrollment-token';
    this.hmacSecret = opts.hmacSecret || '';
    this.principal = opts.principal || null;
    this.audit = opts.audit || null;
    this.fetch = opts.fetchImpl || globalThis.fetch;
    this.timeoutMs = opts.timeoutMs ?? 4000;
    this.cache = new Map();
    this.stats = { broker: 0, file: 0, literal: 0, failed: 0 };
  }

  /**
   * @param {string|undefined} value - `opaque-ref:<name>` (or a literal, if allowed)
   * @param {{label?: string, literalAllowed?: boolean}} [opts]
   * @returns {Promise<string|null>} null when nothing was configured for this field
   */
  async resolve(value, opts = {}) {
    const label = opts.label || 'secret';
    const ref = refOf(value);

    if (ref === null) {
      if (typeof value === 'string' && value.length > 0) {
        if (opts.literalAllowed === false) {
          this.stats.failed += 1;
          throw new Error(`${label}: literal value is not allowed here, expected ${OPAQUE_PREFIX}<name>`);
        }
        this.stats.literal += 1;
        this.#log('literal', null, value.length, 'warn');
        return value;
      }
      return null;
    }
    if (this.cache.has(ref)) return this.cache.get(ref);

    const fromBroker = await this.#viaBroker(ref);
    const resolved = fromBroker ?? this.#viaFile(ref);
    if (resolved === null) {
      this.stats.failed += 1;
      throw new Error(`${label}: cannot resolve ${ref} (broker "${this.brokerUrl || '(unset)'}" and ${this.secretsDir}/${ref} both unavailable)`);
    }
    this.cache.set(ref, resolved);
    return resolved;
  }

  #enrollmentToken() {
    const file = `${this.secretsDir}/${this.enrollmentFile}`;
    if (!existsSync(file)) return null;
    try {
      const text = readFileSync(file, 'utf8').trim();
      return text.length > 0 ? text : null;
    } catch {
      return null;
    }
  }

  async #viaBroker(ref) {
    if (!this.brokerUrl || !this.fetch) return null;
    const path = `/v1/secret/${encodeURIComponent(ref)}`;
    const headers = { accept: 'text/plain' };
    if (this.hmacSecret && this.principal) {
      const encoded = encodePrincipal(this.principal);
      headers['x-bot-principal'] = encoded;
      headers['x-bot-sig'] = sign(this.hmacSecret, { method: 'GET', path, body: undefined, principal: encoded });
    } else {
      const token = this.#enrollmentToken();
      if (!token) {
        this.#log('no-enrollment-token', ref, 0, 'warn');
        return null;
      }
      headers['x-broker-token'] = token;
    }
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      const res = await this.fetch(`${this.brokerUrl.replace(/\/+$/, '')}${path}`, { headers, signal: controller.signal });
      clearTimeout(timer);
      if (!res.ok) {
        this.#log('broker-error', ref, 0, 'warn', { status: res.status });
        return null;
      }
      const text = (await res.text()).replace(/\n+$/, '');
      if (text.length === 0) return null;
      this.stats.broker += 1;
      this.#log('broker', ref, text.length, 'info');
      return text;
    } catch (err) {
      this.#log('broker-unreachable', ref, 0, 'warn', { error: String(err?.name || err?.message || 'error').slice(0, 60) });
      return null;
    }
  }

  #viaFile(ref) {
    // Refs come from configuration, not the network — but a `../` here would still
    // read an arbitrary host file, so the charset is checked before touching disk.
    if (!/^[A-Za-z0-9._-]+$/.test(ref)) return null;
    const file = `${this.secretsDir}/${ref}`;
    if (!existsSync(file)) return null;
    try {
      const text = readFileSync(file, 'utf8').replace(/\n+$/, '');
      if (text.length === 0) return null;
      this.stats.file += 1;
      this.#log('file', ref, text.length, 'info');
      return text;
    } catch {
      return null;
    }
  }

  #log(source, ref, length, level, extra = {}) {
    const record = {
      ts: Date.now(),
      type: 'credential.resolve',
      result: level === 'warn' ? 'error' : 'allowed',
      source,
      // The ref name is safe to log; the value never is (D5).
      ref: ref ?? '(literal)',
      length,
      ...extra,
    };
    if (this.audit?.emit) this.audit.emit('credential.resolve', { source, ref: record.ref, result: record.result, ...extra });
    else process.stderr.write(`${JSON.stringify(record)}\n`);
  }
}
