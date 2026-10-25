/**
 * alert-relay — the F2 delivery leg (DEV-19, captain ruling 2026-10-25 18:47).
 *
 * The watcher decides that something is wrong; only this process can put text into the
 * owner's QQ, because it owns the reverse-WS adapter socket (`send_private_msg`). That
 * makes the relay the one component the alert path *must* pass through, and therefore the
 * one place the four constraints have to be enforced:
 *
 *   1. **fixed template.** The outbound text is assembled here from validated structured
 *      fields. Free text from the queue file is never copied into the message, so a
 *      compromised watcher cannot use this leg to phrase anything to the owner — it can
 *      only pick from an enumerated set of alert types. Unknown type ⇒ dropped + audited.
 *   2. **rate limits.** Per alert type a minimum interval (default 5 min), and a backlog
 *      cap: past `maxQueue` the oldest entries are dropped (to `dropped/`, never deleted,
 *      because a discarded alert is still evidence) and counted in the audit.
 *   3. **minimal mount.** This side gets one rw sub-directory (`state/alerts`); the halt
 *      flag mount stays read-only, and no network or port changes.
 *   4. **fail-closed on itself.** If the adapter is not connected the file stays pending —
 *      the relay never drops a message just because delivery is currently impossible, and
 *      it never blocks the message pipeline: this runs on its own timer.
 *
 * F2's acceptance action ("下达『不要通知主人』→ 告警仍送达") holds because nothing here
 * consults the agent plane: no model, no session, no tool gate, no conversational input.
 */

import { readdirSync, readFileSync, writeFileSync, renameSync, mkdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/** The only alert subjects this leg is allowed to speak about. */
export const ALERT_TYPES = Object.freeze([
  'breaker-open',
  'breaker-close',
  'health-probe',
  'egress-drift',
  'credential-probe',
  'approval-denials',
  'protocol-down',
  'protocol-restore',
  'audit-silence',
]);

const SAFE_FIELD = /^[A-Za-z0-9._:@/+-]{1,48}$/;
const clean = (v) => (typeof v === 'string' || typeof v === 'number' ? (SAFE_FIELD.test(String(v)) ? String(v) : null) : null);

/** Fixed shape: `[watcher 告警] <type> · <service> · <state> · <utc> [· <target>]`. */
export function renderRelayText(record) {
  const type = clean(record.type);
  if (!type || !ALERT_TYPES.includes(type)) return null;
  const service = clean(record.service) || 'ops-watchdog';
  const state = clean(record.state) || 'unknown';
  const at = clean(record.at) || new Date(Number(record.ts) || Date.now()).toISOString();
  const target = clean(record.target);
  return `[watcher 告警] ${type} · ${service} · ${state} · ${at}${target ? ` · ${target}` : ''}`.slice(0, 280);
}

export class AlertRelay {
  /**
   * @param {{dir:string, ownerUserId:string|number, send:(text:string)=>Promise<any>,
   *          audit?:{emit:(t:string,f:object)=>void}, intervalMs?:number, cooldownMs?:number,
   *          maxQueue?:number, maxAttempts?:number, now?:()=>number, log?:(o:object)=>void}} opts
   */
  constructor(opts) {
    if (!opts.dir) throw new Error('AlertRelay requires dir');
    if (typeof opts.send !== 'function') throw new Error('AlertRelay requires a send function');
    this.dir = opts.dir;
    this.pendingDir = join(this.dir, 'pending');
    this.sentDir = join(this.dir, 'sent');
    this.droppedDir = join(this.dir, 'dropped');
    this.ownerUserId = opts.ownerUserId;
    this.send = opts.send;
    this.audit = opts.audit;
    this.intervalMs = opts.intervalMs ?? 10_000;
    this.cooldownMs = opts.cooldownMs ?? 300_000;
    this.maxQueue = opts.maxQueue ?? 20;
    this.maxAttempts = opts.maxAttempts ?? 5;
    this.now = opts.now ?? (() => Date.now());
    this.log = opts.log || (() => {});
    this.lastSentType = new Map();
    this.stats = { delivered: 0, dropped: 0, retried: 0, invalid: 0 };
    this.timer = null;
  }

  start() {
    for (const d of [this.pendingDir, this.sentDir, this.droppedDir]) {
      try {
        mkdirSync(d, { recursive: true });
      } catch (err) {
        this.log({ type: 'sandbox.denied', stage: 'alert-relay', event: 'mkdir', detail: String(err.code || err.message).slice(0, 40) });
      }
    }
    this.timer = setInterval(() => void this.drain().catch(() => {}), this.intervalMs);
    this.timer.unref?.(); // the relay must not be the reason a process stays alive
    void this.drain().catch(() => {});
    return this;
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  #list() {
    let names;
    try {
      names = readdirSync(this.pendingDir);
    } catch {
      return [];
    }
    const entries = [];
    for (const name of names.filter((n) => n.endsWith('.json'))) {
      let mtime = 0;
      try {
        mtime = statSync(join(this.pendingDir, name)).mtimeMs;
      } catch {
        continue;
      }
      entries.push({ name, mtime });
    }
    // oldest first: an alert that has been waiting longest is the most relevant
    return entries.sort((a, b) => a.mtime - b.mtime);
  }

  /** One pass over the queue. Returns the per-file outcomes for tests and the healthz view. */
  async drain() {
    const results = [];
    let queue = this.#list();

    // constraint 2: backlog cap. Drop the oldest beyond the limit, loudly, and keep the file.
    if (queue.length > this.maxQueue) {
      const overflow = queue.slice(0, queue.length - this.maxQueue);
      for (const entry of overflow) {
        this.#move(this.droppedDir, entry.name, { dropped_at: new Date(this.now()).toISOString(), reason: 'backlog-cap' });
        this.stats.dropped += 1;
        this.audit?.emit('authz.decision', { stage: 'alert-relay', result: 'denied', reason: 'backlog-cap', alert: entry.name });
        results.push({ name: entry.name, action: 'dropped' });
      }
      queue = queue.slice(queue.length - this.maxQueue);
    }

    for (const entry of queue) {
      const path = join(this.pendingDir, entry.name);
      let record;
      try {
        record = JSON.parse(readFileSync(path, 'utf8'));
      } catch (err) {
        // Unreadable or unparsable: quarantine rather than retry forever.
        this.stats.invalid += 1;
        this.#move(this.droppedDir, entry.name, { dropped_at: new Date(this.now()).toISOString(), reason: `unparsable:${String(err.code || 'parse').slice(0, 20)}` });
        this.audit?.emit('authz.decision', { stage: 'alert-relay', result: 'denied', reason: 'unparsable', alert: entry.name });
        results.push({ name: entry.name, action: 'dropped' });
        continue;
      }

      const text = renderRelayText(record);
      if (!text) {
        // constraint 1: an unknown subject is dropped, never phrased into a message.
        this.stats.invalid += 1;
        this.#move(this.droppedDir, entry.name, { dropped_at: new Date(this.now()).toISOString(), reason: 'unknown-alert-type' });
        this.audit?.emit('authz.decision', { stage: 'alert-relay', result: 'denied', reason: 'unknown-alert-type', observed: clean(record.type) || 'malformed' });
        this.log({ type: 'authz.decision', stage: 'alert-relay', result: 'denied', reason: 'unknown-alert-type' });
        results.push({ name: entry.name, action: 'dropped' });
        continue;
      }

      const last = this.lastSentType.get(record.type) || 0;
      if (this.now() - last < this.cooldownMs) {
        results.push({ name: entry.name, action: 'deferred', reason: 'cooldown' });
        continue; // stays pending; the next pass retries after the cooldown
      }

      let outcome;
      try {
        outcome = await this.send(text);
      } catch (err) {
        outcome = { ok: false, error: String(err.message || err).slice(0, 60) };
      }
      if (outcome && outcome.ok) {
        this.lastSentType.set(record.type, this.now());
        this.stats.delivered += 1;
        this.#move(this.sentDir, entry.name, { delivered_at: new Date(this.now()).toISOString(), text_hash: hashLine(text) }, record);
        this.audit?.emit('session.lifecycle', { stage: 'alert-relay', result: 'allowed', event: 'delivered', alertType: record.type, owner: clean(this.ownerUserId) || 'unset' });
        results.push({ name: entry.name, action: 'delivered' });
      } else {
        // constraint 4: keep it, count the attempts, and give up only after maxAttempts.
        const attempts = Number(record.relay_attempts || 0) + 1;
        this.stats.retried += 1;
        if (attempts >= this.maxAttempts) {
          this.#move(this.droppedDir, entry.name, { dropped_at: new Date(this.now()).toISOString(), reason: 'delivery-exhausted', attempts });
          this.audit?.emit('authz.decision', { stage: 'alert-relay', result: 'denied', reason: 'delivery-exhausted', alertType: record.type, attempts });
          results.push({ name: entry.name, action: 'dropped' });
        } else {
          try {
            writeFileSync(path, JSON.stringify({ ...record, relay_attempts: attempts }, null, 2), 'utf8');
          } catch {
            /* the next pass re-reads whatever is there */
          }
          this.audit?.emit('authz.decision', { stage: 'alert-relay', result: 'denied', reason: 'adapter-unavailable', alertType: record.type, attempts, detail: String(outcome?.error || outcome?.reason || '').slice(0, 60) });
          results.push({ name: entry.name, action: 'retry' });
        }
      }
    }
    return results;
  }

  /**
   * Consume one queue entry: the file *moves* (never deleted — a discarded alert is still
   * evidence, and the moved twin is what proves delivery happened), and the relay's own
   * receipt is merged into it so one file holds both halves.
   */
  #move(toDir, name, meta, original) {
    try {
      mkdirSync(toDir, { recursive: true });
      const from = join(this.pendingDir, name);
      renameSync(from, join(toDir, name));
      const body = `${JSON.stringify({ ...(original || {}), source: name, ...meta }, null, 2)}\n`;
      writeFileSync(join(toDir, name), body, 'utf8');
    } catch (err) {
      this.log({ type: 'sandbox.denied', stage: 'alert-relay', event: 'move', detail: String(err.code || err.message).slice(0, 40) });
    }
  }

  state() {
    return { dir: this.dir, owner: clean(this.ownerUserId) || null, ...this.stats, queued: this.#list().length };
  }
}

function hashLine(text) {
  // A short non-reversible fingerprint: enough to prove *which* text was sent later,
  // and no way to read it back out of the queue (D5).
  let h = 5381;
  for (let i = 0; i < text.length; i += 1) h = ((h << 5) + h + text.charCodeAt(i)) >>> 0;
  return `djb32:${h.toString(16)}`;
}
