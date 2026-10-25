/**
 * breaker — the producer side of E3 (writes the `/state/degraded` kill flag).
 *
 * The consumer already exists and is correct (baseline E2): `apps/gateway/src/index.mjs`
 * reads `DEGRADED_FLAG_PATH` before the whitelist gate and answers a fixed line without
 * touching the LLM, and treats an *unreadable* flag as degraded (fail-closed). All that
 * was missing was somebody opening and closing it — which is precisely DEV-19.
 *
 * Ownership matters. An operator may `touch state/degraded` by hand, and a watchdog that
 * deletes a flag it did not create turns an intentional halt into an automatic resume.
 * So the watcher stamps its own flag with `managed_by` and only ever unlinks a file that
 * carries its stamp.
 *
 * Latching: a security finding (`degrade: true`) holds the flag for `holdMs` from its
 * last sighting — an attacker cannot simply stop probing for 30 seconds to get the
 * breaker to reset. An availability finding holds while the condition is true and clears
 * on the recovery event.
 */

import { writeFileSync, renameSync, unlinkSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export const MANAGED_BY = 'ops/watcher';

export class Breaker {
  /**
   * @param {{path:string, holdMs?:number, log?:(o:object)=>void}} opts
   */
  constructor(opts) {
    this.path = opts.path;
    this.holdMs = opts.holdMs ?? 30 * 60 * 1000;
    this.log = opts.log || (() => {});
    /** @type {Map<string, {kind:'security'|'availability', summary:string, evidence:object, firstSeen:number, lastSeen:number}>} */
    this.reasons = new Map();
    this.openedAt = null;
    this.lastError = null;
    try {
      mkdirSync(dirname(this.path), { recursive: true });
    } catch {
      /* the mount may be read-only at boot; the write attempt below reports it */
    }
  }

  /**
   * @param {{degrade:boolean, key?:string, kind?:'security'|'availability', summary:string, evidence?:object}} finding
   * @param {number} now
   */
  note(finding, now = Date.now()) {
    if (!finding.degrade) return;
    const key = finding.key || finding.rule;
    const prev = this.reasons.get(key);
    this.reasons.set(key, {
      kind: finding.kind || 'security',
      summary: finding.summary,
      evidence: finding.evidence || {},
      firstSeen: prev ? prev.firstSeen : now,
      lastSeen: now,
    });
  }

  /** Drop an availability reason once the condition has actually recovered. */
  clearAvailability(key, now = Date.now()) {
    const entry = this.reasons.get(key);
    if (entry && entry.kind === 'availability') {
      this.reasons.delete(key);
      return true;
    }
    return false;
  }

  /** Expire latched security reasons; returns true if any reason is still holding. */
  activeCount(now = Date.now()) {
    for (const [key, entry] of [...this.reasons.entries()]) {
      if (entry.kind === 'security' && now - entry.lastSeen > this.holdMs) this.reasons.delete(key);
    }
    return this.reasons.size;
  }

  /** @returns {string|null|{unreadable:boolean}} null = absent, '' = a bare `touch`. */
  readFlag() {
    try {
      if (!existsSync(this.path)) return null;
      return readFileSync(this.path, 'utf8');
    } catch (err) {
      // Unreadable but present: the gateway already treats this as degraded. Say so, and
      // never try to delete what we cannot read.
      this.lastError = `flag-unreadable: ${String(err.code || err.message).slice(0, 40)}`;
      return { unreadable: true };
    }
  }

  /** True when a flag exists that this watcher did not write. */
  foreignFlagPresent() {
    const raw = this.readFlag();
    if (raw === null || raw.unreadable) return false;
    if (!String(raw).trim()) return true; // a manual `touch state/degraded` leaves an empty file
    try {
      const parsed = JSON.parse(raw);
      return parsed.managed_by !== MANAGED_BY;
    } catch {
      return true; // not our JSON ⇒ not our flag
    }
  }

  /** @returns {{changed:boolean, opened:boolean, detail?:string}} */
  reconcile(now = Date.now()) {
    const holding = this.activeCount(now) > 0;
    const exists = existsSync(this.path);
    const foreign = exists && this.foreignFlagPresent();

    if (holding && !foreign && !exists) {
      const detail = { managed_by: MANAGED_BY, opened_at: new Date(now).toISOString(), reasons: [...this.reasons.entries()].map(([key, v]) => ({ key, kind: v.kind, summary: v.summary, evidence: v.evidence })) };
      try {
        const tmp = `${this.path}.tmp-${process.pid}`;
        writeFileSync(tmp, `${JSON.stringify(detail, null, 2)}\n`, 'utf8');
        renameSync(tmp, this.path); // atomic: the gateway must never observe an empty-but-present flag mid-write
        this.openedAt = now;
        this.lastError = null;
        return { changed: true, opened: true };
      } catch (err) {
        this.lastError = `flag-write-failed: ${String(err.code || err.message).slice(0, 40)}`;
        this.log({ type: 'sandbox.denied', event: 'degraded-flag-write', detail: this.lastError });
        return { changed: false, opened: false, detail: this.lastError };
      }
    }

    if (!holding && exists && !foreign) {
      try {
        unlinkSync(this.path);
        this.openedAt = null;
        this.lastError = null;
        return { changed: true, opened: false };
      } catch (err) {
        this.lastError = `flag-unlink-failed: ${String(err.code || err.message).slice(0, 40)}`;
        this.log({ type: 'sandbox.denied', event: 'degraded-flag-unlink', detail: this.lastError });
        return { changed: false, opened: false, detail: this.lastError };
      }
    }

    if (holding && exists && !foreign && this.openedAt) {
      // Refresh the reason list without flipping the state, so an operator reading the
      // flag sees *why* it is open right now, not only why it opened.
      try {
        const current = JSON.parse(readFileSync(this.path, 'utf8'));
        if (current.managed_by === MANAGED_BY) {
          current.reasons = [...this.reasons.entries()].map(([key, v]) => ({ key, kind: v.kind, summary: v.summary, evidence: v.evidence }));
          const tmp = `${this.path}.tmp-${process.pid}`;
          writeFileSync(tmp, `${JSON.stringify(current, null, 2)}\n`, 'utf8');
          renameSync(tmp, this.path);
        }
      } catch {
        /* refresh is best-effort; the flag itself is already in force */
      }
    }

    return { changed: false, opened: holding && !foreign };
  }

  state() {
    return {
      flagPath: this.path,
      flagPresent: existsSync(this.path),
      foreignFlag: this.foreignFlagPresent(),
      reasons: [...this.reasons.entries()].map(([key, v]) => ({ key, kind: v.kind, summary: v.summary, lastSeen: v.lastSeen })),
      openedAt: this.openedAt,
      lastError: this.lastError,
    };
  }
}
