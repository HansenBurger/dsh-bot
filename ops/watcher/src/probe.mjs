/**
 * probe — liveness probes that produce **no audit side effects**.
 *
 * Why TCP-connect for most targets: every container in this stack binds its real
 * health endpoint (`/healthz`) to `127.0.0.1` *inside itself* (C1 — no cross-container
 * admin surface), so from net-ops there is nothing to HTTP-poll. An HTTP request against
 * a service port would be worse than useless: on the broker it appends a
 * `credential.resolve result=denied reason=no-token` line to the audit stream, which is
 * exactly the event class this watcher treats as a credential-path attack (E3 signal 1).
 * A watchdog that tripped its own detector would be a self-inflicted outage generator.
 *
 * `http` mode is allowed for endpoints that answer without authentication side effects
 * (memory's internal server answers `/healthz` with 404 and emits nothing); **any** HTTP
 * status counts as alive, because "answered" is the property under test.
 */

import net from 'node:net';
import http from 'node:http';

export function tcpProbe({ host, port, timeoutMs }) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = net.connect({ host, port, timeout: timeoutMs });
    const done = (ok, detail) => {
      socket.destroy();
      resolve({ ok, ms: Date.now() - started, detail });
    };
    socket.once('connect', () => done(true, 'connected'));
    socket.once('timeout', () => done(false, 'timeout'));
    socket.once('error', (err) => done(false, String(err.code || err.message).slice(0, 40)));
  });
}

export function httpProbe({ host, port, path = '/', timeoutMs, scheme = 'http' }) {
  return new Promise((resolve) => {
    const started = Date.now();
    const req = http.get(
      { host, port, path, timeout: timeoutMs, agent: false, headers: { host: `${host}:${port}` } },
      (res) => {
        res.resume();
        // 4xx/5xx is still "a process answered on this port"; that is the claim we test.
        resolve({ ok: true, ms: Date.now() - started, detail: `http ${res.statusCode}` });
      },
    );
    req.once('timeout', () => {
      req.destroy(new Error('timeout'));
    });
    req.once('error', (err) => resolve({ ok: false, ms: Date.now() - started, detail: String(err.code || err.message).slice(0, 40) }));
  });
}

/** Dispatch on the target scheme; `https` is probed at the TCP layer (TLS handshake is out of scope). */
export function probeTarget(target, { timeoutMs }) {
  if (target.scheme === 'http') return httpProbe({ ...target, timeoutMs });
  return tcpProbe({ host: target.host, port: target.port, timeoutMs });
}

/**
 * Consecutive-failure state machine (E3: 「连续失败达阈值」).
 * Opening needs `failThreshold` failures; closing needs `closeThreshold` successes, so a
 * single flaky tick neither arms nor disarms the breaker.
 */
export class HealthState {
  constructor({ failThreshold, closeThreshold }) {
    this.failThreshold = failThreshold;
    this.closeThreshold = closeThreshold;
    /** @type {Map<string, {ok:boolean, fails:number, oks:number, since:number, detail:string}>} */
    this.targets = new Map();
  }

  record(name, ok, detail, now = Date.now()) {
    // Alert hygiene: a fresh watchdog must not announce "recovered" for a dependency that
    // was never down — boot-time chatter is how an alert channel gets muted by its owner.
    const prev = this.targets.get(name) || { ok: true, fails: 0, oks: 0, since: now, detail: '', tripped: false };
    const next = ok
      ? { ok: !prev.tripped, fails: 0, oks: prev.tripped ? prev.oks + 1 : 0, since: prev.ok ? prev.since : now, detail, tripped: prev.tripped && prev.oks + 1 < this.closeThreshold }
      : { ok: false, fails: prev.fails + 1, oks: 0, since: prev.tripped ? prev.since : now, detail, tripped: prev.fails + 1 >= this.failThreshold };
    this.targets.set(name, next);
    return { ...next, tripped: !ok && next.fails >= this.failThreshold, recovered: ok && prev.tripped && next.tripped === false };
  }

  /** Names of required targets that have crossed the failure threshold. */
  failed(requiredNames) {
    return [...this.targets.entries()]
      .filter(([name, st]) => requiredNames.includes(name) && st.fails >= this.failThreshold)
      .map(([name, st]) => ({ name, detail: st.detail, fails: st.fails, since: st.since }));
  }

  allHealthy(requiredNames) {
    return requiredNames.every((name) => {
      const st = this.targets.get(name);
      return st ? st.fails < this.failThreshold : false;
    });
  }

  stats() {
    return Object.fromEntries([...this.targets.entries()].map(([k, v]) => [k, { ok: v.ok, fails: v.fails, oks: v.oks, detail: v.detail }]));
  }
}
