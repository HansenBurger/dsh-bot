/**
 * net-probe — T9-F4: the connection layer must fail fast when a dependency is gone.
 *
 * What the t9 fault matrix measured: when the memory/broker container is stopped, its
 * bridge IP answers nothing (no RST — the veth is simply gone), so a plain `fetch` hangs
 * in TCP connect for 8-20s and only then trips its overall timeout. With
 * `MAX_CONCURRENT_RUNS=2` (E1) that means **two stuck requests saturate the intake**:
 * every later message bounces off 429 AGENT_BUSY while the owner sees a silent bot for
 * tens of seconds. A single-leg outage reads as "the whole companion is dead".
 *
 * The fix cannot be a short overall timeout — a real model round legitimately takes
 * seconds (t9: p50 2216ms, max 5064ms) — it has to be a short **connect** timeout, the
 * phase that is either ~instant (container up) or hopeless (container down). Node's
 * fetch gives no per-phase control without pulling a dependency, so we do the stdlib
 * thing: probe the TCP endpoint with `node:net` for `timeoutMs` (1.5s default, task
 * guidance says 1-2s) before spending the request. Unreachable ⇒ fail-closed *now*, on
 * the existing audit-visible error paths; reachable ⇒ carry on with the normal, longer
 * end-to-end budget.
 *
 * Known limit, stated honestly: probe-pass-then-die is still bounded by the overall
 * timeout, and probe costs one extra localhost TCP handshake (sub-millisecond).
 */

import { connect } from 'node:net';

/** 1.5s: under the 2s upper bound of the task guidance, above any LAN handshake. */
export const DEFAULT_CONNECT_PROBE_MS = 1500;

/** `{host, port}` of a base URL, with the scheme's default port when none is written. */
export function probeTarget(baseUrl) {
  const u = new URL(String(baseUrl));
  const defaultPort = u.protocol === 'https:' ? 443 : 80;
  return { host: u.hostname, port: Number(u.port || defaultPort) };
}

/**
 * Resolve once the TCP connection is established; reject on connect error or after
 * `timeoutMs` with a `CONNECT_PROBE_TIMEOUT` code. `connectImpl` is injectable so the
 * hang case (no answer at all) is testable without blackholing a real socket.
 */
export function tcpConnectProbe({ host, port, timeoutMs = DEFAULT_CONNECT_PROBE_MS, connectImpl = connect }) {
  return new Promise((resolve, reject) => {
    const socket = connectImpl({ host, port });
    let settled = false;
    const finish = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket?.destroy?.();
      } catch {
        /* already dead */
      }
      if (err) reject(err);
      else resolve(true);
    };
    const timer = setTimeout(() => finish(Object.assign(new Error(`tcp connect to ${host}:${port} timed out after ${timeoutMs}ms`), { code: 'CONNECT_PROBE_TIMEOUT' })), timeoutMs);
    socket?.once?.('connect', () => finish(null));
    socket?.once?.('error', (err) => finish(err));
  });
}

/**
 * The gate a client calls before its fetch: probe the base URL, and on failure throw an
 * error carrying a machine-readable `reason` for the audit line. Rejections propagate
 * `{ fast: true }` so callers keep their existing fail-closed text for the owner.
 */
export async function assertDependencyReachable({ baseUrl, timeoutMs = DEFAULT_CONNECT_PROBE_MS, probe = tcpConnectProbe, connectImpl }) {
  const { host, port } = probeTarget(baseUrl);
  try {
    await probe({ host, port, timeoutMs, ...(connectImpl ? { connectImpl } : {}) });
    return { host, port, probed: true };
  } catch (err) {
    throw Object.assign(new Error(`dependency unreachable: ${host}:${port} (${String(err.code || err.message).slice(0, 80)})`), {
      fast: true,
      probeCode: String(err.code || err.message).slice(0, 80),
      host,
      port,
    });
  }
}
