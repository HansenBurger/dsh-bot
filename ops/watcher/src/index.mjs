/**
 * index — ops/watcher process entry (t3 §3 L6 运维区, baseline E3/F2/E7, DEV-19).
 *
 * One loop, three inputs, two outputs:
 *
 *   inputs  : TCP/HTTP probes of the net-ops peers · the `bot.audit.v1` JSONL streams
 *             (read-only mount) · file-growth of those streams
 *   outputs : the `/state/degraded` kill flag (consumed by the gateway before the LLM,
 *             baseline E2) · the bypass alert ledger + whatever channel is wired (F2)
 *
 * Properties this file is responsible for:
 *   - **zero LLM tokens.** No broker URL, no provider key, no model name is ever read
 *     here; the container holds no credential mount at all (compose:297 only mounts logs
 *     and state). If this component can be reached by the agent plane, it is broken.
 *   - **fail-open on its own failure, fail-closed on the stack's.** A probe that errors
 *     out is a *finding*; a crash-looping watcher must not take the bot down, so nothing
 *     here writes a flag on its own behalf except from an actual rule.
 *   - **no new listener.** The status endpoint binds 127.0.0.1 inside the container for
 *     the Docker healthcheck only; the stack's published-port set is unchanged
 *     (assert-listeners must stay green — C1/C4).
 */

import { readFileSync, writeFileSync, renameSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createServer } from 'node:http';
import { loadConfig } from './config.mjs';
import { JsonlTailer } from './tail.mjs';
import { DetectionEngine } from './rules.mjs';
import { Breaker, MANAGED_BY } from './breaker.mjs';
import { AlertDispatcher } from './alert.mjs';
import { probeTarget, HealthState } from './probe.mjs';

const LOG = (o) => process.stderr.write(`${JSON.stringify({ ts: Date.now(), service: 'ops-watcher', ...o })}\n`);

export function createWatcher(opts = {}) {
  const config = opts.config ?? loadConfig(opts.env ?? process.env);
  const engine = new DetectionEngine(config);
  const breaker = new Breaker({ path: config.degradedFlagPath, holdMs: config.breakerHoldMs, log: LOG });
  const alerts = new AlertDispatcher({ outboxPath: config.alertOutbox, alert: config.alert, dryRun: config.alert.dryRun, log: LOG });
  const health = new HealthState({ failThreshold: config.failThreshold, closeThreshold: config.closeThreshold });
  const requiredNames = config.targets.filter((t) => t.required).map((t) => t.name);
  const cursor = readCursor(config.cursorPath);
  const logPaths = config.logFiles.map((f) => join(config.logDir, f));
  // Cold start (no cursor file at all): seek to end-of-file. Replaying yesterday's audit
  // history would fire every old finding at 03:00 and open the breaker for nothing.
  let bootstrapOffsets = cursor.offsets || null;
  if (!bootstrapOffsets) {
    bootstrapOffsets = {};
    for (const path of logPaths) {
      try {
        bootstrapOffsets[path] = statSync(path).size;
      } catch {
        /* stream not created yet */
      }
    }
  }
  const tailer = new JsonlTailer({ paths: logPaths, offsets: bootstrapOffsets });
  const growth = { ...(cursor.growth || {}) };
  const stalledReported = new Set();
  const state = { startedAt: Date.now(), ticks: 0, findings: 0, lastTickAt: 0, lastError: null };

  const saveCursor = () => {
    try {
      const tmp = `${config.cursorPath}.tmp-${process.pid}`;
      writeFileSync(tmp, JSON.stringify({ offsets: tailer.snapshot(), growth, managed_by: MANAGED_BY }, null, 2), 'utf8');
      renameSync(tmp, config.cursorPath);
    } catch (err) {
      state.lastError = `cursor: ${String(err.code || err.message).slice(0, 40)}`;
    }
  };

  const beat = (payload) => {
    // E7 needs a heartbeat that outlives this container: `state/watcher.heartbeat` is on
    // the host bind mount, so a stopped watcher is provable by mtime alone
    // (deploy/scripts/assert-watcher-alive.sh).
    try {
      writeFileSync(config.heartbeatPath, `${JSON.stringify({ ts: Date.now(), service: 'ops-watcher', ...payload })}\n`, 'utf8');
    } catch (err) {
      state.lastError = `heartbeat: ${String(err.code || err.message).slice(0, 40)}`;
    }
  };

  /** TM-014 信号 8: an audit stream that stopped growing *while its peers still move*.
   *  Reported once per stall episode; silence across every stream at once is an idle
   *  companion, not a stalled writer (see the divergence gate below). */
  const checkGrowth = (now) => {
    const findings = [];
    // Pass 1: refresh the growth table for every watched file first, so pass 2 judges
    // peer activity on same-tick data (file order must not decide who counts as active).
    const stalled = [];
    for (const file of config.logFiles) {
      const path = join(config.logDir, file);
      let st;
      try {
        st = statSync(path);
      } catch {
        continue; // a service that has never written a line has no growth expectation yet
      }
      const seen = growth[path] || { size: st.size, at: now, everGrew: false };
      if (st.size > seen.size) {
        growth[path] = { size: st.size, at: now, everGrew: true };
        stalledReported.delete(path);
        continue;
      }
      growth[path] = { ...seen, size: st.size };
      if (!seen.everGrew) continue; // boot-time baseline: only a stream that *was* growing is "stalled"
      stalled.push({ file, path, ageMs: now - seen.at });
    }
    // Pass 2: divergence gate — every audited stream here is *event-driven*, so a quiet
    // evening silences all of them together and must not alert. The stall signal only
    // means a broken writer when a peer stream moved within the staleness window. This
    // also breaks the self-feeding loop observed in production, where the alert-relay's
    // own ingress line reset the stall and re-armed it every idle hour.
    for (const { file, path, ageMs } of stalled) {
      const peerActive = Object.entries(growth).some(
        ([p, g]) => p !== path && g.everGrew && now - g.at < config.staleLogMs,
      );
      if (ageMs >= config.staleLogMs && peerActive && !stalledReported.has(path)) {
        stalledReported.add(path);
        findings.push(engine.streamStalled({ file, ageMs }));
      }
    }
    return findings;
  };

  const tickOnce = async (now = Date.now()) => {
    state.ticks += 1;
    state.lastTickAt = now;

    // 1. probes (E3 signal 4: 连续失败达阈值)
    const probed = await Promise.all(
      config.targets.map(async (target) => ({ target, result: await probeTarget(target, { timeoutMs: config.probeTimeoutMs }) })),
    );
    const probeFindings = [];
    for (const { target, result } of probed) {
      const st = health.record(target.name, result.ok, result.detail, now);
      if (!target.required) {
        if (st.tripped) probeFindings.push({ rule: 'E3-health-optional', severity: 'warn', degrade: false, alert: true, summary: `可选依赖 ${target.name} 连续 ${st.fails} 次探测失败：只告警`, evidence: { target: target.name, detail: result.detail } });
        continue;
      }
      if (st.tripped) {
        probeFindings.push({ ...engine.probeFailure({ name: target.name, detail: result.detail, fails: st.fails }), key: `E3-health-probe:${target.name}`, kind: 'availability' });
      } else if (st.recovered && target.required) {
        probeFindings.push({ ...engine.probeRecovery({ name: target.name, oks: st.oks }), key: `E3-health-probe:${target.name}`, kind: 'availability' });
      }
    }

    // 2. audit stream
    const records = tailer.read();
    const auditFindings = engine.feed(records, now);
    const findings = [...probeFindings, ...auditFindings];
    state.findings += findings.length;

    // 3. availability reasons must *clear* too, or the flag would never close again
    for (const name of requiredNames) {
      const st = health.targets.get(name);
      if (st && !st.tripped && st.fails === 0 && breaker.reasons.has(`E3-health-probe:${name}`)) {
        breaker.clearAvailability(`E3-health-probe:${name}`, now);
      }
    }

    // 4. breaker (E3)
    for (const finding of findings) if (finding.degrade) breaker.note({ ...finding, key: finding.key || `${finding.rule}:${finding.evidence?.target || ''}`, kind: finding.kind || 'security' }, now);
    const wasOpen = breaker.state().flagPresent;
    const transition = breaker.reconcile(now);
    const breakerState = breaker.state();

    // 5. alerts (F2)
    for (const finding of findings) {
      if (!finding.alert) continue;
      // Deliberately *not* forced: the breaker-open transition below is the message that
      // matters, and a standing outage must not re-ping the owner every tick (drill 2026-10-25
      // produced 8 alerts for one 60-second outage before this line was corrected).
      await alerts.dispatch(finding, breakerState, { key: finding.key });
    }
    if (transition.changed) {
      await alerts.dispatch(
        {
          rule: transition.opened ? 'E3-breaker-open' : 'E3-breaker-close',
          severity: transition.opened ? 'critical' : 'info',
          summary: transition.opened ? '自动熔断已置位：接入侧只回固定文案，不再进入模型' : '自动熔断已解除：接入侧恢复放行',
          evidence: { reasons: breakerState.reasons.map((r) => r.key).join(','), openedAt: breakerState.openedAt || '' },
        },
        breakerState,
        { force: true },
      );
      LOG({ type: 'config.change', event: transition.opened ? 'degraded-open' : 'degraded-close', reasons: breakerState.reasons.map((r) => r.key) });
    } else if (breakerState.foreignFlag && wasOpen && !state.foreignWarned) {
      state.foreignWarned = true;
      await alerts.dispatch({ rule: 'E2-foreign-flag', severity: 'warn', degrade: false, alert: true, summary: '熔断旗标由人工持有：watcher 不接管、不删除他人旗标', evidence: { path: config.degradedFlagPath } }, breakerState, { force: true });
    }

    // 6. log-growth (E7 / TM-014 信号 8)
    for (const finding of checkGrowth(now)) if (finding.alert) await alerts.dispatch(finding, breaker.state(), { key: finding.key });

    saveCursor();
    beat({ degraded: breakerState.flagPresent, reasons: breakerState.reasons.map((r) => r.key), ticks: state.ticks });
    return { findings, transition, breakerState };
  };

  const status = () => ({
    service: config.service,
    uptimeSeconds: Math.round((Date.now() - state.startedAt) / 1000),
    ticks: state.ticks,
    findings: state.findings,
    lastTickAt: state.lastTickAt,
    lastError: state.lastError,
    degraded: breaker.state().flagPresent,
    foreignFlag: breaker.state().foreignFlag,
    reasons: breaker.state().reasons,
    targets: health.stats(),
    required: requiredNames,
    detector: engine.stats(),
    alerts: { ...alerts.counters, ...alerts.channelStatus(), dryRun: config.alert.dryRun },
    mode: { intervalMs: config.intervalMs, failThreshold: config.failThreshold, closeThreshold: config.closeThreshold, holdMs: breaker.holdMs, staleLogMs: config.staleLogMs },
  });

  return { config, tickOnce, status, breaker, alerts, engine, health, saveCursor };
}

function readCursor(path) {
  try {
    if (!existsSync(path)) return {};
    const parsed = JSON.parse(readFileSync(path, 'utf8'));
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

/** Container-internal status endpoint for the Docker healthcheck. Loopback only (C1). */
export function startStatusServer(watcher, { port, host = '127.0.0.1' }) {
  const server = createServer((req, res) => {
    const path = new URL(req.url, 'http://watcher').pathname.replace(/\/+$/, '') || '/';
    if (path !== '/healthz') {
      res.writeHead(404, { 'content-type': 'application/json' });
      return res.end('{"code":"NOT_FOUND"}');
    }
    const st = watcher.status();
    const stale = st.lastTickAt && Date.now() - st.lastTickAt > st.mode.intervalMs * 6;
    res.writeHead(st.lastError || stale ? 503 : 200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ status: stale ? 'stale' : st.lastError ? 'degraded-self' : 'ok', ...st }));
  });
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

export async function main(env = process.env) {
  const watcher = createWatcher({ env });
  const { config } = watcher;
  LOG({ type: 'session.lifecycle', event: 'start', intervalMs: config.intervalMs, targets: config.targets.map((t) => `${t.name}:${t.host}:${t.port}`), required: config.targets.filter((t) => t.required).map((t) => t.name), flag: config.degradedFlagPath, alertMode: config.alert.dryRun ? 'dry-run' : 'live', channels: watcher.alerts.channelStatus().configured });
  const server = await startStatusServer(watcher, { port: config.statusPort, host: config.statusBind });

  let running = false;
  const loop = async () => {
    if (running) return; // a slow probe cycle must not overlap itself into a stampede
    running = true;
    try {
      await watcher.tickOnce();
    } catch (err) {
      // The watchdog survives its own bugs; a lost tick is reported, never retried loudly.
      LOG({ type: 'sandbox.denied', event: 'tick-error', detail: String(err.message || err).slice(0, 120) });
    } finally {
      running = false;
    }
  };

  await loop();
  const timer = setInterval(loop, config.intervalMs);
  const stop = (signal) => {
    LOG({ type: 'session.lifecycle', event: 'shutdown', signal });
    clearInterval(timer);
    server.close();
    process.exit(0);
  };
  process.on('SIGTERM', () => stop('SIGTERM'));
  process.on('SIGINT', () => stop('SIGINT'));
  return { watcher, timer, server };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    process.stdout.write(`ops/watcher: FATAL ${String(err.message).slice(0, 200)}\n`);
    process.exitCode = 1;
  });
}
