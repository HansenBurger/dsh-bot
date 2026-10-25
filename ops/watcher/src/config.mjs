/**
 * config — environment parsing for the bypass watcher (t3 §3 `watcher:` block).
 *
 * Every knob has a default that matches the declared design contract, so the container
 * starts correctly with only the four environment variables compose already sets
 * (`TG_BOT_TOKEN`, `OWNER_CHAT_ID`, `ALIVE_HEARTBEAT_MIN`, plus the mounts). Nothing
 * here reads a credential from a literal: the alert token may arrive as a file path
 * (`*_REF` style) exactly like the rest of the stack (D1).
 */

import { readFileSync } from 'node:fs';

const INT = (v, d) => {
  const n = Number.parseInt(String(v ?? ''), 10);
  return Number.isFinite(n) && n > 0 ? n : d;
};
const FLOAT = (v, d) => {
  const n = Number(String(v ?? ''));
  return Number.isFinite(n) && n > 0 ? n : d;
};
const list = (v) => String(v ?? '')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

/**
 * Read a secret either from a mounted file (preferred) or a literal env value.
 * A missing file is *not* an error: an unconfigured alert channel is a normal state of
 * this deployment (TG is deferred per DEV-05), and the watcher must still circuit-break.
 */
function secret(env, name) {
  const ref = env[`${name}_REF`];
  if (ref) {
    try {
      return String(readFileSync(ref, 'utf8')).trim() || '';
    } catch {
      return '';
    }
  }
  return String(env[name] ?? '').trim();
}

/**
 * Target spec: `name=tcp://host:port[:required|optional]` or
 * `name=http://host:port/path[:required|optional]`. `optional` targets only alert;
 * `required` (the default) targets can trip the circuit-breaker.
 */
export function parseTargets(raw) {
  return list(raw)
    .map((entry) => {
      const eq = entry.indexOf('=');
      if (eq < 0) return null;
      const name = entry.slice(0, eq).trim();
      const rest = entry.slice(eq + 1).trim();
      // `name=tcp://host:port[:required|optional]` — the trailing `:flag` is split off
      // after URL parsing, because `tcp://` never carries one and http:// may carry a path.
      const flagMatch = /:(required|optional)$/.exec(rest);
      const spec = flagMatch ? rest.slice(0, -flagMatch[0].length) : rest;
      if (!/^(tcp|http|https):\/\//.test(spec) || !name) return null;
      let url;
      try {
        url = new URL(spec);
      } catch {
        return null;
      }
      const port = Number(url.port);
      if (!Number.isInteger(port) || port <= 0 || !url.hostname) return null;
      const path = `${url.pathname}${url.search}`.replace(/^$/, '');
      return {
        name,
        scheme: url.protocol.replace(':', ''),
        host: url.hostname,
        port,
        path: url.protocol === 'http:' || url.protocol === 'https:' ? path || '/' : '',
        required: flagMatch ? flagMatch[1] === 'required' : true,
      };
    })
    .filter(Boolean);
}

export function loadConfig(env = process.env) {
  const intervalS = FLOAT(env.WATCHER_INTERVAL_S, 10);
  const failThreshold = INT(env.WATCHER_FAIL_THRESHOLD, 3);
  const closeThreshold = INT(env.WATCHER_CLOSE_THRESHOLD, 3);

  const defaultTargets = [
    // 172.28.3.30 broker / 172.28.3.40 proxy / 172.28.3.50 memory are the net-ops members
    // (t3 §4). The *admin* healthz ports of every container are bound to 127.0.0.1 inside
    // that container (C1), so they are unreachable by design from here: a TCP connect to
    // the service port is the honest liveness signal, and memory's internal `/healthz`
    // answers 404 on purpose — any HTTP status at all proves the process is listening.
    'broker=tcp://172.28.3.30:8080:required',
    'memory=http://172.28.3.50:8091/healthz:required',
    'proxy=tcp://172.28.3.40:3128:optional',
  ].join(',');

  return {
    // loop
    intervalMs: intervalS * 1000,
    // E3: 连续失败达阈值 → 熔断。3 次 × 10s = 30s，落在 E6 的「1 min 内发现」预算内。
    failThreshold,
    closeThreshold,
    probeTimeoutMs: INT(env.WATCHER_PROBE_TIMEOUT_MS, 2000),
    targets: parseTargets(env.WATCHER_TARGETS || defaultTargets),

    // inputs
    logDir: env.WATCHER_LOG_DIR || '/var/log/dshbot',
    logFiles: list(env.WATCHER_LOG_FILES || 'ingress.jsonl,agent.jsonl,broker.jsonl,memory.jsonl'),
    cursorPath: env.WATCHER_CURSOR_PATH || `${env.WATCHER_STATE_DIR || '/state'}/watcher.cursor.json`,
    // F1/TM-014 信号 8: an audit file that stopped growing is itself a finding (P2 alert).
    staleLogMs: FLOAT(env.WATCHER_STALE_LOG_MIN, 60) * 60 * 1000,

    // outputs
    degradedFlagPath: env.DEGRADED_FLAG_PATH || '/state/degraded',
    stateDir: env.WATCHER_STATE_DIR || '/state',
    alertOutbox: env.WATCHER_ALERT_OUTBOX || `${env.WATCHER_STATE_DIR || '/state'}/alerts.jsonl`,
    heartbeatPath: env.WATCHER_HEARTBEAT_PATH || `${env.WATCHER_STATE_DIR || '/state'}/watcher.heartbeat`,
    statusPort: INT(env.WATCHER_ADMIN_PORT, 8186),
    statusBind: '127.0.0.1',

    // detection thresholds (E3's three named signals)
    credentialBurst: INT(env.WATCHER_CREDENTIAL_BURST, 5),
    credentialWindowMs: FLOAT(env.WATCHER_CREDENTIAL_WINDOW_S, 120) * 1000,
    // E3 第三信号「连续审批拒绝」: 主人连续拒掉 N 次待确认写入 → 降级只读，等人工介入。
    approvalDenyStreak: INT(env.WATCHER_APPROVAL_DENY_STREAK, 3),
    // 非白名单出站点的连续次数。第二次就熔断：第一次可能是配置错误，第二次是模式。
    egressDriftStreak: INT(env.WATCHER_EGRESS_DRIFT_STREAK, 2),
    // mirror of deploy/egress-proxy/rules.conf; kept in sync by ops/watcher/README.md
    egressAllowlist: list(env.WATCHER_EGRESS_ALLOWLIST || 'api.deepseek.com,api.telegram.org,github.com,registry.npmjs.org')
      .map((h) => h.toLowerCase()),

    // E3 security findings latch the breaker: an attacker must not be able to clear it by
    // simply stopping for one poll cycle. Availability findings are cleared by a real
    // recovery, not by this timer.
    breakerHoldMs: FLOAT(env.WATCHER_SECURITY_HOLD_MIN, 30) * 60 * 1000,

    // alerting (F2)
    alert: {
      dryRun: env.WATCHER_ALERT_DRY_RUN !== '0',
      // Where the structured queue files land. The gateway relay owns the other half of
      // this directory; empty string disables the delivery leg entirely.
      queueDir: String(env.WATCHER_ALERT_QUEUE_DIR ?? `${env.WATCHER_STATE_DIR || '/state'}/alerts`).trim(),
      cooldownMs: FLOAT(env.WATCHER_ALERT_COOLDOWN_S, 300) * 1000,
      tg: {
        botToken: secret(env, 'TG_BOT_TOKEN'),
        chatId: String(env.OWNER_CHAT_ID ?? env.TG_OWNER_CHAT_ID ?? '').trim(),
        host: env.WATCHER_TG_HOST || 'api.telegram.org',
        proxy: env.HTTPS_PROXY || env.https_proxy || '',
      },
      qq: {
        // The OB11-compatible HTTP endpoint (napcat `send_private_msg`). Nothing in the
        // current topology exposes one: see docs/validation/ops-watcher.md §5.
        url: String(env.WATCHER_QQ_ALERT_URL ?? '').trim(),
        token: secret(env, 'WATCHER_QQ_ALERT_TOKEN'),
        userId: String(env.WATCHER_QQ_ALERT_USER || '1035376945').trim(),
      },
    },
    // E7: 沉默即告警。ALIVE_HEARTBEAT_MIN is the declared design knob (compose:296).
    aliveHeartbeatMin: FLOAT(env.ALIVE_HEARTBEAT_MIN, 5),
    service: env.WATCHER_SERVICE_NAME || 'ops-watcher',
  };
}
