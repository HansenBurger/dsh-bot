/**
 * alert — the F2 bypass alert channel (「告警由旁路 watcher 发出，不经 agent、不经 LLM」).
 *
 * The design put Telegram first: `watcher.environment.TG_BOT_TOKEN` + `OWNER_CHAT_ID`
 * with a dedicated alert bot, deliberately separated from the main bot to shrink the
 * blast radius (t3 §6, D8). That channel cannot be exercised on this host today — the
 * TG leg is deferred (DEV-05), the watcher container is on `net-ops` with no route to
 * the QQ protocol side, and the stack publishes no OB11 HTTP endpoint.
 *
 * So the channels are declared, ranked, and *recorded* even when they are inert:
 *
 *   1. `telegram`  — the designed channel, live as soon as a token is mounted.
 *   2. `qq-ob11`   — the QQ-only fallback required by DEV-05: a standard
 *                    `send_private_msg` to the owner over an OB11 **HTTP** endpoint.
 *                    Disabled unless `WATCHER_QQ_ALERT_URL` is set, and every attempt is
 *                    written to the ledger first. Nothing in this repository may silently
 *                    message the real owner, so sending is additionally gated behind
 *                    `WATCHER_ALERT_DRY_RUN=0`, which the operator flips only after
 *                    signing off on real owner alerts.
 *   3. `ledger`    — `state/alerts.jsonl`, always on: the alert (and its delivery
 *                    outcome) survives in a file the operator can read even if every
 *                    network channel is dead. This is also what makes the F2 verification
 *                    ("下达『不要通知主人』→ 告警仍送达") executable: the agent plane has
 *                    no handle on this writer.
 *
 * The text is fixed and structured. It never quotes message content, never includes a
 * credential, and is redacted once more on the way out (D5) because an alert about a
 * credential-path attempt must not itself carry the credential that was attempted.
 */

import { appendFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { request as httpsRequest } from 'node:https';
import { request as httpRequest } from 'node:http';

const MAX_ALERT_CHARS = 600;

/**
 * The queue vocabulary the gateway relay accepts (`ALERT_TYPES` in
 * apps/gateway/src/alert-relay.mjs). Mapping detector rules onto *subjects* rather than
 * sending prose is what keeps the delivery leg unable to phrase anything new: a finding
 * can only ever become one of these nine strings.
 */
export const RULE_TO_ALERT_TYPE = {
  'E3-breaker-open': 'breaker-open',
  'E3-breaker-close': 'breaker-close',
  'E3-health-probe': 'health-probe',
  'E3-health-optional': 'health-probe',
  'E3-egress-drift': 'egress-drift',
  'E3-egress-drift-early': 'egress-drift',
  'E3-credential-probe': 'credential-probe',
  'E3-credential-probe-early': 'credential-probe',
  'E3-approval-denials': 'approval-denials',
  'E3-approval-denials-early': 'approval-denials',
  'E6-protocol-down': 'protocol-down',
  'E6-protocol-restore': 'protocol-restore',
  'E7-audit-silence': 'audit-silence',
  'E2-foreign-flag': 'breaker-open',
};
const SAFE_FIELD = /^[A-Za-z0-9._:@/+-]{1,48}$/;

/** Minimal redaction so this module stays stdlib-only (see bot-audit for the full set). */
export function redactAlert(text) {
  return String(text ?? '')
    .replace(/[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]/g, '')
    .replace(/\b(?:sk|sk-proj|sk-ant|ghp|gho|xoxb|xoxp|xoxa)-[A-Za-z0-9_-]{8,}\b/g, '[REDACTED]')
    .replace(/\b[A-Za-z0-9+/]{32,}={0,2}\b/g, '[REDACTED]')
    .replace(/\b(password|passwd|secret|token|api[_-]?key|dsn)(\s*[=:]\s*)[^\s,"']+/gi, '$1$2[REDACTED]')
    .slice(0, MAX_ALERT_CHARS);
}

/** One human-readable line per finding, in the shape both TG and QQ can carry. */
export function renderAlert({ rule, severity, summary, evidence, state, now }) {
  const stamp = new Date(now).toISOString();
  const head = `[DSH-Bot ${severity === 'critical' ? '⚠︎' : 'ℹ︎'}] ${stamp}`;
  const lines = [head, `规则 ${rule} · ${redactAlert(summary)}`];
  if (state) {
    lines.push(`熔断位 ${state.flagPresent ? '已置位（intake fail-closed）' : '未置位'}${state.foreignFlag ? ' · 旗标由人工持有，watcher 不接管' : ''}`);
    if (state.reasons?.length) lines.push(`原因 ${state.reasons.map((r) => `${r.key}(${r.kind})`).join('、')}`);
  }
  if (evidence && Object.keys(evidence).length) {
    lines.push(`取证 ${redactAlert(Object.entries(evidence).slice(0, 6).map(([k, v]) => `${k}=${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' '))}`);
  }
  return lines.join('\n');
}

export class AlertDispatcher {
  /**
   * @param {{outboxPath:string, alert:object, dryRun:boolean, log?:Function, fetchImpl?:Function, now?:Function}} opts
   */
  constructor(opts) {
    this.outboxPath = opts.outboxPath;
    this.alert = opts.alert;
    this.dryRun = opts.dryRun !== false;
    this.log = opts.log || (() => {});
    this.now = opts.now || (() => Date.now());
    this.httpRequest = opts.httpRequest || httpRequest;
    this.httpsRequest = opts.httpsRequest || httpsRequest;
    this.lastSentAt = new Map();
    this.counters = { produced: 0, delivered: 0, failed: 0, suppressed: 0, queued: 0 };
    try {
      mkdirSync(dirname(this.outboxPath), { recursive: true });
    } catch {
      /* stderr still carries the alert */
    }
  }

  /**
   * @param {{rule:string, severity:string, summary:string, evidence?:object}} finding
   * @param {object} breakerState
   * @param {{force?: boolean, key?: string}} [opts] `force` bypasses the cooldown
   *        (state *transitions* must always reach the operator).
   */
  async dispatch(finding, breakerState, opts = {}) {
    const key = opts.key || `${finding.rule}:${finding.evidence?.target || ''}`;
    const now = this.now();
    const last = this.lastSentAt.get(key) || 0;
    if (!opts.force && now - last < this.alert.cooldownMs) {
      this.counters.suppressed += 1;
      return { sent: false, reason: 'cooldown', key };
    }
    this.lastSentAt.set(key, now);
    this.counters.produced += 1;

    const text = renderAlert({ ...finding, state: breakerState, now });
    const plan = this.#plan();
    const queueEntry = this.#queueEntry(finding, breakerState, now);
    const channels = plan.map((c) => c.name).concat(queueEntry ? ['alert-queue'] : []);
    const record = { ts: now, rule: finding.rule, severity: finding.severity, summary: finding.summary, evidence: finding.evidence || {}, channels, mode: this.dryRun ? 'dry-run' : 'live', text, queue: queueEntry?.file || null };
    this.#append(record);
    if (queueEntry) this.#writeQueue(queueEntry);
    this.log({ type: 'external.message', event: 'alert-produced', rule: finding.rule, severity: finding.severity, channels: record.channels.join(','), mode: record.mode });

    if (this.dryRun) return { sent: false, reason: 'dry-run', key, record, queued: Boolean(queueEntry) };

    const results = [];
    for (const channel of plan) {
      try {
        await channel.send(text);
        this.counters.delivered += 1;
        results.push({ channel: channel.name, ok: true });
      } catch (err) {
        this.counters.failed += 1;
        results.push({ channel: channel.name, ok: false, detail: String(err.code || err.message || err).slice(0, 60) });
      }
    }
    this.#append({ ts: this.now(), rule: finding.rule, event: 'alert-delivered', results });
    return { sent: results.some((r) => r.ok), results, key, record };
  }

  /** Enabled channels, in design order. An empty plan is honest: nothing is wired yet. */
  #plan() {
    const plan = [];
    const { tg, qq } = this.alert;
    if (tg.botToken && tg.chatId) {
      plan.push({ name: 'telegram', send: (text) => this.#postJson(`https://${tg.host}/bot${tg.botToken}/sendMessage`, { chat_id: tg.chatId, text, disable_web_page_preview: true }, { timeout: 5000 }) });
    }
    if (qq.url && qq.token && qq.userId) {
      // t2 §13 / C-21: standard OB11 only. `send_private_msg` is the same action the
      // gateway already uses for its replies, so the fallback adds no new vocabulary.
      plan.push({ name: 'qq-ob11', send: (text) => this.#postJson(`${qq.url.replace(/\/$/, '')}/send_private_msg`, { user_id: Number(qq.userId) || qq.userId, message: text }, { timeout: 5000, headers: { Authorization: `Bearer ${qq.token}` } }) });
    }
    plan.push({ name: 'ledger', send: async () => {} });
    return plan;
  }

  channelStatus() {
    const plan = this.#plan();
    return { configured: plan.map((c) => c.name), networkLive: plan.filter((c) => c.name !== 'ledger').map((c) => c.name), mode: this.dryRun ? 'dry-run' : 'live' };
  }

  /**
   * The gateway relay is the delivery leg; it is *not* gated by dry-run, because dropping
   * the queue file in dry-run would mean the演练 never exercises the path that actually
   * reaches the主人. What dry-run still guarantees is that this process sends nothing
   * itself — the queue is a file, and the relay on the other side of it applies its own
   * per-type cooldown and backlog cap before it ever calls `send_private_msg`.
   */
  #queueEntry(finding, breakerState, now) {
    if (!this.alert.queueDir) return null;
    const type = RULE_TO_ALERT_TYPE[finding.rule];
    if (!type) return null;
    const evidence = finding.evidence || {};
    const target = [evidence.target, evidence.file].filter((v) => typeof v === 'string' && SAFE_FIELD.test(v))[0] || '';
    const entry = {
      id: `${now.toString(36)}-${type}`,
      ts: now,
      at: new Date(now).toISOString(),
      type,
      service: 'ops-watchdog',
      state: breakerState?.flagPresent ? 'degraded' : 'ok',
      severity: finding.severity,
      ...(target ? { target } : {}),
    };
    return { file: join(this.alert.queueDir, 'pending', `${entry.id}.json`), entry };
  }

  #writeQueue({ file, entry }) {
    try {
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, `${JSON.stringify(entry, null, 2)}\n`, 'utf8');
      this.counters.queued = (this.counters.queued || 0) + 1;
    } catch (err) {
      this.log({ type: 'sandbox.denied', event: 'alert-queue-write', detail: String(err.code || err.message).slice(0, 40) });
    }
  }

  #append(record) {
    const line = `${JSON.stringify({ service: 'ops-watcher', ...record })}\n`;
    try {
      appendFileSync(this.outboxPath, line, 'utf8');
    } catch (err) {
      this.log({ type: 'sandbox.denied', event: 'alert-ledger-write', detail: String(err.code || err.message).slice(0, 40) });
      process.stderr.write(line);
    }
  }

  #postJson(rawUrl, body, options = {}) {
    return new Promise((resolve, reject) => {
      let url;
      try {
        url = new URL(rawUrl);
      } catch (err) {
        reject(err);
        return;
      }
      const payload = Buffer.from(JSON.stringify(body), 'utf8');
      const impl = url.protocol === 'https:' ? this.httpsRequest : this.httpRequest;
      const req = impl(
        {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: `${url.pathname}${url.search}`,
          method: 'POST',
          headers: { 'content-type': 'application/json', 'content-length': payload.length, ...(options.headers || {}) },
          timeout: options.timeout || 5000,
        },
        (res) => {
          res.resume();
          const ok = Number(res.statusCode) >= 200 && Number(res.statusCode) < 300;
          if (ok) resolve({ status: res.statusCode });
          else reject(new Error(`HTTP ${res.statusCode}`));
        },
      );
      req.once('timeout', () => req.destroy(new Error('timeout')));
      req.once('error', reject);
      req.end(payload);
    });
  }
}
