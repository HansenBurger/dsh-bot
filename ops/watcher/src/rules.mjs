/**
 * rules — detection rules over the `bot.audit.v1` stream (t3 arch §5.2 “旁路 watcher”,
 * baseline E3/F2/E7, DEV-19).
 *
 * The engine is pure: it takes audit records plus the current clock and returns
 * *findings*. No I/O, no fs, no network — everything it needs to be wrong about is
 * covered by a unit test, and the side effects live in `breaker.mjs` / `alert.mjs`.
 *
 * E3 names exactly three triggers, and each one is implemented here:
 *   1. 凭据路径访问尝试  → `credential.resolve result=denied` / `authz.decision
 *      stage∈{ob11-handshake,ob11-self-id,memory-hmac} result=denied`
 *   2. 非白名单出站点    → `llm.egress target` whose host is not in the squid allowlist
 *   3. 连续审批拒绝      → `approval.outcome stage=decided decision=denied` × N in a row
 *
 * Two availability rules come from the topology instead of the audit stream (E3 “连续失败
 * 达阈值”): a required net-ops peer that refuses a probe N times in a row. And C-32 says
 * the QQ protocol leg must **only** alert, never degrade — NapCat being down is not a
 * security state, and degrading the rest of the stack for it would turn one dead channel
 * into two.
 */

const CREDENTIAL_STAGES = new Set(['ob11-handshake', 'ob11-self-id', 'ob11-frame', 'memory-hmac']);
/** Reasons that mean “someone reached for a credential they were not handed”. */
const CREDENTIAL_DENIAL_REASONS = new Set(['unknown-token', 'unknown-client', 'never-resolvable', 'ref-not-authorized', 'no-token', 'no-such-endpoint', 'UNAUTHENTICATED', 'NONCE_REPLAY', 'token-fingerprint-mismatch', 'self-id-mismatch']);

const hostOf = (target) => String(target || '').split('/')[0].split(':')[0].toLowerCase();

export class DetectionEngine {
  /**
   * @param {{credentialBurst:number, credentialWindowMs:number, approvalDenyStreak:number,
   *          egressDriftStreak:number, egressAllowlist:string[]}} opts
   */
  constructor(opts) {
    this.credentialBurst = opts.credentialBurst ?? 5;
    this.credentialWindowMs = opts.credentialWindowMs ?? 120_000;
    this.approvalDenyStreak = opts.approvalDenyStreak ?? 3;
    this.egressDriftStreak = opts.egressDriftStreak ?? 2;
    this.egressAllowlist = (opts.egressAllowlist ?? []).map((h) => h.toLowerCase());
    this.credentialHits = [];
    this.approvalStreak = 0;
    this.egressDrift = 0;
    /** protocol-leg state, one entry per adapter socket family (C-32: alert only) */
    this.protocol = { connected: false, at: 0 };
    this.seen = { records: 0, byType: {} };
  }

  /**
   * @param {object[]} records audit records in stream order
   * @param {number} now epoch ms
   * @returns {Array<{rule:string, severity:'info'|'warn'|'critical', degrade:boolean, alert:boolean, summary:string, evidence:object}>}
   */
  feed(records, now = Date.now()) {
    const findings = [];
    for (const record of records) {
      this.seen.records += 1;
      this.seen.byType[record.type] = (this.seen.byType[record.type] || 0) + 1;
      const finding = this.#evaluate(record, now);
      if (finding) findings.push(finding);
      for (const extra of this.#protocol(record, now)) findings.push(extra);
    }
    return findings;
  }

  #evaluate(record, now) {
    switch (record.type) {
      case 'credential.resolve':
        return this.#credential(record, now, { kind: 'broker-ref', reason: record.reason, clientId: record.clientId, ref: record.ref, path: record.path });
      case 'authz.decision':
        if (record.result === 'denied' && CREDENTIAL_STAGES.has(record.stage) && CREDENTIAL_DENIAL_REASONS.has(String(record.reason || record.code || ''))) {
          return this.#credential(record, now, { kind: `stage:${record.stage}`, reason: record.reason || record.code, socketId: record.socketId });
        }
        return null;
      case 'llm.egress':
      case 'egress.connect':
        return this.#egress(record);
      case 'approval.outcome':
        return this.#approval(record);
      default:
        return null;
    }
  }

  #credential(record, now, evidence) {
    if (record.result !== 'denied') return null;
    if (!CREDENTIAL_DENIAL_REASONS.has(String(evidence.reason || ''))) return null;
    this.credentialHits = this.credentialHits.filter((t) => now - t < this.credentialWindowMs);
    this.credentialHits.push(now);
    const burst = this.credentialHits.length;
    if (burst >= this.credentialBurst) {
      const trimmed = this.credentialHits.length;
      this.credentialHits = [];
      return {
        rule: 'E3-credential-probe',
        severity: 'critical',
        degrade: true,
        alert: true,
        summary: `${trimmed} 次凭据路径拒绝（E3 信号 1）`,
        evidence: { ...evidence, burst, windowMs: this.credentialWindowMs },
      };
    }
    return {
      rule: 'E3-credential-probe-early',
      severity: 'warn',
      degrade: false,
      alert: true,
      summary: `凭据路径访问尝试 ${burst}/${this.credentialBurst}（尚未熔断）`,
      evidence,
    };
  }

  #egress(record) {
    const target = hostOf(record.target || record.host || '');
    if (!target) return null;
    if (this.egressAllowlist.includes(target)) {
      this.egressDrift = 0;
      return null;
    }
    this.egressDrift += 1;
    const evidence = { target, status: record.status ?? null, clientId: record.clientId ?? null, streak: this.egressDrift };
    if (this.egressDrift >= this.egressDriftStreak) {
      this.egressDrift = 0;
      return { rule: 'E3-egress-drift', severity: 'critical', degrade: true, alert: true, summary: `非白名单出站点：${target}（E3 信号 2）`, evidence };
    }
    return { rule: 'E3-egress-drift-early', severity: 'warn', degrade: false, alert: true, summary: `出站点 ${target} 不在白名单（第 ${this.egressDrift} 次）`, evidence };
  }

  #approval(record) {
    // Only an *answer from the owner* counts. `expired` (no answer in 5 min) and `orphan`
    // (an approval word with nothing pending) are not refusals — treating them as such
    // would degrade the companion every time the主人 falls asleep.
    if (record.stage !== 'decided') return null;
    if (record.decision === 'approved') {
      this.approvalStreak = 0;
      return null;
    }
    if (record.decision !== 'denied') return null;
    this.approvalStreak += 1;
    const evidence = { streak: this.approvalStreak, toolName: record.toolName ?? null, threshold: this.approvalDenyStreak };
    if (this.approvalStreak >= this.approvalDenyStreak) {
      // The streak is deliberately *not* reset here: while the owner keeps refusing, the
      // breaker must stay latched instead of drifting closed between two refusals.
      return { rule: 'E3-approval-denials', severity: 'critical', degrade: true, alert: true, summary: `连续 ${evidence.streak} 次审批被拒（E3 信号 3）`, evidence };
    }
    return { rule: 'E3-approval-denials-early', severity: 'info', degrade: false, alert: false, summary: `审批连续拒绝 ${this.approvalStreak}/${this.approvalDenyStreak}`, evidence };
  }

  #protocol(record, now) {
    if (record.type !== 'session.lifecycle' || record.stage !== 'ob11-handshake') return [];
    if (record.event === 'connected') {
      const wasDown = !this.protocol.connected && this.protocol.at > 0;
      this.protocol = { connected: true, at: now };
      return wasDown
        ? [{ rule: 'E6-protocol-restore', severity: 'info', degrade: false, alert: true, summary: '协议端回程已恢复', evidence: { socketId: record.socketId } }]
        : [];
    }
    if (record.event === 'disconnected') {
      this.protocol = { connected: false, at: now };
      // C-32: the QQ leg dropping must alert, never degrade; NapCat is the channel that
      // carries the alert, so degrading on its loss would silence the very thing we need.
      return [{ rule: 'E6-protocol-down', severity: 'warn', degrade: false, alert: true, summary: '协议端（NapCat）反向 WS 已断开：只告警不熔断（C-32）', evidence: { socketId: record.socketId } }];
    }
    return [];
  }

  /** Availability finding from the probe loop (E3 “连续失败达阈值”). */
  probeFailure({ name, detail, fails }) {
    return {
      rule: 'E3-health-probe',
      severity: 'critical',
      degrade: true,
      alert: true,
      summary: `必需依赖 ${name} 连续 ${fails} 次探测失败（E3 信号 4：健康轮询）`,
      evidence: { target: name, detail, fails },
    };
  }

  probeRecovery({ name, oks }) {
    return { rule: 'E3-health-probe', severity: 'info', degrade: false, alert: true, summary: `依赖 ${name} 已连续 ${oks} 次探测成功`, evidence: { target: name, oks } };
  }

  /** TM-014 信号 8 / E7: an audit stream that stopped growing. Alert only, never degrade. */
  streamStalled({ file, ageMs }) {
    return { rule: 'E7-audit-silence', severity: 'warn', degrade: false, alert: true, summary: `审计流停增：${file} 已 ${Math.round(ageMs / 1000)}s 无新行`, evidence: { file, ageMs } };
  }

  stats() {
    return { credentialHits: this.credentialHits.length, approvalStreak: this.approvalStreak, egressDrift: this.egressDrift, protocol: { ...this.protocol }, seen: { ...this.seen, byType: { ...this.seen.byType } } };
  }
}
