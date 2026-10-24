/**
 * @dsh-bot/bot-audit
 *
 * `bot.audit.v1` JSONL sink (t3 arch §9.4, baseline F1).
 *
 * Eight event classes are mandatory:
 *   external.message / authz.decision / tool.call / approval.outcome /
 *   sandbox.denied / credential.resolve / egress.connect / config.change
 * plus the memory subsystem's ninth class `memory.access` (arch §5.5 note:
 * the PG table is a *query view*, this stream is the source of truth — F3).
 *
 * Append-only discipline: we open the file with 'a', never truncate, and rotate
 * by rename+create so an existing descriptor keeps writing to the old inode.
 * Local deletion is not a containment measure — the collector keeps the remote
 * copy (F3) — so nothing here offers a "delete" API on purpose.
 *
 * Redaction happens before serialization (D5): secrets never reach the log even
 * if a caller passes them in.
 */

import { appendFileSync, mkdirSync, renameSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname } from 'node:path';

export const AUDIT_TYPES = Object.freeze([
  'external.message',
  'authz.decision',
  'tool.call',
  'approval.outcome',
  'sandbox.denied',
  'credential.resolve',
  'egress.connect',
  'config.change',
  'memory.access',
  // Added with the t5 runtime: `emit()` rewrites anything outside this list to
  // `external.message`, and the gateway's rate-limit and connection events were being
  // silently relabelled — an operator grepping for throttling found nothing. They are
  // distinct event classes, not subtypes of "external message", so the vocabulary grows
  // instead of the information being lost.
  'ratelimit.exceeded',
  'session.lifecycle',
  // Added with the t8 model path. `emit()` relabels anything outside this list, so the
  // LLM egress calls and the companion turns would otherwise be indistinguishable from
  // generic message events — and quota/latency forensics depend on grepping them out.
  'llm.call',
  'agent.turn',
]);

const MAX_PREVIEW_CHARS = 200;

/**
 * High-entropy / credential-shaped strings that must never be logged verbatim
 * (D5). Applied to every string field of the record.
 */
const REDACTION_PATTERNS = [
  // provider keys and common token prefixes
  /\b(?:sk|sk-proj|ghp|gho|xox[baprs)-]{10,})-[A-Za-z0-9_-]{8,}\b/g,
  // long base64/hex blobs (>=32 chars) — typical secret shape
  /\b[A-Za-z0-9+/]{32,}={0,2}\b/g,
  /\b[0-9a-f]{40,}\b/gi,
  // explicit assignments
  /(Authorization\s*:\s*Bearer\s+)[^\s]+/gi,
  /(password|passwd|secret|token|api[_-]?key|dsn)(\s*[=:]\s*)[^\s,"']+/gi,
];

/** sha256 of text, prefixed so a reader knows it is a hash not an id. */
export function textHash(text) {
  return `sha256:${createHash('sha256').update(String(text ?? ''), 'utf8').digest('hex')}`;
}

/**
 * Mask anything credential-shaped while keeping the text usable for triage (D5).
 *
 * Patterns are applied in ONE pass over a combined alternation. Chaining
 * `String.replace` per pattern is wrong here: each later pattern re-scans text
 * that already contains `[REDACTED]`, whose 10 uppercase letters are themselves a
 * >=32-char run once repeated — so the output degenerates into an unbounded
 * explosion of markers and the audit line becomes unreadable.
 */
export function redact(value) {
  let out = String(value ?? '');
  // Strip zero-width / bidi controls so a payload cannot hide text inside a log line.
  out = out.replace(new RegExp('[\\u200B-\\u200F\\u202A-\\u202E\\u2060\\uFEFF]', 'g'), '');
  // Capture-group indices are positional, so each branch owns its own slots and
  // an earlier non-matching branch contributes only undefined.
  // Alternatives are tried left-to-right at each position, so a bare `Bearer …`
  // header value is claimed by branch 1 (prefix kept) before the generic
  // assignment branch can swallow the whole "Authorization: Bearer" prefix.
  return out.replace(COMBINED_RE, (match, ...args) => {
    // When the pattern has named groups, `replace` appends the groups object as
    // the FINAL argument — after (match, ...captures, offset, wholeString). A fixed
    // offset from the end returns the offset number or the whole string instead,
    // which silently drops every prefix this function is meant to preserve.
    const groups = args[args.length - 1] || {};
    if (groups.bearerPrefix) return `${groups.bearerPrefix}[REDACTED]`;   // "Authorization: Bearer …"
    if (groups.assignKey) return `${groups.assignKey}${groups.assignSep}[REDACTED]`; // keeps key + operator
    if (groups.keyPrefix) return `${groups.keyPrefix}[REDACTED]`;         // "sk-…" keeps the shape hint
    if (groups.dsnUser) return `${groups.dsnUser}[REDACTED]@`;             // keep scheme/host, drop the password
    return maskToken(match);                                              // bare high-entropy run
  });
}

// Ordered alternatives; the assignment form must precede the bare-run form so a
// token introduced by `key=` keeps its key visible for triage. Written as regex
// literals (not strings) so `\b` / `\s` keep their meaning and quotes need no
// escaping inside a JS string.
const COMBINED_RE = new RegExp(
  [
    // 1) header form: keep "Authorization: Bearer " so triage knows which channel leaked
    String.raw`(?<bearerPrefix>\b[A-Za-z-]*[Aa]uthorization\s*[:=]\s*(?:Bearer\s+)?)\S+`,
    // 2) assignment form: capture key + separator, mask only the value
    String.raw`(?<assignKey>\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|dsn))(?<assignSep>\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)`,
    // 3) well-known credential prefixes: mask the value, keep the identifying prefix
    String.raw`(?<keyPrefix>\b(?:sk-proj|sk-ant|sk|ghp|gho|ghu|ghs|xoxb|xoxp|xoxa)-)[A-Za-z0-9_-]{10,}`,
    // 4) connection strings: the userinfo password is the secret; keep scheme + host.
    //    The trailing '@' is re-emitted by the replacer, so it must be consumed here.
    String.raw`(?<dsnUser>(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[A-Za-z0-9_.%-]*:)[^@\s]+@`,
    // 5) bare high-entropy run
    String.raw`([A-Za-z0-9+/]{32,}={0,2}|[0-9a-fA-F]{40,})`,
  ].join('|'),
  'gi',
);

/**
 * Bare high-entropy runs are masked only when they actually look like a key.
 * A run of one repeated character has entropy 0 and stays visible, otherwise
 * every preview containing a long separator line collapses to `[REDACTED]`.
 */
function maskToken(run) {
  const freq = new Map();
  for (const ch of run) freq.set(ch, (freq.get(ch) || 0) + 1);
  if (freq.size <= 2) return run;
  let h = 0;
  for (const n of freq.values()) {
    const p = n / run.length;
    h -= p * Math.log2(p);
  }
  return h >= 3.5 ? '[REDACTED]' : run;
}

/**
 * First `max` characters of the **original** text, then redacted.
 * Slicing after redaction would shorten the preview further because every mask
 * collapses a long secret into `[REDACTED]`.
 */
export function preview(text, max = MAX_PREVIEW_CHARS) {
  // Bound the *redacted* result: masking can lengthen a short token into
  // `[REDACTED]`, so slicing the input first does not bound the output.
  const raw = String(text ?? '');
  let limit = Math.min(raw.length, max);
  for (;;) {
    const sliced = raw.slice(0, limit) + (limit < raw.length ? '…' : '');
    const candidate = redact(sliced);
    if (candidate.length <= max) return candidate;
    if (limit === 0) return candidate.slice(0, max);
    limit = Math.max(0, limit - Math.max(1, candidate.length - max));
  }
}

function scrub(node, depth = 0) {
  if (depth > 6) return undefined;
  if (typeof node === 'string') return redact(node);
  if (Array.isArray(node)) return node.map((n) => scrub(n, depth + 1));
  if (node && typeof node === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(node)) {
      if (typeof v === 'string') {
        // Message-shaped keys are bounded to a preview even when redaction finds
        // nothing to mask, so a chat transcript never lands whole in the audit file.
        if (/^(text|body|content|raw|payload|args|arguments|value|summary|prompt)$/i.test(k)) {
          out[k] = preview(v);
          continue;
        }
        // Credential-shaped keys/values are masked regardless of length (D5):
        // a DSN passed under an unusual key name must still not leak.
        const looksLikeCredentialValue = /(postgres|postgresql|mysql|mongodb|redis|amqp):\/\/\S/i.test(v) || /\b(?:sk|sk-proj|sk-ant|ghp|gho|xoxb)-[A-Za-z0-9_-]{10,}/.test(v);
        if (/password|passwd|secret|token|api[_-]?key|dsn|credential|authorization|key$/i.test(k) || looksLikeCredentialValue) {
          out[k] = '[REDACTED]';
          continue;
        }
        out[k] = redact(v);
        continue;
      }
      out[k] = scrub(v, depth + 1);
    }
    return out;
  }
  return node;
}

export class AuditSink {
  /**
   * @param {{path: string, maxSizeBytes?: number, service?: string}} opts
   */
  constructor(opts) {
    if (!opts?.path) throw new Error('AuditSink requires a path');
    this.path = opts.path;
    this.service = opts.service || 'unknown';
    this.maxSizeBytes = opts.maxSizeBytes ?? 32 * 1024 * 1024;
    this.dir = dirname(this.path);
    try {
      mkdirSync(this.dir, { recursive: true });
    } catch {
      /* read-only mount: fall back to stderr emission below */
    }
    this.enabled = true;
  }

  /**
   * Emit one audit event.
   * @param {string} type - one of {@link AUDIT_TYPES}
   * @param {object} fields - structured fields; ids only, display text forbidden
   */
  emit(type, fields = {}) {
    if (!AUDIT_TYPES.includes(type)) type = 'external.message';
    const record = {
      ts: Date.now(),
      type,
      service: this.service,
      ...scrub(fields),
    };
    if (fields.textPreview !== undefined) record.text_preview = preview(fields.textPreview);
    if (fields.text !== undefined) {
      record.text_hash = textHash(fields.text);
      delete record.text;
    }
    const line = `${JSON.stringify(record)}\n`;
    if (!this.enabled) {
      process.stderr.write(line);
      return record;
    }
    try {
      this.#rotateIfNeeded();
      appendFileSync(this.path, line, 'utf8');
    } catch (err) {
      // Losing audit is worse than losing the request: fail loudly to stderr so
      // the watcher's "log stopped growing" signal (TM-014) fires.
      process.stderr.write(`{"ts":${Date.now()},"type":"sandbox.denied","service":"${this.service}","audit_sink_error":${JSON.stringify(String(err.message)).slice(0, 200)}}\n`);
      process.stderr.write(line);
    }
    return record;
  }

  #rotateIfNeeded() {
    let size = 0;
    try {
      size = statSync(this.path).size;
    } catch {
      return;
    }
    if (size < this.maxSizeBytes) return;
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    try {
      renameSync(this.path, `${this.path}.${stamp}.old`);
    } catch {
      /* concurrent rotation: fine */
    }
  }
}
