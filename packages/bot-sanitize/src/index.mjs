/**
 * @dsh-bot/bot-sanitize
 *
 * Text-level defences shared by the gateway and the memory service. Two distinct
 * jobs, deliberately kept in separate functions:
 *
 *  1. `tagRisk()` — heuristic *labelling* of injection-shaped input (t3 arch
 *     §5.3.2 / baseline A6). It never discards: silent dropping lets an attacker
 *     bisect the rule set. The tag rides along on the normalized object and into
 *     the audit trail; policy elsewhere decides what a tag means.
 *
 *  2. `sanitizeForStorage()` — write-side decontamination for long-term memory
 *     (memory arch §4.5 rule 1). Strips envelope delimiters that could let a
 *     stored string terminate or imitate its own `<memory-untrusted-xxxx>`
 *     wrapper on a later read, plus control characters, then length-bounds.
 *
 *  3. `envelope()` — random-delimiter wrapping (§5.3.3, C-25) used for chat
 *     input, tool results and retrieved memory alike. Token is fresh per call so
 *     two identical messages produce different prompts (A4/M-16).
 *
 *  4. `redactOutbound()` — reply-buffer scrubbing before anything leaves the
 *     agent zone (§5.3.4 / A7 / TM-011).
 */

import { randomBytes } from 'node:crypto';

/* ------------------------------------------------------------------ *
 * Control characters
 * ------------------------------------------------------------------ */

// Zero-width + bidi controls + BOM + word joiner. Deliberately a literal class:
// \p{Cf} would also eat soft hyphens that appear in legitimate text.
const CONTROL_CHARS = new RegExp('[\\u200B-\\u200F\\u2028\\u2029\\u2060\\uFEFF\\u180E]', 'g');
// U+202F NARROW NO-BREAK SPACE and U+2066-U+2069 iso-bidi controls are invisible
// but not whitespace; treat them as control too.
const EXTRA_CONTROLS = new RegExp('[\\u202A-\\u202E\\u2066-\\u2069]', 'g');

/** True when any invisible control/bidi character is present. */
function hasControl(s) {
  CONTROL_CHARS.lastIndex = 0;
  EXTRA_CONTROLS.lastIndex = 0;
  return CONTROL_CHARS.test(s) || EXTRA_CONTROLS.test(s);
}

/* ------------------------------------------------------------------ *
 * Risk tagging (label only, never drop)
 * ------------------------------------------------------------------ */

const INSTRUCTION_OVERRIDE = [
  /忽略(以上|之前|上面|所有)(的)?(指令|提示|规则|设定)/i,
  /无视(以上|之前|所有)(的)?(指令|提示|规则)/i,
  /ignore\s+(all\s+)?(previous|above|prior|earlier)\s+(instructions?|prompts?|rules?|context)/i,
  /disregard\s+(all\s+)?(previous|the\s+system)/i,
  /(你现在是|你不再是|扮演一个?(没有|不受)(任何)?限制)/,
  /you\s+are\s+now\s+(a|an)\b.*\bwithout\s+(any\s+)?restrictions/i,
  /developer\s+mode|jailbreak|dan\s+mode/i,
  // Either direction of the same ask: leak *the* prompt, or dump a credential
  // store. The verb list is shared so "输出你的系统提示" (verb before noun) hits too.
  /(系统提示|system\s+prompt|提示词)[\s\S]{0,16}(输出|打印|重复|泄露|给我看|reveal|print|show|repeat|dump)|(?:输出|打印|重复|泄露|reveal|print|show|repeat|dump)[\s\S]{0,16}(系统提示|提示词|system\s+prompt)/i,
];

const CREDENTIAL_PATHS = [
  /\.credentials\.ya?ml/i,
  /(^|[\s/'"])~?\/?\.(?:ssh|aws|gnupg)\b/i,
  // `.env` counts as a credential path only near a read/exfiltration verb or an
  // explicit content request — ordinary chatter mentions "env" harmlessly.
  // Alternatives are grouped so no branch can swallow the leading dot of ".env".
  /(?:^|[^\w./-])\.env(?:\.\w+)?(?![\w-])([\s\S]{0,16}(?:内容|文件|路径|目录|里|中)|[\s\S]{0,16}?(?:读|查看|打开|输出|打印|上传|发送|给我|发我))?/i,
  /(?:^|[^\w-])(?:cat|less|more|head|tail|read|show|print|dump|open|send|upload)\b[\s\S]{0,24}(?:^|[^\w./-])\.env(?![\w-])/i,
  /(?:读|读取|查看|打开|输出|打印|上传|发送|给我|发我)[\s\S]{0,24}(?:^|[^\w./-])\.env(?![\w-])/i,
  /\/etc\/(?:passwd|shadow|sudoers)\b/i,
  /\bid_rsa\b|\bseed\.db\b|api[_-]?key\s*[:=]/i,
  /\bprintenv\b|\benviron(ment)?\b.{0,8}(dump|list|key)/i,
];

const OFF_ALLOWLIST_URL_HINT = /(https?:\/\/(?!(?:api\.telegram\.org|api\.deepseek\.com|[^/]*\.qq\.com|[^/]*\.gtimg\.cn))[^\s]+)\b/i;

/** base64/hex blob of >=40 chars with no whitespace — encoded-payload shape. */
const ENCODED_BLOB = /\b(?:[A-Za-z0-9+/]{40,}={0,2}|[0-9a-fA-F]{48,})\b/g;

/**
 * @param {string} text
 * @param {{maxChars?: number}} [opts]
 * @returns {string[]} risk tags drawn from the closed RiskTag vocabulary
 */
export function tagRisk(text, opts = {}) {
  const maxChars = opts.maxChars ?? 8000;
  const tags = new Set();
  if (typeof text !== 'string' || text.length === 0) return [];

  if (text.length > maxChars) tags.add('oversize');
  const sample = text.slice(0, maxChars);

  if (hasControl(sample)) tags.add('zero-width');

  if (INSTRUCTION_OVERRIDE.some((re) => re.test(sample))) tags.add('instruction-override');
  if (CREDENTIAL_PATHS.some((re) => re.test(sample))) tags.add('credential-path');
  if (OFF_ALLOWLIST_URL_HINT.test(sample)) tags.add('offallowlist-url');

  const blobs = sample.match(ENCODED_BLOB);
  if (blobs && blobs.some((b) => shannonEntropy(b) > 4.0)) tags.add('encoded-payload');

  return [...tags];
}

/** Bits per character; used to avoid flagging "aaaaaaaa" as a secret. */
function shannonEntropy(s) {
  const freq = new Map();
  for (const ch of s) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/* ------------------------------------------------------------------ *
 * Write-side decontamination (memory arch §4.5 rule 1)
 * ------------------------------------------------------------------ */

// Any of our own envelope shapes, including a partial/forged one.
const ENVELOPE_RESIDUE = /<\/?(?:xmsg|retrieved-untrusted|memory-untrusted)-[0-9a-f]{1,16}>?/gi;
const FAKE_ENVELOPE = /<\/?[a-z][a-z0-9_-]*-[0-9a-f]{4,64}>/gi;

/**
 * Prepare candidate memory text for durable storage.
 *
 * @param {string} body
 * @param {{maxChars?: number}} [opts]
 * @returns {{text: string, stripped: string[], truncated: boolean, emptyAfterSanitize: boolean}}
 */
export function sanitizeForStorage(body, opts = {}) {
  const maxChars = opts.maxChars ?? 2000;
  const stripped = [];
  if (typeof body !== 'string') return { text: '', stripped: ['non-string'], truncated: false, emptyAfterSanitize: true };

  let out = body.replace(CONTROL_CHARS, '').replace(EXTRA_CONTROLS, '');

  out = out.replace(ENVELOPE_RESIDUE, (m) => {
    stripped.push(m.slice(0, 40));
    return '';
  });
  // Second pass with the generic shape catches `<memory-untrusted-ffff>` written
  // with an unexpected token length, which the specific pattern above misses.
  out = out.replace(FAKE_ENVELOPE, (m) => {
    stripped.push(m.slice(0, 40));
    return '';
  });

  out = out.replace(/[ \t]{2,}/g, ' ').replace(/\n{3,}/g, '\n\n').trim();

  let truncated = false;
  if (out.length > maxChars) {
    out = out.slice(0, maxChars);
    truncated = true;
  }
  return { text: out, stripped, truncated, emptyAfterSanitize: out.length === 0 };
}

/* ------------------------------------------------------------------ *
 * Read-side envelope (C-25 / A4 / M-16)
 * ------------------------------------------------------------------ */

/**
 * Fresh delimiter token per call. 4 bytes → 8 hex chars (arch deploy §4
 * `envelopeTokenBytes: 4`).
 */
export function envelopeToken(bytes = 4) {
  return randomBytes(bytes).toString('hex');
}

/**
 * Wrap untrusted content so neither the model nor a later log can confuse it
 * with instructions. `meta` lines carry only structured fields.
 *
 * @param {'xmsg'|'retrieved-untrusted'|'memory-untrusted'} kind
 * @param {string} content - already sanitized where applicable
 * @param {Record<string,string|number>} [meta]
 */
export function envelope(kind, content, meta = {}) {
  const token = envelopeToken();
  const open = `<${kind}-${token}>`;
  const close = `</${kind}-${token}>`;
  const lines = [];
  for (const [k, v] of Object.entries(meta)) lines.push(`${k}=${v}`);
  return [open, lines.length ? lines.join(' ') : null, String(content ?? ''), close].filter((x) => x !== null).join('\n');
}

/* ------------------------------------------------------------------ *
 * Outbound redaction (A7 / TM-011)
 * ------------------------------------------------------------------ */

const OUTBOUND_PATTERNS = [
  // absolute host/container paths that reveal the layout
  [/\/(?:home|root|app|workspace|var\/log|run|rw)\/[^\s'"`,)\]]*/g, '[路径已隐藏]'],
  // stack frames
  [/^\s*at\s+.*$/gm, '[堆栈已隐藏]'],
  [/\b(?:Error|Exception|Traceback):[^\n]*/g, '[内部错误]'],
  // env var names that look like credentials
  [/\b[A-Z][A-Z0-9_]{3,}_(?:KEY|TOKEN|SECRET|PASSWORD|DSN)\b/g, '[变量名已隐藏]'],
];

/**
 * Scrub a reply before it leaves the agent zone.
 * @param {string} text
 * @returns {{text: string, hits: Record<string, number>}}
 */
export function redactOutbound(text) {
  const hits = {};
  let out = String(text ?? '');
  for (const [re, replacement] of OUTBOUND_PATTERNS) {
    out = out.replace(re, () => {
      const key = replacement;
      hits[key] = (hits[key] || 0) + 1;
      return replacement;
    });
  }
  return { text: out, hits };
}

/**
 * Detect a secret-class payload that must be refused outright rather than
 * encrypted (memory arch §5.1: storing the owner's password is a design defect,
 * not a crypto problem — same-host KEK gives no isolation, axiom 2).
 *
 * @param {string} body
 * @returns {{refused: boolean, reason?: string}}
 */
export function detectSecretClass(body) {
  if (typeof body !== 'string' || body.length === 0) return { refused: false };
  const labelled = /\b(?:password|passwd|pwd|secret|private[_-]?key|access[_-]?token|api[_-]?key)\s*[:=]\s*\S{6,}/i;
  if (labelled.test(body)) return { refused: true, reason: 'labelled-credential' };
  // PEM/OpenSSH/jwt shapes
  if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(body)) return { refused: true, reason: 'pem-private-key' };
  if (/^eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(body.trim())) return { refused: true, reason: 'jwt-shaped-token' };
  // high-entropy run of >= 32 chars with no spaces
  const runs = body.match(/\S{32,}/g) || [];
  for (const run of runs) {
    if (run.length >= 32 && shannonEntropy(run) >= 4.3) return { refused: true, reason: 'high-entropy-string' };
  }
  return { refused: false };
}
