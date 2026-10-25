/**
 * @dsh-bot/bot-normalize
 *
 * Unified internal message model (t3-integration-architecture §5.4 / D-05).
 * Both protocol ends (OneBot 11, Telegram) map into `NormalizedMessage` exactly
 * once; business logic never touches a raw provider event.
 *
 * Design rules carried by this module — they are security constraints, not style:
 *  - C-03 / A2: authorization only ever reads structured ids. `displayName` is
 *    accepted for rendering and **never** participates in any decision; the OB11
 *    `nickname` field is dropped during normalization (see §9.1 of arch doc).
 *  - C-23: strict parsing. Unknown fields, JSON5 syntax (comments, trailing
 *    commas, unquoted keys) and enum values outside the closed vocabulary are
 *    rejected instead of tolerated — NapCat ≥ v4.4.14 parses request-side JSON5,
 *    so accepting it here would open a parser differential.
 *  - Closed vocabularies are exported as frozen arrays so callers can validate
 *    against the same list the types describe.
 *
 * Zero dependencies: this is the leaf of the workspace graph.
 */

export const CHANNELS = Object.freeze(['telegram', 'onebot']);
export const PEER_KINDS = Object.freeze(['dm', 'group', 'channel']);

/** t3 arch §5.3.2 + memory RiskTag enum (openapi components/schemas/RiskTag). */
export const RISK_TAGS = Object.freeze([
  'instruction-override',
  'encoded-payload',
  'zero-width',
  'credential-path',
  'offallowlist-url',
  'oversize',
  'unknown-segment',
  'memory-poison-suspect',
]);

export const SEGMENT_ALLOWLIST = Object.freeze(['text', 'at', 'image', 'face', 'record', 'video', 'file', 'json', 'location']);
export const INBOUND_PART_KINDS = Object.freeze(['image', 'file', 'audio', 'video', 'location', 'poll']);

/** Closed error-code vocabulary from openapi components/schemas/Error. */
export const ERROR_CODES = Object.freeze([
  'BAD_REQUEST', 'UNKNOWN_FIELD', 'UNKNOWN_CLASS', 'UNAUTHENTICATED', 'NONCE_REPLAY',
  'FORBIDDEN_ROLE', 'ACL_DENIED', 'PEER_BOUNDARY_VIOLATION', 'APPROVAL_REQUIRED',
  'APPROVAL_INVALID', 'MEMORY_REFUSED_CATEGORY', 'SANITIZED_EMPTY', 'IDEMPOTENCY_CONFLICT',
  'BODY_TOO_LARGE', 'RATE_LIMITED', 'DEPENDENCY_UNAVAILABLE', 'DEGRADED_HALT', 'INTERNAL',
]);

export class NormalizeError extends Error {
  /**
   * @param code - one of {@link ERROR_CODES}
   * @param message - human text; must not echo attacker payload (D5)
   * @param details - safe structural hints only (field name, index), never content
   */
  constructor(code, message, details) {
    super(message);
    this.name = 'NormalizeError';
    this.code = ERROR_CODES.includes(code) ? code : 'BAD_REQUEST';
    this.details = details;
  }
}

function assert(condition, code, message, details) {
  if (!condition) throw new NormalizeError(code, message, details);
}

const MAX_TEXT_CHARS = 8000;
const MAX_ID_CHARS = 128;

/**
 * Strict JSON parser: rejects anything JSON.parse would not accept (JSON5) and
 * additionally rejects duplicate object keys, which JSON.parse silently folds —
 * a classic parser-differential trick.
 *
 * Duplicate detection cannot use `JSON.parse(text, reviver)`: the spec calls the
 * reviver once per key **after** construction, so a repeated key never appears
 * twice in that stream. It needs own-property order, hence this small scanner.
 *
 * @param {string} source
 * @returns {any}
 */
export function parseStrictJson(source) {
  assert(typeof source === 'string', 'BAD_REQUEST', 'frame is not a string');
  assert(source.length > 0, 'BAD_REQUEST', 'empty frame');
  assert(source.length <= 64 * 1024, 'BODY_TOO_LARGE', 'frame exceeds 64 KiB');
  // Reject BOM: JSON5 tolerates it, JSON.parse does not, and a leading byte can
  // shift a downstream fingerprint check.
  assert(!source.startsWith('﻿'), 'BAD_REQUEST', 'byte-order-mark not allowed');

  try {
    walkStrict(source, { index: 0 });
  } catch (err) {
    throw new NormalizeError('BAD_REQUEST', 'frame is not strictly valid JSON', { reason: String(err.message).slice(0, 120) });
  }
  let value;
  try {
    value = JSON.parse(source);
  } catch (err) {
    throw new NormalizeError('BAD_REQUEST', 'frame is not strictly valid JSON', { reason: String(err.message).slice(0, 120) });
  }
  assert(isJsonValue(value), 'BAD_REQUEST', 'frame is not a JSON value');
  return value;
}

/* ---------------- strict JSON scanner (structure + duplicate keys) --------- */

const WS = new Set([' ', '\t', '\n', '\r']);

function skipWs(s, i) {
  while (i.index < s.length && WS.has(s[i.index])) i.index += 1;
}

function expect(s, i, ch) {
  if (s[i.index] !== ch) fail(`expected ${ch} at ${i.index}`);
  i.index += 1;
}

function fail(msg) {
  const e = new Error(msg);
  e.isSyntaxError = true;
  throw e;
}

function walkValue(s, i, depth) {
  if (depth > 64) fail('nesting too deep');
  skipWs(s, i);
  const c = s[i.index];
  if (c === '{') return walkObject(s, i, depth + 1);
  if (c === '[') return walkArray(s, i, depth + 1);
  if (c === '"') { walkString(s, i); return; }
  if (c === 't') return literal(s, i, 'true');
  if (c === 'f') return literal(s, i, 'false');
  if (c === 'n') return literal(s, i, 'null');
  if (c === '-' || (c >= '0' && c <= '9')) return walkNumber(s, i);
  fail(`unexpected character ${JSON.stringify(c)} at ${i.index}`);
}

function literal(s, i, word) {
  if (s.slice(i.index, i.index + word.length) !== word) fail(`bad literal at ${i.index}`);
  i.index += word.length;
}

function walkNumber(s, i) {
  const start = i.index;
  if (s[i.index] === '-') i.index += 1;
  if (s[i.index] === '0') {
    i.index += 1;
  } else if (s[i.index] >= '1' && s[i.index] <= '9') {
    while (i.index < s.length && s[i.index] >= '0' && s[i.index] <= '9') i.index += 1;
  } else {
    fail(`bad number at ${start}`);
  }
  if (s[i.index] === '.') {
    i.index += 1;
    if (!(s[i.index] >= '0' && s[i.index] <= '9')) fail(`bad number at ${start}`);
    while (i.index < s.length && s[i.index] >= '0' && s[i.index] <= '9') i.index += 1;
  }
  if (s[i.index] === 'e' || s[i.index] === 'E') {
    i.index += 1;
    if (s[i.index] === '+' || s[i.index] === '-') i.index += 1;
    if (!(s[i.index] >= '0' && s[i.index] <= '9')) fail(`bad number at ${start}`);
    while (i.index < s.length && s[i.index] >= '0' && s[i.index] <= '9') i.index += 1;
  }
  // Leading +, hex/octal/binary literals, Infinity and NaN are JSON5-isms.
  const raw = s.slice(start, i.index);
  if (!/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/.test(raw)) fail(`bad number ${raw}`);
}

function walkString(s, i) {
  if (s[i.index] !== '"') fail(`bad string at ${i.index}`);
  i.index += 1;
  while (i.index < s.length) {
    const c = s[i.index];
    if (c === '"') {
      i.index += 1;
      return;
    }
    if (c === '\\') {
      const n = s[i.index + 1];
      if (!['"', '\\', '/', 'b', 'f', 'n', 'r', 't', 'u'].includes(n)) fail(`bad escape at ${i.index}`);
      if (n === 'u') {
        if (!/^[0-9a-fA-F]{4}$/.test(s.slice(i.index + 2, i.index + 6))) fail(`bad unicode escape at ${i.index}`);
        i.index += 6;
      } else {
        i.index += 2;
      }
      continue;
    }
    const code = c.charCodeAt(0);
    if (code < 0x20) fail(`unescaped control character at ${i.index}`);
    i.index += 1;
  }
  fail('unterminated string');
}

function walkObject(s, i, depth) {
  expect(s, i, '{');
  const keys = new Set();
  skipWs(s, i);
  if (s[i.index] === '}') {
    i.index += 1;
    return;
  }
  for (;;) {
    skipWs(s, i);
    const keyStart = i.index;
    walkString(s, i);
    const key = JSON.parse(s.slice(keyStart, i.index));
    if (keys.has(key)) fail(`duplicate key ${key}`);
    keys.add(key);
    skipWs(s, i);
    expect(s, i, ':');
    walkValue(s, i, depth);
    skipWs(s, i);
    const c = s[i.index];
    if (c === ',') {
      i.index += 1;
      continue;
    }
    if (c === '}') {
      i.index += 1;
      return;
    }
    fail(`expected , or } at ${i.index}`);
  }
}

function walkArray(s, i, depth) {
  expect(s, i, '[');
  skipWs(s, i);
  if (s[i.index] === ']') {
    i.index += 1;
    return;
  }
  for (;;) {
    walkValue(s, i, depth);
    skipWs(s, i);
    const c = s[i.index];
    if (c === ',') {
      i.index += 1;
      continue;
    }
    if (c === ']') {
      i.index += 1;
      return;
    }
    fail(`expected , or ] at ${i.index}`);
  }
}

function walkStrict(text, i) {
  walkValue(text, i, 0);
  skipWs(text, i);
  if (i.index !== text.length) fail(`trailing content at ${i.index}`);
}

function isJsonValue(v) {
  if (v === null) return true;
  const t = typeof v;
  if (t === 'boolean' || t === 'number') return Number.isFinite(v);
  if (t === 'string') return true;
  if (Array.isArray(v)) return v.every(isJsonValue);
  if (t === 'object') return Object.values(v).every(isJsonValue);
  return false;
}

/**
 * Reject unknown properties (C-23 posture: no lenient parsing anywhere).
 * @param {object} obj
 * @param {string[]} known
 * @param {string} where - label used in the error detail (field name only)
 */
export function rejectUnknownFields(obj, known, where) {
  assert(obj && typeof obj === 'object' && !Array.isArray(obj), 'BAD_REQUEST', `${where} must be an object`);
  const extra = Object.keys(obj).filter((k) => !known.includes(k));
  assert(extra.length === 0, 'UNKNOWN_FIELD', `${where} carries unknown field(s)`, { fields: extra.slice(0, 8) });
  return obj;
}

function str(v, field, max = MAX_ID_CHARS, required = true) {
  if (v === undefined || v === null) {
    assert(!required, 'BAD_REQUEST', `${field} required`);
    return undefined;
  }
  // OB11 sends numeric ids as JSON numbers; canonicalise to string, never trust
  // display text as an identifier.
  const s = typeof v === 'number' ? String(v) : typeof v === 'bigint' ? String(v) : v;
  assert(typeof s === 'string', 'BAD_REQUEST', `${field} must be a string or number`, { type: typeof v });
  assert(s.length > 0 && s.length <= max, 'BAD_REQUEST', `${field} length out of range`);
  return s;
}

/**
 * peerKey is the stable routing key for session mapping (D-06): one DSH Session
 * per `(channel, chat_id)`. Format matches the DB CHECK on subject.subject_key:
 *   telegram:dm:111 | onebot:group:123456 | onebot:channel:9
 * @param {{kind:string, chatId:string}} peer
 * @param {string} channel
 */
export function buildPeerKey(channel, peer) {
  return `${channel}:${peer.kind}:${peer.chatId}`;
}

/**
 * Parse one OneBot v11 event frame into NormalizedMessage(s).
 *
 * Only `post_type ∈ {message, meta_event, notice, request}` is accepted (§5.2
 * step 4). Group/private messages require `sender.user_id`; the QQ-side
 * `sender.nickname` / `card` are dropped here so they cannot reach a decision
 * even by accident (A2).
 *
 * @param {unknown} raw - already strictly parsed JSON value
 * @param {{expectedSelfId?: string, receivedAt?: number}} [opts]
 * @returns {{messages: object[], selfId: string|undefined, postType: string}}
 */
export function inboundOnebot(raw, opts = {}) {
  assert(raw && typeof raw === 'object' && !Array.isArray(raw), 'BAD_REQUEST', 'OB11 frame must be an object');
  const frame = /** @type {Record<string, any>} */ (raw);

  const postType = str(frame.post_type, 'post_type', 32);
  assert(['message', 'meta_event', 'notice', 'request'].includes(postType), 'BAD_REQUEST', 'unsupported post_type', { postType });

  const selfId = frame.self_id === undefined ? undefined : str(frame.self_id, 'self_id', 32);
  if (opts.expectedSelfId !== undefined && selfId !== undefined) {
    assert(selfId === opts.expectedSelfId, 'UNAUTHENTICATED', 'self_id does not match the expected account');
  }

  const receivedAt = opts.receivedAt ?? Date.now();
  if (postType !== 'message') {
    return { messages: [], selfId, postType };
  }

  const messageType = str(frame.message_type, 'message_type', 16);
  assert(['private', 'group'].includes(messageType), 'BAD_REQUEST', 'unsupported message_type', { messageType });

  const kind = messageType === 'group' ? 'group' : 'dm';
  const chatId = str(messageType === 'group' ? frame.group_id : frame.user_id, 'chat id');
  const userId = str(frame.user_id, 'user_id');
  const messageId = str(frame.message_id, 'message_id', 64);

  assert(Array.isArray(frame.message), 'BAD_REQUEST', 'message segments must be an array');

  const parts = [];
  const riskTags = new Set();
  let text = '';
  let atBot = false;
  let replyTo;

  for (const seg of frame.message) {
    assert(seg && typeof seg === 'object' && typeof seg.type === 'string', 'BAD_REQUEST', 'malformed segment');
    const data = seg.data && typeof seg.data === 'object' ? seg.data : {};
    switch (seg.type) {
      case 'text': {
        const t = typeof data.text === 'string' ? data.text : '';
        text += t;
        break;
      }
      case 'at': {
        // Collapse to a boolean only when it mentions our own account; a group
        // member mention is not an address to the bot.
        if (selfId !== undefined && String(data.qq) === String(selfId)) atBot = true;
        break;
      }
      case 'image':
      case 'face':
        parts.push({ kind: 'image', ref: str(data.url || data.file, 'media ref', 512, false), file_id: data.file_id });
        break;
      case 'record':
        parts.push({ kind: 'audio', ref: str(data.url || data.file, 'media ref', 512, false), file_id: data.file_id });
        break;
      case 'video':
        parts.push({ kind: 'video', ref: str(data.url || data.file, 'media ref', 512, false), file_id: data.file_id });
        break;
      case 'file':
        parts.push({ kind: 'file', ref: str(data.url || data.file, 'media ref', 512, false), name: data.name, file_id: data.file_id });
        break;
      case 'location':
        parts.push({ kind: 'location', lat: data.lat, lon: data.lon, title: data.title });
        break;
      case 'json':
      default:
        // Segment types outside the allowlist are dropped but always tagged —
        // A6: never silently discard, otherwise an attacker can bisect the rules.
        riskTags.add('unknown-segment');
        break;
    }
  }

  if (frame.reply && typeof frame.reply === 'object' && frame.reply.message_id !== undefined) {
    replyTo = str(frame.reply.message_id, 'reply.message_id', 64);
  }

  text = text.slice(0, MAX_TEXT_CHARS);
  if (text.length === MAX_TEXT_CHARS) riskTags.add('oversize');

  const message = buildNormalized({
    channel: 'onebot',
    peer: { kind, chatId },
    sender: { userId },
    atBot,
    replyTo,
    text,
    parts,
    rawRef: { messageId, seq: frame.seq === undefined ? 0 : Number(frame.seq) || 0 },
    riskTags: [...riskTags],
    receivedAt,
  });

  return { messages: [message], selfId, postType };
}

/**
 * Build + validate a NormalizedMessage. This is the single choke point through
 * which every inbound byte passes after the gate; anything malformed here is a
 * bug, not a policy decision.
 * @param {object} input
 */
export function buildNormalized(input) {
  assert(CHANNELS.includes(input.channel), 'BAD_REQUEST', 'unknown channel', { channel: input.channel });
  assert(PEER_KINDS.includes(input.peer?.kind), 'BAD_REQUEST', 'unknown peer kind', { kind: input.peer?.kind });
  const chatId = str(input.peer.chatId, 'peer.chatId');
  const userId = str(input.sender?.userId, 'sender.userId');
  assert(typeof input.text === 'string', 'BAD_REQUEST', 'text must be a string');
  assert(input.text.length <= MAX_TEXT_CHARS, 'BAD_REQUEST', 'text too long');

  const tags = Array.isArray(input.riskTags) ? input.riskTags : [];
  for (const t of tags) assert(RISK_TAGS.includes(t), 'BAD_REQUEST', 'unknown risk tag', { tag: t });

  const parts = Array.isArray(input.parts) ? input.parts : [];
  for (const p of parts) assert(INBOUND_PART_KINDS.includes(p.kind), 'BAD_REQUEST', 'unknown part kind', { kind: p.kind });

  const messageId = str(input.rawRef?.messageId, 'rawRef.messageId', 64);
  return Object.freeze({
    v: 1,
    id: `${input.channel}:${messageId}`,
    channel: input.channel,
    peer: Object.freeze({ kind: input.peer.kind, chatId, threadId: input.peer.threadId }),
    sender: Object.freeze({ userId }),
    atBot: Boolean(input.atBot),
    replyTo: input.replyTo,
    text: input.text,
    parts: Object.freeze(parts),
    rawRef: Object.freeze({ messageId, seq: Number(input.rawRef?.seq) || 0 }),
    riskTags: Object.freeze([...new Set(tags)]),
    receivedAt: Number(input.receivedAt) || Date.now(),
  });
}

/**
 * Peer key used for dedupe/session routing/audit references. Never contains
 * display text.
 * @param {object} msg - NormalizedMessage
 */
export function peerKeyOf(msg) {
  return buildPeerKey(msg.channel, msg.peer);
}

/** Stable idempotency/dedupe key for a normalized message. */
export function dedupeKeyOf(msg) {
  return `${peerKeyOf(msg)}#${msg.rawRef.messageId}`;
}

/* ------------------------------------------------------------------ *
 * Outbound
 * ------------------------------------------------------------------ */

export const OUTBOUND_KINDS = Object.freeze(['text', 'image', 'file', 'reply', 'buttons', 'react']);

/**
 * Validate an OutboundPart[] before it reaches an adapter.
 * @param {Array<object>} parts
 */
export function assertOutboundParts(parts) {
  assert(Array.isArray(parts), 'BAD_REQUEST', 'parts must be an array');
  for (const p of parts) {
    assert(OUTBOUND_KINDS.includes(p.kind), 'BAD_REQUEST', 'unknown outbound kind', { kind: p.kind });
    if (p.kind === 'text') assert(typeof p.text === 'string', 'BAD_REQUEST', 'text part needs text');
    if (p.kind === 'buttons') {
      assert(Array.isArray(p.buttons) && p.buttons.length > 0, 'BAD_REQUEST', 'buttons part needs buttons');
      for (const b of p.buttons) assert(typeof b?.id === 'string' && typeof b?.label === 'string', 'BAD_REQUEST', 'malformed button');
    }
  }
  return parts;
}

/**
 * Split a long reply to a channel's character budget without cutting surrogate
 * pairs. Used because capability negotiation (not lowest-common-denominator) is
 * the design contract (arch §5.4).
 * @param {string} text
 * @param {number} maxChars
 * @returns {string[]}
 */
export function chunkText(text, maxChars) {
  assert(Number.isInteger(maxChars) && maxChars > 0, 'BAD_REQUEST', 'maxChars must be positive');
  if (text.length <= maxChars) return [text];
  const out = [];
  let buf = '';
  for (const ch of text) {
    if ((buf + ch).length > maxChars) {
      out.push(buf);
      buf = ch;
    } else {
      buf += ch;
    }
  }
  if (buf) out.push(buf);
  return out;
}
