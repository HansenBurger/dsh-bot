/**
 * whitelist — the A1 gate: default-deny on structured ids, decided BEFORE the LLM.
 *
 * Two rules the whole pipeline depends on:
 *
 *   1. Only `(channel, chat_id, user_id)` is consulted. Display names (`nickname`,
 *      `card`, TG `first_name`) are dropped during normalization and are *never* a
 *      key here — the same human can rename themselves to the owner's nickname on a
 *      QQ group, and A2 exists precisely because that trick must not work.
 *   2. Fail closed: an unreadable/invalid policy file is a startup error, and an
 *      entry that does not match yields `role=public`, which the submit hop refuses
 *      outright (U1). There is no "unknown ⇒ try anyway" path.
 *
 * The shape mirrors the security baseline (docs/security/t2-security-baseline.md A1)
 * and is loaded from a read-only mount so the agent can never widen its own audience.
 */

export const ROLES = Object.freeze(['owner', 'trusted']);

/** The channels the normalizer can actually produce; a typo here must not linger. */
export const CHANNELS = Object.freeze(['onebot', 'telegram']);

export class WhitelistError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

/**
 * @param {unknown} raw - parsed policy JSON
 * @returns {{entries: Array<object>, byKey: Map<string, object>, defaultRole: string}}
 */
export function compileWhitelist(raw) {
  if (!raw || typeof raw !== 'object') throw new WhitelistError('POLICY_INVALID', 'whitelist policy must be an object');
  const entries = Array.isArray(raw.entries) ? raw.entries : null;
  if (!entries) throw new WhitelistError('POLICY_INVALID', 'whitelist policy needs an entries[] array');
  const defaultRole = raw.defaultRole === 'public' || raw.defaultRole === undefined ? 'public' : raw.defaultRole;
  // Anything but `public` as the default would make the whole gate meaningless.
  if (defaultRole !== 'public') throw new WhitelistError('POLICY_INVALID', `defaultRole must be public, got ${defaultRole}`);

  const byKey = new Map();
  entries.forEach((e, i) => {
    for (const field of ['channel', 'chatId', 'userId']) {
      if (typeof e[field] !== 'string' || e[field].length === 0 || e[field].length > 128) {
        throw new WhitelistError('POLICY_INVALID', `entries[${i}].${field} must be a non-empty string (<=128)`);
      }
    }
    if (!CHANNELS.includes(e.channel)) throw new WhitelistError('POLICY_INVALID', `entries[${i}].channel must be one of ${CHANNELS.join('|')}`);
    if (!ROLES.includes(e.role)) throw new WhitelistError('POLICY_INVALID', `entries[${i}].role must be owner|trusted`);
    const key = keyOf(e.channel, e.chatId, e.userId);
    if (byKey.has(key)) throw new WhitelistError('POLICY_INVALID', `duplicate entry at index ${i} for ${key}`);
    byKey.set(key, Object.freeze({ channel: e.channel, chatId: e.chatId, userId: e.userId, role: e.role, note: e.note }));
  });

  // Owner discipline. Two shapes have to be told apart:
  //   * two owner rows in the SAME channel — someone widened who may delete memory, so
  //     this is a hard policy error;
  //   * one owner row per channel (QQ DM + Telegram DM in the shipped sample, where the
  //     conversation is on QQ and approval notices arrive on Telegram) — legitimate.
  // Id spaces are not comparable across channels, so a second owner on another channel
  // cannot be proven to be a second human: it compiles, but the boot log says so.
  const owners = [...byKey.values()].filter((e) => e.role === 'owner');
  const ownersPerChannel = new Map();
  for (const owner of owners) {
    ownersPerChannel.set(owner.channel, (ownersPerChannel.get(owner.channel) || 0) + 1);
  }
  for (const [channel, count] of ownersPerChannel) {
    if (count > 1) throw new WhitelistError('POLICY_INVALID', `at most one owner entry per channel is allowed, found ${count} on ${channel}`);
  }
  const warnings = [];
  const ownerIds = new Set(owners.map((e) => e.userId));
  if (ownerIds.size > 1) {
    warnings.push(`${ownerIds.size} owner entries on ${ownerIds.size} distinct ids (${[...ownersPerChannel.keys()].join(', ')}): confirm they are the same human`);
  }

  return Object.freeze({ entries: Object.freeze(entries.map((e) => byKey.get(keyOf(e.channel, e.chatId, e.userId)))), byKey, defaultRole, warnings: Object.freeze(warnings) });
}

const keyOf = (channel, chatId, userId) => `${channel}|${chatId}|${userId}`;

/**
 * Decide one inbound message.
 * @param {{byKey: Map<string, object>}} policy
 * @param {{channel:string, chatId:string, userId:string}} ids - structured only
 * @returns {{allow: boolean, role: string, reason?: string}}
 */
export function decide(policy, ids) {
  const entry = policy.byKey.get(keyOf(ids.channel, String(ids.chatId), String(ids.userId)));
  if (!entry) {
    return { allow: false, role: 'public', reason: 'not-whitelisted' };
  }
  return { allow: true, role: entry.role };
}

/**
 * A degraded stack answers with a fixed line instead of an LLM call (E2/E3): the
 * flag is written by the watcher, read-only from the gateway's point of view.
 */
export function degradedReply(readFlag) {
  return { text: '伴侣暂时处于只读降级状态（安全熔断已触发），请稍后再试。', degraded: Boolean(readFlag) };
}
