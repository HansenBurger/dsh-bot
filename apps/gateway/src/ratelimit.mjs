/**
 * ratelimit — E1 flood gates + idempotent dedupe.
 *
 * Three independent budgets, because each stops a different abuse:
 *   - per sender: one spamming account;
 *   - per chat: a group pile-on (one user cannot be blamed for the whole flood, and
 *     the chat budget is what protects the *conversation*);
 *   - global: the agent process itself (MAX_CONCURRENT_RUNS is the downstream bound).
 *
 * Buckets are plain token counters on a fixed 60s window — deliberately not a fancy
 * sliding log: the requirement is "an attacker cannot make us call the LLM without
 * limit", and a bounded-memory counter satisfies that with no growth vector.
 */

import { LruSet } from './lru.mjs';

export class RateLimiter {
  /**
   * @param {{senderPerMin?: number, chatPerMin?: number, globalPerMin?: number, now?: () => number}} [opts]
   */
  constructor(opts = {}) {
    this.senderPerMin = Number(opts.senderPerMin ?? 10);
    this.chatPerMin = Number(opts.chatPerMin ?? 30);
    this.globalPerMin = Number(opts.globalPerMin ?? 60);
    this.now = opts.now ?? (() => Date.now());
    this.windows = new Map();
  }

  #take(bucketKey, limit) {
    const minute = Math.floor(this.now() / 60_000);
    let state = this.windows.get(bucketKey);
    if (!state || state.minute !== minute) {
      // Only one live window per key: the map is bounded by the number of distinct
      // senders/chats, not by message volume.
      state = { minute, count: 0 };
      this.windows.set(bucketKey, state);
    }
    if (state.count >= limit) return { allowed: false, limit };
    state.count += 1;
    return { allowed: true, limit };
  }

  /**
   * @param {{channel:string, chatId:string, userId:string}} ids
   */
  check(ids) {
    const global = this.#take('g:global', this.globalPerMin);
    if (!global.allowed) return { allowed: false, scope: 'global', limit: global.limit };
    const chat = this.#take(`c:${ids.channel}:${ids.chatId}`, this.chatPerMin);
    if (!chat.allowed) return { allowed: false, scope: 'chat', limit: chat.limit };
    const sender = this.#take(`s:${ids.channel}:${ids.userId}`, this.senderPerMin);
    if (!sender.allowed) return { allowed: false, scope: 'sender', limit: sender.limit };
    return { allowed: true };
  }

  /** Drop windows for principals that stopped talking (called from the housekeeping job). */
  sweep(nowMs) {
    const minute = Math.floor((nowMs ?? this.now()) / 60_000);
    for (const [key, state] of this.windows) if (state.minute < minute - 1) this.windows.delete(key);
    return this.windows.size;
  }
}

/**
 * Dedupe on the *adapter's* message id. Reverse-WS reconnects make OneBot clients
 * re-deliver the last few events; without this the bot answers the same message
 * twice, which is the most visible failure mode a user can hit.
 */
export class Dedupe {
  constructor({ maxEntries = 4096 } = {}) {
    this.seen = new LruSet(maxEntries);
    this.hits = 0;
  }

  /** @returns {boolean} true when this key has already been processed */
  isDuplicate(key) {
    if (this.seen.has(key)) {
      this.hits += 1;
      return true;
    }
    this.seen.add(key);
    return false;
  }
}
