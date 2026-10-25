/**
 * llm — the companion turn loop for the container's standalone intake plane.
 *
 * This is the piece that makes `BOT_CORE_MODE=llm` real: an inbound QQ message becomes a
 * model call **through the secret broker's LLM egress proxy**, tool calls are executed
 * with the very same tool objects the DSH plugin registers (`createMemoryTools`), and a
 * durable memory write still requires the owner's decision, taken in the owner's private
 * chat (C-10).
 *
 * Credential boundary, restated because it is the whole point:
 *   - this process holds only `x-broker-token` (an enrollment token) and the opaque ref
 *     name `llm-key`; it never reads, receives, or logs the API key. The broker strips any
 *     `authorization` header we send and injects the real one itself.
 *   - proof, not assertion: `GET /v1/secret/llm-key` from this container is denied by
 *     broker policy (`NEVER_RESOLVE`), and no key file is mounted here at all.
 *
 * What this is *not*: it is not the DSH host agent loop. The `dsh` compose service behind
 * profile `agent` would run `dsh --profile bot headless` with this plugin attached; that
 * path needs a provider credential at boot, a persona/agent-preset layer t3 only sketched,
 * and it collides with the host GUI on 127.0.0.1:3080. Until then this file is the honest
 * stand-in, and the deviation is recorded in the README.
 */

import { randomBytes } from 'node:crypto';
import { envelope, redactOutbound } from '@dsh-bot/bot-sanitize';
import { createMemoryTools, createMemoryGuard, MEMORY_HANDLING_PROMPT, PERSONA_PROMPT } from './index.mjs';

/** A deferral, not a denial: the human decision is pending, so nothing is written yet. */
export class ApprovalDeferred extends Error {
  constructor(pending) {
    super('approval-deferred');
    this.name = 'ApprovalDeferred';
    this.pending = pending;
  }
}

const APPROVE_WORDS = new Set(['同意', '批准', '确认', '可以', '好的', '好', 'yes', 'y', 'ok']);
const DENY_WORDS = new Set(['拒绝', '不同意', '不用', '取消', '算了', 'no', 'n']);

/**
 * Exact-word matching, deliberately. A substring scan ("消息里有'同意'就算批准") would let
 * any chat content — including text retrieved from memory, or a sentence like
 * "不同意" — mint an approval. So: normalise whitespace, strip trailing punctuation, and
 * compare the *whole* message.
 */
export function approvalWord(text) {
  const norm = String(text ?? '').trim().toLowerCase().replace(/[。！!？?，,.\s]+$/g, '');
  if (!norm || norm.length > 12) return null; // a long message is never a bare approval
  if (DENY_WORDS.has(norm)) return 'denied';
  if (APPROVE_WORDS.has(norm)) return 'approved';
  return null;
}

/** One pending approval per conversation; unanswered ones expire and never write. */
export class ApprovalQueue {
  constructor({ ttlMs = 300_000, audit, now = () => Date.now() } = {}) {
    this.ttlMs = ttlMs;
    this.audit = audit;
    this.now = now;
    this.byChat = new Map();
  }

  key(principal) {
    return `${principal.channel}:${principal.chatId}`;
  }

  create({ principal, toolName, args, note }) {
    const key = this.key(principal);
    const existing = this.peek(key);
    if (existing) {
      // Two simultaneous asks in one chat would make "同意" ambiguous about *which* write
      // it authorises, so the second one is refused rather than queued.
      this.audit.emit('approval.outcome', { stage: 'coalesced', result: 'denied', reason: 'pending-exists', toolName, chatKey: key });
      return null;
    }
    const pending = {
      id: `appr-${randomBytes(8).toString('hex')}`,
      toolName,
      args,
      note,
      principal,
      expiresAt: this.now() + this.ttlMs,
      createdAt: this.now(),
    };
    this.byChat.set(key, pending);
    this.audit.emit('approval.outcome', { stage: 'requested', approvalId: pending.id, toolName, chatKey: key, ttlMs: this.ttlMs, note });
    return pending;
  }

  /** The live pending for this chat, expiring it as a side effect if it has gone stale. */
  peek(key) {
    const pending = this.byChat.get(key);
    if (!pending) return null;
    if (this.now() > pending.expiresAt) {
      this.byChat.delete(key);
      this.audit.emit('approval.outcome', { stage: 'expired', result: 'denied', approvalId: pending.id, toolName: pending.toolName, chatKey: key, waitedMs: this.now() - pending.createdAt });
      return null;
    }
    return pending;
  }

  take(key, decision) {
    const pending = this.peek(key);
    if (!pending) return null;
    this.byChat.delete(key);
    this.audit.emit('approval.outcome', { stage: 'decided', approvalId: pending.id, toolName: pending.toolName, chatKey: key, decision, waitedMs: this.now() - pending.createdAt });
    return pending;
  }
}

/**
 * OpenAI-compatible client for the broker's LLM egress. Content never goes into the audit
 * sink — only counts, status, latency, and token usage.
 */
export class BrokerLlmClient {
  constructor({ brokerUrl, token, model = 'deepseek-flash', audit, fetchImpl = globalThis.fetch, timeoutMs = 60_000 } = {}) {
    if (!brokerUrl) throw new Error('llm: brokerUrl is required (the agent has no direct WAN route by design)');
    if (!token) throw new Error('llm: enrollment token is required');
    this.brokerUrl = String(brokerUrl).replace(/\/+$/, '');
    this.token = token;
    this.model = model;
    this.audit = audit;
    this.fetch = fetchImpl;
    this.timeoutMs = timeoutMs;
    this.calls = 0;
  }

  /** @returns {Promise<{message: object, toolCalls: array, finishReason: string}>} */
  async chat({ messages, tools }) {
    this.calls += 1;
    const started = Date.now();
    let res;
    try {
      res = await this.fetch(`${this.brokerUrl}/v1/llm/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-broker-token': this.token },
        body: JSON.stringify({ model: this.model, messages, ...(tools && tools.length ? { tools, tool_choice: 'auto' } : {}), stream: false }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (err) {
      this.audit.emit('llm.call', { result: 'error', reason: 'egress-failed', model: this.model, call: this.calls, ms: Date.now() - started, message: String(err.message).slice(0, 120) });
      throw err;
    }
    const text = await res.text();
    if (!res.ok) {
      // The upstream error body is echoed to the audit as a truncated, credential-free
      // fragment: DeepSeek's 4xx bodies name the model and the quota, never the key.
      this.audit.emit('llm.call', { result: 'error', reason: `upstream-${res.status}`, model: this.model, call: this.calls, ms: Date.now() - started, detail: text.slice(0, 160) });
      throw Object.assign(new Error(`llm upstream ${res.status}`), { status: res.status, detail: text.slice(0, 160) });
    }
    let json;
    try {
      json = JSON.parse(text);
    } catch {
      this.audit.emit('llm.call', { result: 'error', reason: 'unparseable', model: this.model, call: this.calls, ms: Date.now() - started });
      throw new Error('llm: upstream returned a non-JSON body');
    }
    const choice = json.choices?.[0] ?? {};
    const message = choice.message ?? {};
    this.audit.emit('llm.call', {
      result: 'allowed',
      model: this.model,
      call: this.calls,
      finishReason: choice.finish_reason ?? null,
      toolCalls: (message.tool_calls || []).length,
      contentChars: String(message.content ?? '').length,
      promptTokens: json.usage?.prompt_tokens ?? null,
      completionTokens: json.usage?.completion_tokens ?? null,
      ms: Date.now() - started,
    });
    return { message, toolCalls: message.tool_calls || [], finishReason: choice.finish_reason ?? null };
  }
}

/** DSH's compact parameter map → the JSON Schema OpenAI-compatible endpoints expect. */
export function toToolSchema(tool) {
  const properties = {};
  const required = [];
  for (const [name, spec] of Object.entries(tool.parameters || {})) {
    const entry = { type: spec.type || 'string', description: spec.description || '' };
    if (spec.enum) entry.enum = spec.enum;
    if (spec.items) entry.items = { type: spec.items.type || 'string' };
    if (spec.const) entry.const = spec.const;
    properties[name] = entry;
    if (spec.required) required.push(name);
  }
  return { type: 'function', function: { name: tool.name, description: tool.description, parameters: { type: 'object', properties, ...(required.length ? { required } : {}), additionalProperties: false } } };
}

/**
 * The turn loop. `turn()` answers one inbound message; `resolvePending()` continues a
 * write that the owner just approved — without a second model call, because the decision
 * (not the wording) is what was pending.
 */
export class CompanionLoop {
  constructor({ llm, memory, audit, principalOf = () => null, bindPrincipal, approvals, maxRounds = 3, historyLimit = 10, subjectHint }) {
    this.llm = llm;
    this.audit = audit;
    this.approvals = approvals || new ApprovalQueue({ audit });
    this.maxRounds = maxRounds;
    this.subjectHint = subjectHint;
    this.history = new Map();
    this.historyLimit = historyLimit;
    this.memoryRef = { client: null };
    const deps = {
      memory: () => {
        if (!this.memoryRef.client && memory) this.memoryRef.client = memory;
        if (!this.memoryRef.client) throw new Error('bot-core: memory client unavailable');
        return this.memoryRef.client;
      },
      currentPrincipal: principalOf,
      approve: async ({ toolName, args, note, exec }) => {
        // On the approval-continuation path the human decision has already been taken and
        // audited (resolvePending), and the exec object is built by *this* loop, never by
        // the model — so the token travels instead of a second prompt. A tool call arriving
        // straight from the model always has `exec.approvalId === undefined`.
        if (exec?.approvalId) return exec.approvalId;
        const principal = principalOf();
        const pending = this.approvals.create({ principal, toolName, args, note });
        if (!pending) throw new Error('等待中的确认还没回答，先处理那条。');
        throw new ApprovalDeferred(pending);
      },
    };
    const built = createMemoryTools(deps);
    this.tools = [built.searchTool(), built.readTool(), built.writeTool(), built.forgetTool()];
    this.byName = new Map(this.tools.map((t) => [t.name, t]));
    this.guard = createMemoryGuard(principalOf);
    this.bindPrincipal = bindPrincipal;
  }

  systemMessages(principal) {
    const subject = principal ? this.subjectHint?.(principal) : '';
    return [
      { role: 'system', content: PERSONA_PROMPT },
      { role: 'system', content: MEMORY_HANDLING_PROMPT },
      ...(subject ? [{ role: 'system', content: `当前会话主体 subjectKey = ${subject}（写入长期记忆时用这个值，不要自己拼别的）。` }] : []),
    ];
  }

  historyKey(principal) {
    return `${principal.channel}:${principal.peerKind}:${principal.chatId}:${principal.userId}`;
  }

  remember(key, messages) {
    const keep = messages.filter((m) => m.role !== 'system').slice(-this.historyLimit);
    this.history.set(key, keep);
    while (this.history.size > 200) this.history.delete(this.history.keys().next().value);
  }

  /**
   * Replace the "本轮未执行" placeholder the deferral left in the stored history with how the
   * conversation actually ended. Without this the next turn still reads as if the owner had
   * not answered, and the companion refuses to recall a fact it had just been handed.
   */
  settlePendingCall(key, callId, text) {
    if (!callId) return false;
    const messages = this.history.get(key) || [];
    const at = messages.findIndex((m) => m.role === 'tool' && m.tool_call_id === callId);
    if (at < 0) return false;
    const next = messages.slice();
    next[at] = { ...next[at], content: envelope('tool-outcome', text) };
    this.history.set(key, next);
    return true;
  }

  /**
   * @param {{text: string, principal: object}} input
   * @returns {Promise<{reply: string, pending: boolean, calls: number, error?: string}>}
   */
  async turn({ text, principal }) {
    if (this.bindPrincipal) this.bindPrincipal(principal);
    const key = this.historyKey(principal);
    const messages = [...this.systemMessages(principal), ...(this.history.get(key) || []), { role: 'user', content: String(text ?? '').slice(0, 4000) }];
    const callsBefore = this.llm.calls;

    for (let round = 0; round < this.maxRounds; round += 1) {
      let result;
      try {
        result = await this.llm.chat({ messages, tools: this.tools.map(toToolSchema) });
      } catch (err) {
        return { reply: '我现在连不上模型，稍后再试。', pending: false, calls: this.llm.calls - callsBefore, error: err.message };
      }
      const callList = result.toolCalls;
      messages.push({ role: 'assistant', content: result.message.content ?? '', ...(callList.length ? { tool_calls: callList } : {}) });
      if (!callList.length) {
        const reply = this.finalize(result.message.content);
        this.remember(key, messages);
        return { reply, pending: false, calls: this.llm.calls - callsBefore };
      }
      for (let i = 0; i < callList.length; i += 1) {
        const call = callList[i];
        const outcome = await this.runTool(call, principal);
        if (outcome.deferred) {
          // Every tool_call in the assistant message we just stored needs a tool message
          // back, or the provider rejects the *next* turn of this conversation with
          // 400 "An assistant message with 'tool_calls' must be followed by tool messages
          // responding to each 'tool_call_id'". Approval defers mid-list, so the deferred
          // call and all the ones behind it get an honest placeholder: nothing ran yet.
          for (const rest of callList.slice(i)) {
            messages.push({ role: 'tool', tool_call_id: rest.id, content: envelope('tool-pending', '等待主人在私聊里确认，本轮未执行。') });
          }
          if (outcome.pending) outcome.pending.historyKey = key;
          this.remember(key, messages);
          return { reply: outcome.question, pending: true, calls: this.llm.calls - callsBefore };
        }
        messages.push({ role: 'tool', tool_call_id: call.id, content: outcome.text });
      }
    }
    this.remember(key, messages);
    return { reply: '这轮我想得太久了，先停一下；你可以换个说法再问。', pending: false, calls: this.llm.calls - callsBefore };
  }

  async runTool(call, principal) {
    const tool = this.byName.get(call.function?.name);
    const name = call.function?.name || '';
    if (!tool) return { text: envelope('tool-error', `未知工具 ${name}`), deferred: false };
    let args = {};
    try {
      args = JSON.parse(call.function.arguments || '{}');
    } catch {
      return { text: envelope('tool-error', '参数不是合法 JSON，未执行。'), deferred: false };
    }
    const denial = this.guard({ name, args });
    if (denial) {
      this.audit.emit('sandbox.denied', { stage: 'tool-guard', toolName: name, result: 'denied', reason: denial, role: principal?.role });
      return { text: envelope('tool-denied', denial), deferred: false };
    }
    try {
      const out = await tool.execute(args, { name, args, callId: call.id });
      return { text: String(out?.text ?? JSON.stringify(out ?? {})).slice(0, 8000), deferred: false };
    } catch (err) {
      if (err instanceof ApprovalDeferred) {
        const p = err.pending;
        // The queue learns which model call it is holding up, so the history entry can be
        // settled when the owner answers (see settlePendingCall).
        p.callId = call.id;
        return { deferred: true, pending: p, question: `${p.note}\n（回复「同意」写入，「拒绝」放弃；${Math.round(this.approvals.ttlMs / 60000)} 分钟内不作答自动失效）\n要记的是：${p.toolName === 'memory_write' ? String(p.args.body ?? '').slice(0, 200) : p.toolName}` };
      }
      return { text: envelope('tool-error', String(err.message || 'tool failed').slice(0, 300)), deferred: false };
    }
  }

  /**
   * Owner answered the pending approval: mint the one-time token and run the exact stored
   * call. No model turn here — the human decision covers the action, and re-asking the
   * model could change what gets written after the fact.
   */
  async resolvePending({ text, principal }) {
    const decision = approvalWord(text);
    if (!decision) return null; // not an approval message: the caller treats it as a normal turn
    const key = this.approvals.key(principal);
    const pending = this.approvals.peek(key);
    if (!pending) {
      // A bare "同意" with nothing pending must approve *nothing*, now or later.
      this.audit.emit('approval.outcome', { stage: 'orphan', result: 'noop', decision, chatKey: key, role: principal.role });
      return { reply: '现在没有等你确认的操作，所以什么都没做。', calls: 0, orphan: true };
    }
    if (decision === 'denied') {
      this.approvals.take(key, 'denied');
      this.settlePendingCall(pending.historyKey, pending.callId, '主人拒绝了这条操作，没有执行。');
      return { reply: '好，这条没有写入记忆。', calls: 0, denied: true };
    }
    if (pending.principal.userId !== principal.userId || pending.principal.channel !== principal.channel) {
      this.approvals.take(key, 'denied');
      this.settlePendingCall(pending.historyKey, pending.callId, '这条确认不是发给当前会话的，没有执行。');
      this.audit.emit('approval.outcome', { stage: 'decided', approvalId: pending.id, result: 'denied', reason: 'principal-mismatch', chatKey: key });
      return { reply: '这条确认不是发给你的，我没有执行。', calls: 0, denied: true };
    }
    const tool = this.byName.get(pending.toolName);
    if (!tool) {
      this.approvals.take(key, 'denied');
      this.settlePendingCall(pending.historyKey, pending.callId, '那个操作已不再支持，没有执行。');
      return { reply: '那个操作我不再支持，没有执行。', calls: 0, denied: true };
    }
    if (this.bindPrincipal) this.bindPrincipal(principal);
    const approvalId = `appr-${randomBytes(16).toString('hex')}`;
    this.approvals.take(key, 'approved');
    try {
      // The tool re-enters `approve`, which is where the memory service token comes from;
      // on this path the decision already happened, so the queue hands out the token.
      const out = await tool.execute(pending.args, { name: pending.toolName, args: pending.args, approvalId });
      const text = String(out?.text ?? '已处理。');
      this.settlePendingCall(pending.historyKey, pending.callId, `主人已同意，这一步已经执行（memoryId=${out?.memoryId ?? '未知'}）。`);
      this.audit.emit('approval.outcome', { stage: 'applied', result: 'allowed', approvalId: pending.id, toolName: pending.toolName, chatKey: key, memoryId: out?.memoryId ?? null, deduped: Boolean(out?.deduped) });
      return { reply: text, calls: 0, applied: true, memoryId: out?.memoryId ?? null };
    } catch (err) {
      this.settlePendingCall(pending.historyKey, pending.callId, `主人已同意，但这一步执行失败：${shortReason(err)}。没有写入。`);
      this.audit.emit('approval.outcome', { stage: 'applied', result: 'error', approvalId: pending.id, toolName: pending.toolName, chatKey: key, reason: String(err.message).slice(0, 160) });
      return { reply: `写入失败了：${shortReason(err)}。`, calls: 0, error: err.message };
    }
  }

  finalize(content) {
    const text = String(content ?? '').trim();
    if (!text) return '（模型这轮没有返回内容）';
    return redactOutbound(text).text.slice(0, 1800);
  }
}

function shortReason(err) {
  const m = String(err?.message || '');
  if (/not approved/.test(m)) return '未获批准';
  if (/POLICY|permission/.test(m)) return '权限不足';
  return m.slice(0, 80) || '内部错误';
}
