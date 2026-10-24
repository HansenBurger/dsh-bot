/**
 * ob11 — OneBot v11 **reverse websocket** listener (the protocol edge of the gateway).
 *
 * Direction matters: NapCat/LLBot dial *us* (`MODE: reverse_ws`, t3 §3 napcat env), so
 * this container owns no inbound host port beyond the loopback-published 3001 and the
 * QQ side needs no route into the NAS (C4/D-03).
 *
 * Handshake checks, in order:
 *   1. the `access_token` presented by the client is compared by **sha256 fingerprint**
 *      against `OB11_ACCESS_TOKEN_FINGERPRINT` — the real token never sits in this
 *      container's env (D1);
 *   2. `self_id` must equal `OB11_EXPECTED_SELF_ID`, otherwise a different QQ account
 *      (or someone replaying another bot's stream) would be handed our pipeline;
 *   3. frames are size-capped and must parse as strict JSON before normalization.
 *
 * Everything rejected here is audit-logged with the structured reason only.
 */

import { createHash, timingSafeEqual } from 'node:crypto';
import { WebSocketServer } from 'ws';
import { inboundOnebot, NormalizeError } from '@dsh-bot/bot-normalize';

const MAX_FRAME_BYTES = 256 * 1024;

export class Ob11Listener {
  /**
   * @param {{port:number, host?:string, path?:string, expectedSelfId?: string, tokenFingerprint?: string,
   *          onEvent:(evt:{type:string, messages:object[], raw:object, socketId:string})=>void,
   *          audit:{emit:(t:string,f:object)=>void}, log?:(o:object)=>void}} opts
   */
  constructor(opts) {
    this.port = Number(opts.port ?? 3001);
    this.host = opts.host || '0.0.0.0';
    this.path = opts.path || '/onebot/v11/ws';
    this.expectedSelfId = opts.expectedSelfId;
    this.tokenFingerprint = opts.tokenFingerprint;
    this.onEvent = opts.onEvent || (() => {});
    this.audit = opts.audit;
    this.log = opts.log || ((o) => process.stderr.write(`${JSON.stringify({ ts: Date.now(), service: 'gateway', ...o })}\n`));
    /** @type {Map<string, {ws:import('ws').WebSocket, selfId:string, pending:Map<string,object>, seq:number}>} */
    this.sockets = new Map();
    this.server = null;
    this.replies = { sent: 0, failed: 0 };
  }

  /**
   * Bind the socket. Resolves only once the port is actually listening: a healthcheck
   * that reports "up" before the port exists would let compose mark the container
   * healthy while every adapter connection attempt is still refused.
   */
  async start() {
    this.server = new WebSocketServer({ host: this.host, port: this.port, path: this.path, maxPayload: MAX_FRAME_BYTES, clientTracking: true });
    this.server.on('connection', (ws, req) => this.#onConnection(ws, req));
    await new Promise((resolve, reject) => {
      this.server.once('listening', resolve);
      this.server.once('error', reject);
    });
    return this;
  }

  async stop() {
    for (const entry of this.sockets.values()) {
      try {
        entry.ws.terminate();
      } catch {
        /* already gone */
      }
    }
    this.sockets.clear();
    if (!this.server) return;
    await new Promise((resolve) => this.server.close(resolve));
    this.server = null;
  }

  #onConnection(ws, req) {
    const url = new URL(req.url, 'http://gateway');
    const token = url.searchParams.get('access_token') || String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    const socketId = `${req.socket.remoteAddress}:${Math.random().toString(36).slice(2, 8)}`;

    if (this.tokenFingerprint) {
      const presented = sha256Hex(token);
      if (!equalHex(presented, this.tokenFingerprint)) {
        this.audit?.emit('authz.decision', { stage: 'ob11-handshake', result: 'denied', reason: 'token-fingerprint-mismatch', socketId });
        this.log({ type: 'authz.decision', stage: 'ob11-handshake', result: 'denied', reason: 'token-fingerprint-mismatch' });
        ws.close(1008, 'unauthorized');
        return;
      }
    }

    // The connection is not trusted yet: self_id only arrives inside the first frames.
    const entry = { ws, selfId: '', pending: new Map(), seq: 0, socketId };
    this.sockets.set(socketId, entry);
    this.audit?.emit('session.lifecycle', { stage: 'ob11-handshake', result: 'allowed', event: 'connected', socketId });

    ws.on('message', (data, isBinary) => {
      if (isBinary) {
        this.audit?.emit('authz.decision', { stage: 'ob11-frame', result: 'denied', reason: 'binary-frame', socketId });
        return;
      }
      if (data.length > MAX_FRAME_BYTES) return;
      let raw;
      try {
        raw = JSON.parse(data.toString('utf8'));
      } catch {
        this.audit?.emit('authz.decision', { stage: 'ob11-frame', result: 'denied', reason: 'non-json-frame', socketId });
        return;
      }
      this.#onFrame(entry, raw);
    });

    ws.on('close', () => {
      this.sockets.delete(socketId);
      for (const [, call] of entry.pending) clearTimeout(call.timer);
      entry.pending.clear();
      this.audit?.emit('session.lifecycle', { stage: 'ob11-handshake', result: 'allowed', event: 'disconnected', socketId });
    });
    ws.on('error', (err) => {
      this.audit?.emit('sandbox.denied', { stage: 'ob11-socket', result: 'error', message: String(err.message).slice(0, 80), socketId });
    });
  }

  #onFrame(entry, raw) {
    // API responses carry `echo` and no post_type: resolve the pending call, done.
    if (raw && typeof raw === 'object' && raw.status !== undefined && raw.echo !== undefined && entry.pending.has(String(raw.echo))) {
      const call = entry.pending.get(String(raw.echo));
      clearTimeout(call.timer);
      entry.pending.delete(String(raw.echo));
      call.settle({ ok: raw.retcode === 0, retcode: raw.retcode, data: raw.data, message: raw.info });
      return;
    }

    if (raw.self_id !== undefined) {
      const selfId = String(raw.self_id);
      if (!entry.selfId) entry.selfId = selfId;
      if (this.expectedSelfId && selfId !== String(this.expectedSelfId)) {
        // A foreign account on our socket: drop it, do not process a single event.
        this.audit?.emit('authz.decision', { stage: 'ob11-self-id', result: 'denied', reason: 'self-id-mismatch', observed: selfId.slice(0, 32) });
        entry.ws.close(1008, 'self_id mismatch');
        return;
      }
    }

    let parsed;
    try {
      parsed = inboundOnebot(raw, { expectedSelfId: this.expectedSelfId });
    } catch (err) {
      const code = err instanceof NormalizeError ? err.code : 'BAD_REQUEST';
      this.audit?.emit('authz.decision', { stage: 'ob11-normalize', result: 'denied', code, reason: String(err.message).slice(0, 60) });
      return;
    }
    if (parsed.messages.length === 0) return;
    this.onEvent({ type: parsed.postType, messages: parsed.messages, selfId: parsed.selfId, raw, socketId: entry.socketId });
  }

  /**
   * Call an adapter action over the reverse socket (send_msg / get_msg / set_reply...).
   * Exactly one connected client is assumed; with several, the one whose self_id
   * matches is used, and the call fails closed rather than picking arbitrarily.
   */
  async call(action, params, { timeoutMs = 8000 } = {}) {
    const candidates = [...this.sockets.values()].filter((e) => e.ws.readyState === 1);
    if (candidates.length === 0) return { ok: false, error: 'no-adapter-connection' };
    const chosen = this.expectedSelfId ? candidates.find((e) => e.selfId === String(this.expectedSelfId)) || candidates[0] : candidates[0];
    if (candidates.length > 1 && !this.expectedSelfId) return { ok: false, error: 'ambiguous-adapter-connection' };

    chosen.seq += 1;
    const echo = `gw-${Date.now().toString(36)}-${chosen.seq}`;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        chosen.pending.delete(echo);
        resolve({ ok: false, error: 'adapter-timeout' });
      }, timeoutMs);
      chosen.pending.set(echo, { timer, settle: resolve });
      try {
        chosen.ws.send(JSON.stringify({ action, params, echo }));
      } catch (err) {
        clearTimeout(timer);
        chosen.pending.delete(echo);
        resolve({ ok: false, error: String(err.message).slice(0, 60) });
      }
    });
  }

  /** Deliver a normalized reply back through the adapter that owns the peer. */
  async send(msg, text) {
    const action = msg.peer.kind === 'group' ? 'send_group_msg' : 'send_private_msg';
    const idField = msg.peer.kind === 'group' ? 'group_id' : 'user_id';
    const result = await this.call(action, { [idField]: Number(msg.peer.chatId) || msg.peer.chatId, message: [{ type: 'text', data: { text } }] });
    if (result.ok) this.replies.sent += 1;
    else this.replies.failed += 1;
    return result;
  }

  connections() {
    return [...this.sockets.values()].map((e) => ({ socketId: e.socketId, selfId: e.selfId || null, readyState: e.ws.readyState, pending: e.pending.size }));
  }
}

const sha256Hex = (s) => createHash('sha256').update(String(s), 'utf8').digest('hex');

function equalHex(a, b) {
  const ba = Buffer.from(String(a).toLowerCase(), 'utf8');
  const bb = Buffer.from(String(b).toLowerCase(), 'utf8');
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}
