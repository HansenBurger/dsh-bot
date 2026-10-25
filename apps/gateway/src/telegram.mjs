/**
 * telegram — Bot API **long-polling** adapter (C6: no inbound webhook listener).
 *
 * getUpdates is an outbound request, so the container needs no published port and the
 * only route to api.telegram.org is the egress proxy (C5). Node's global `fetch` does
 * not honour HTTP_PROXY, so the tunnel is explicit here:
 *   - `http://` targets go through the proxy in absolute-form;
 *   - `https://` targets use CONNECT and then TLS over the tunneled socket.
 * A configured proxy that turns out unreachable fails the poll loudly — it must never
 * silently fall back to a direct connection, because "direct" would be an egress path
 * outside the allowlist.
 */

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { URL } from 'node:url';
import { buildNormalized, NormalizeError } from '@dsh-bot/bot-normalize';

const MAX_TG_TEXT = 4096;

export class TelegramAdapter {
  /**
   * @param {{token: string, proxyUrl?: string, audit?: {emit:(t:string,f:object)=>void}, onMessage:(msg:object)=>void, log?:Function, timeoutMs?: number, allowedChatIds?: string[]}} opts
   */
  constructor(opts) {
    this.token = opts.token;
    this.apiBase = opts.apiBase || 'https://api.telegram.org';
    this.proxyUrl = opts.proxyUrl || process.env.HTTP_PROXY || process.env.http_proxy || '';
    this.audit = opts.audit;
    this.onMessage = opts.onMessage || (() => {});
    this.log = opts.log || ((o) => process.stderr.write(`${JSON.stringify({ ts: Date.now(), service: 'gateway', ...o })}\n`));
    this.timeoutMs = opts.timeoutMs ?? 65_000;
    this.offset = 0;
    this.running = false;
    this.stats = { polls: 0, updates: 0, errors: 0 };
  }

  async start() {
    this.running = true;
    void this.#loop();
    return this;
  }

  stop() {
    this.running = false;
  }

  async #loop() {
    while (this.running) {
      try {
        // The Bot API answers with an envelope: {ok, result}. Iterating it directly is a
        // TypeError ("updates is not iterable") that the catch below turns into a silent
        // error+backoff — inbound Telegram polling would never deliver anything while the
        // health endpoint stayed green.
        const envelope = await this.getUpdates();
        const updates = Array.isArray(envelope?.result) ? envelope.result : [];
        this.stats.polls += 1;
        if (!Array.isArray(envelope?.result)) {
          this.stats.errors += 1;
          this.audit?.emit('sandbox.denied', { stage: 'tg-poll', result: 'error', message: 'unexpected getUpdates envelope' });
        }
        for (const upd of updates) {
          this.offset = Math.max(this.offset, Number(upd.update_id) + 1);
          const msg = upd.message || upd.edited_message;
          if (!msg) continue;
          this.stats.updates += 1;
          try {
            this.onMessage(this.normalize(msg));
          } catch (err) {
            const code = err instanceof NormalizeError ? err.code : 'BAD_REQUEST';
            this.audit?.emit('authz.decision', { stage: 'tg-normalize', result: 'denied', code, reason: String(err.message).slice(0, 60) });
          }
        }
      } catch (err) {
        this.stats.errors += 1;
        this.audit?.emit('sandbox.denied', { stage: 'tg-poll', result: 'error', message: String(err.message).slice(0, 90) });
        // Back off instead of hot-looping against a 4xx/5xx or a dead proxy.
        await sleep(2_000);
      }
    }
  }

  /** @param {object} msg - a TG `Message` */
  normalize(msg) {
    const chatId = String(msg.chat?.id ?? '');
    const userId = String(msg.from?.id ?? '');
    if (!chatId || !userId) throw new NormalizeError('BAD_REQUEST', 'tg update missing chat/from id');
    // A2: first_name/last_name/username are display text and are dropped right here.
    return buildNormalized({
      channel: 'telegram',
      peer: { kind: msg.chat?.type === 'group' || msg.chat?.type === 'supergroup' ? 'group' : 'dm', chatId },
      sender: { userId },
      text: String(msg.text || msg.caption || '').slice(0, MAX_TG_TEXT),
      atBot: Boolean(msg.entities?.some((e) => e.type === 'mention' && /bot/i.test(e.url || ''))),
      rawRef: { messageId: String(msg.message_id), seq: 0 },
      receivedAt: Date.now(),
    });
  }

  getUpdates() {
    const path = `/bot${this.token}/getUpdates`;
    const query = `?timeout=50&allowed_updates=["message","edited_message","channel_post"]&offset=${this.offset}`;
    return this.#request('POST', `${path}${query}`, '{}');
  }

  async sendMessage(chatId, text, opts = {}) {
    const body = JSON.stringify({ chat_id: chatId, text: text.slice(0, MAX_TG_TEXT), disable_web_page_preview: true, ...opts });
    return this.#request('POST', `/bot${this.token}/sendMessage`, body);
  }

  /** Token is a credential: it is present in the path, so no log line may echo a URL. */
  async #request(method, path, body) {
    const url = new URL(`${this.apiBase}${path}`);
    const text = await new Promise((resolve, reject) => {
      const send = (opts) => {
        const factory = url.protocol === 'https:' ? httpsRequest : httpRequest;
        const req = factory(opts, (res) => {
          let data = '';
          res.setEncoding('utf8');
          res.on('data', (c) => {
            data += c;
            if (data.length > 4 * 1024 * 1024) req.destroy(new Error('tg response too large'));
          });
          res.on('end', () => {
            if ((res.statusCode || 0) >= 400) return reject(new Error(`tg http ${res.statusCode}`));
            resolve(data);
          });
        });
        req.setTimeout(this.timeoutMs, () => req.destroy(new Error('tg request timeout')));
        req.on('error', reject);
        req.write(body);
        req.end();
      };

      const requestOpts = (override = {}) => ({
        method,
        path: url.pathname + url.search,
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
        ...override,
      });

      if (!this.proxyUrl) {
        return send(requestOpts({ hostname: url.hostname, port: Number(url.port) || (url.protocol === 'https:' ? 443 : 80) }));
      }

      const proxy = new URL(this.proxyUrl);
      if (url.protocol !== 'https:') {
        // Absolute-form request through an http proxy: the proxy performs the hop (C5).
        return send(requestOpts({ host: proxy.hostname, port: Number(proxy.port) || 3128, path: url.href }));
      }

      // https: open a CONNECT tunnel, then layer TLS on the tunneled socket.
      const target = `${url.hostname}:${url.port || 443}`;
      const connectReq = httpRequest({ method: 'CONNECT', host: target, path: '/', headers: { host: target } });
      connectReq.on('connect', (res, conn) => {
        if (res.statusCode !== 200) {
          conn.destroy();
          return reject(new Error(`proxy CONNECT ${res.statusCode}`));
        }
        const tlsSocket = tlsConnect({ socket: conn, servername: url.hostname });
        tlsSocket.on('error', (err) => reject(new Error(`tls over tunnel failed: ${String(err.message).slice(0, 60)}`)));
        send(requestOpts({ createConnection: () => tlsSocket }));
      });
      // A dead proxy must fail the poll loudly; a silent direct fallback would be an
      // egress path outside the allowlist.
      connectReq.on('error', (err) => reject(new Error(`proxy unreachable: ${String(err.message).slice(0, 60)}`)));
      connectReq.end();
    });
    try {
      return JSON.parse(text);
    } catch {
      throw new Error('tg response not JSON');
    }
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
