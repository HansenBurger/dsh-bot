/**
 * proxy-tunnel — HTTPS egress through the C5 allowlist proxy, with no new dependency.
 *
 * Why this file exists: the broker is the only process that ever holds the plaintext
 * LLM key, and per t3 §4 it must not have a free route to the internet — every outbound
 * request is supposed to pass the squid allowlist (`deploy/egress-proxy/rules.conf`).
 * Node's `https.request` ignores `HTTPS_PROXY` entirely (and `undici` is not installed in
 * this image), so without a tunnel the broker would either fail to connect or tempt
 * someone into giving the key-holding container its own WAN route. That second option is
 * the one this module exists to make unnecessary.
 *
 * Semantics, deliberately strict:
 *   - a proxy is used only when the *upstream* protocol is https and the target host is
 *     not covered by NO_PROXY. Plain http targets keep connecting directly, because
 *     forwarding them would mean rewriting absolute-URI request lines, and every target
 *     we actually use is TLS;
 *   - failure is failure: if CONNECT is rejected, unanswered, or the socket dies, the
 *     request errors out. There is no silent fallback to a direct connection, because a
 *     proxy that silently stops filtering is exactly the exfiltration path (TM-014)
 *     the allowlist was built to close;
 *   - nothing here ever logs the target beyond host:port, and never touches headers.
 */

import net from 'node:net';
import tls from 'node:tls';

const CONNECT_TIMEOUT_MS = 5000;

/**
 * Resolve the proxy to use for `targetHost`, honouring NO_PROXY.
 * @returns {{hostname: string, port: number} | null}
 */
export function proxyFor(targetHost, env = process.env) {
  const raw = env.HTTPS_PROXY || env.https_proxy || env.HTTP_PROXY || env.http_proxy || '';
  if (!raw) return null;
  let url;
  try {
    url = new URL(raw.includes('://') ? raw : `http://${raw}`);
  } catch {
    return null;
  }
  if (!url.hostname) return null;

  const noProxy = (env.NO_PROXY || env.no_proxy || '')
    .split(',')
    .map((s) => s.trim().replace(/^\./, ''))
    .filter(Boolean);
  const host = String(targetHost || '').toLowerCase();
  const bypassed = noProxy.some((entry) => {
    if (entry === '*') return true;
    const e = entry.toLowerCase();
    return host === e || host.endsWith(`.${e}`);
  });
  if (bypassed) return null;

  return { hostname: url.hostname, port: Number(url.port) || 3128, proxyAuthorization: url.password ? `Basic ${Buffer.from(`${url.username}:${url.password}`).toString('base64')}` : undefined };
}

/**
 * `createConnection` for `https.request`: CONNECT-tunnel to the target, then TLS over it.
 * @param {{hostname: string, port: number}} target
 * @param {{hostname: string, port: number, proxyAuthorization?: string}} proxy
 * @param {(err: Error | null, socket?: import('node:stream').Duplex) => void} onConnect
 */
export function tunneledConnection(target, proxy, onConnect, opts = {}) {
  const port = target.port || 443;
  const fail = (message, egressReason) => {
    const err = new Error(message);
    // A reason *code*, not a scraped message: the broker audits "proxy refused" and
    // "proxy unreachable" differently, and an operator reading the log must be able to
    // tell its own egress policy from a network outage.
    err.egressReason = egressReason;
    settled(err);
  };
  const settled = (err, socket) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    if (err) {
      sock.destroy();
      return onConnect(err);
    }
    onConnect(null, socket);
  };
  let done = false;
  const sock = net.connect({ host: proxy.hostname, port: proxy.port });
  const timer = setTimeout(() => fail(`proxy CONNECT timed out (${proxy.hostname}:${proxy.port})`, 'proxy-unreachable'), opts.timeoutMs ?? CONNECT_TIMEOUT_MS);
  sock.once('error', (err) => fail(`proxy connect failed: ${err.message}`, 'proxy-unreachable'));

  let buffer = Buffer.alloc(0);
  const onData = (chunk) => {
    if (done) return;
    buffer = Buffer.concat([buffer, chunk]);
    const end = buffer.indexOf('\r\n\r\n');
    if (end < 0) {
      if (buffer.length > 8192) fail('proxy CONNECT response too large', 'proxy-denied');
      return;
    }
    const head = buffer.subarray(0, end).toString('latin1');
    const rest = buffer.subarray(end + 4);
    sock.removeListener('data', onData);
    if (!/^HTTP\/1\.[01] 20[01]/i.test(head)) {
      const code = head.split(' ')[1] || '?';
      // 403/407 come from the allowlist, i.e. from *our* policy — that is a denial, not
      // an outage, and it is the line the exfiltration watchdog (TM-014) should fire on.
      return fail(`proxy refused CONNECT ${target.hostname}:${port} (${code})`, 'proxy-denied');
    }
    // Bytes already in flight belong to the TLS handshake: put them back before the
    // tls socket attaches to the same stream, or they are lost.
    if (rest.length) sock.unshift(rest);
    const secure = tls.connect({ socket: sock, servername: target.hostname, ALPNProtocols: ['http/1.1'] });
    secure.once('secureConnect', () => settled(null, secure));
    secure.once('error', (err) => fail(`TLS through proxy failed: ${err.message}`, 'proxy-unreachable'));
  };
  sock.on('data', onData);
  sock.write(`CONNECT ${target.hostname}:${port} HTTP/1.1\r\nHost: ${target.hostname}:${port}\r\n${proxy.proxyAuthorization ? `Proxy-Authorization: ${proxy.proxyAuthorization}\r\n` : ''}\r\n`);
}

/**
 * Build the request options for an https target, adding the tunnel only when a proxy
 * applies. Returns the options unchanged (plus `__via`) when there is no proxy.
 */
export function upstreamRequestOptions(baseUrl, extraHeaders, env = process.env) {
  const target = { hostname: baseUrl.hostname, port: Number(baseUrl.port) || (baseUrl.protocol === 'https:' ? 443 : 80) };
  const via = { protocol: baseUrl.protocol, ...target };
  if (baseUrl.protocol !== 'https:') return { options: extraHeaders, via: 'direct' };
  const proxy = proxyFor(target.hostname, env);
  if (!proxy) return { options: extraHeaders, via: 'direct' };
  const createConnection = (options, onConnect) => tunneledConnection(target, proxy, onConnect);
  return { options: { ...extraHeaders, createConnection }, via: `proxy:${proxy.hostname}:${proxy.port}` };
}
