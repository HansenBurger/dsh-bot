// One-shot handshake probe: which access token does the pinned ingress accept right now?
// Used to prove the fingerprint rotation, so it prints only the close code and the
// matching audit line - never the token itself.
import { WebSocket } from 'ws';
import { readFileSync, existsSync } from 'node:fs';

const token = process.argv[2] === 'old'
  ? 'prototype-token-for-local-verification'
  : readFileSync('deploy/secrets/napcat-ob11-access-token', 'utf8').trim();

const label = process.argv[2] === 'old' ? 'retired prototype token' : 'current secret token';
const ws = new WebSocket(`ws://127.0.0.1:3001/onebot/v11/ws?access_token=${token}`);
// The gateway completes the HTTP upgrade and *then* closes 1008 on a fingerprint
// mismatch, which is how OneBot11 adapters expect a refusal. So "open" alone proves
// nothing: the verdict is the close code (or a session that stays open).
let opened = false;
const outcome = await new Promise((resolve) => {
  const timer = setTimeout(() => resolve(opened ? 'opened and stayed open (accepted)' : 'no close within 8s'), 4000);
  ws.on('open', () => { opened = true; });
  ws.on('close', (code) => { clearTimeout(timer); resolve(`close=${code}${opened ? ' after upgrade' : ''}`); });
  ws.on('error', (err) => { clearTimeout(timer); resolve(`client error: ${err.message.slice(0, 40)}`); });
});
console.log(`${label}: ${outcome}`);
if (existsSync('logs/ingress.jsonl')) {
  const lines = readFileSync('logs/ingress.jsonl', 'utf8').trim().split('\n').slice(-3);
  for (const l of lines) {
    const d = JSON.parse(l);
    if (d.type === 'session.lifecycle' || d.reason) {
      console.log('  audit:', JSON.stringify({ type: d.type, event: d.event, reason: d.reason, result: d.result }));
    }
  }
}
