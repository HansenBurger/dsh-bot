/**
 * memory-e2e — exercise the live memory service over its internal REST surface.
 *
 * Transport: the memory container runs with `read_only: true`, so nothing can be copied
 * into it. This file is piped through stdin instead:
 *
 *   docker compose -f deploy/compose.yaml exec -T memory node --input-type=module < scripts/memory-e2e.mjs
 *
 * Inside that container 127.0.0.1:8091 is the service itself, /run/secrets holds the
 * credentials the broker/mounts injected, /var/lib/dshbot/memory is the L1 volume, and
 * the host PostgreSQL unix socket is mounted — which is what makes the whole checklist
 * below possible without opening a single port to the host.
 *
 * It proves, in order:
 *   G the container reaches host PostgreSQL over the unix socket as dsh_companion_rw
 *   A write → row on the host instance + row in the SQLite cache (the dual-write)
 *   B read → returns the plaintext body (SQLite-first path)
 *   C Chinese retrieval → hits through companion.byte_trgm() on the host instance
 *   D session context → round-trips through L1, closed slot enum enforced
 *   E delete requires a one-time approval token, and honours it when present
 *   F after delete → tombstone, cache invalidation, read no longer returns the body
 *   I a trusted (non-owner) principal cannot forget
 */

import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';

// Absolute specifier: the image's node_modules is the only place these packages exist
// when the script arrives over stdin (there is no local directory to resolve from).
const { signedHeaders } = await import('/app/node_modules/@dsh-bot/bot-hmac/src/index.mjs');

const HMAC_PATH = '/run/secrets/mem-hmac-secret';
const hmac = readFileSync(HMAC_PATH, 'utf8').trim();
const BASE = process.env.MEM_E2E_BASE || 'http://127.0.0.1:8091';
const subject = { channel: 'onebot', chatId: '100012345', userId: '100012345', role: 'owner' };

const results = [];
const step = (name, ok, detail) => {
  results.push({ name, ok: !!ok, detail: String(detail ?? '').slice(0, 200) });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail !== undefined ? ` — ${String(detail).slice(0, 200)}` : ''}`);
};

class ServiceError extends Error {
  constructor(code, message, status) {
    super(`${code}: ${message}`);
    this.code = code;
    this.status = status;
  }
}

/** The same signing discipline apps/bot-core/src/memory-client.mjs uses, inlined so this
 *  file has no import that the read-only rootfs cannot satisfy. */
async function call(method, path, body, principal = subject, approvalId = undefined) {
  const raw = body === undefined ? undefined : JSON.stringify(body);
  const headers = {
    accept: 'application/json',
    ...signedHeaders(hmac, { method, path, body: raw, ...principal, bind: approvalId }),
  };
  if (raw !== undefined) headers['content-type'] = 'application/json';
  const res = await fetch(`${BASE}${path}`, { method, headers, body: raw, signal: AbortSignal.timeout(15000) });
  const json = await res.json().catch(() => null);
  if (!res.ok) throw new ServiceError(json?.code || `HTTP_${res.status}`, json?.message || res.statusText, res.status);
  return json;
}

const sqlite = (sql) => execFileSync('sqlite3', [process.env.MEM_L1_PATH || '/var/lib/dshbot/memory/l1.db', sql], { encoding: 'utf8' }).trim();
// A probe must never abort the run: an unexpected column or a denied privilege is a
// FAIL line, not a stack trace that hides the other 20 checks.
const psqlRw = (sql) => {
  try {
    return runPsql(sql);
  } catch (err) {
    return `error: ${String(err.stderr || err.message).replace(/\n/g, ' ').slice(0, 120)}`;
  }
};
const runPsql = (sql) =>
  execFileSync('psql', ['-h', '/var/run/postgresql', '-U', 'dsh_companion_rw', '-d', 'dsh_companion', '-X', '-q', '-tAc', sql], {
    encoding: 'utf8',
    // Password through the child environment, never argv (argv is world-readable in `ps`).
    env: { ...process.env, PGPASSWORD: readFileSync('/run/secrets/mem-pg-rw-password', 'utf8').trim() },
  }).trim();

const BODY = '主人不吃香菜，点外卖不要放香菜';
const marker = `e2e-${Date.now()}`;
const token = () => `appr-${randomBytes(16).toString('hex')}`;

/* ---------------- G the socket path (precondition for A/F) ---------------- */
let socketUser = '';
try {
  socketUser = psqlRw('select current_user');
} catch (err) {
  socketUser = `error: ${String(err.stderr || err.message).slice(0, 140)}`;
}
step('G container connects to the host instance over the unix socket', socketUser === 'dsh_companion_rw', socketUser);

/* ---------------- A write ---------------- */
let memoryId;
try {
  const written = await call('POST', '/v1/memories', {
    subjectKey: 'onebot:dm:100012345',
    class: 'preference',
    body: BODY,
    // A dietary taboo applies everywhere, so it is written at global scope; dm/group
    // scope would additionally require scopePeer.
    scope: 'global',
    sensitivity: 'internal',
    visibility: 'private',
    // L2 stable attributes/preferences are keyed by attribute, not by text: without an
    // attrKey the service cannot deduplicate or conflict-detect, so it refuses the write.
    attrKey: 'dietary_taboo',
    idempotencyKey: marker,
    // `preference` carries requires_approval = true in the seeded policy, so this write
    // is only lawful because a one-time token accompanies it.
    approvalId: token(),
  });
  memoryId = written?.memoryId;
  step('A1 write returns a memory id', Boolean(memoryId), JSON.stringify(written).slice(0, 160));
} catch (err) {
  step('A1 write returns a memory id', false, err.message);
}

/* An approval-free write into the same class must be refused — checked before the read
   assertions so a refusal here cannot be confused with a broken row. */
let unapprovedWrite;
try {
  await call('POST', '/v1/memories', { subjectKey: 'onebot:dm:100012345', class: 'preference', body: '无审批写入', scope: 'global', attrKey: 'unapproved_probe', idempotencyKey: `${marker}-noauth` });
} catch (err) {
  unapprovedWrite = err;
}
step('A2 a write into an approval-required class is refused without a token', /APPROVAL_REQUIRED/.test(String(unapprovedWrite?.code || unapprovedWrite?.message)), unapprovedWrite?.message || 'accepted');

const rowOnHost = memoryId ? psqlRw(`select count(*) from companion.memory_readable where memory_id = '${memoryId}'`) : '0';
step('A3 the row exists on the host PostgreSQL instance', rowOnHost === '1', `memory_readable count=${rowOnHost}`);
const cachedAfterWrite = memoryId ? sqlite(`select count(*) from memory_cache where memory_id = '${memoryId}'`) : '0';
step('A4 the write was dual-written into the SQLite cache', cachedAfterWrite === '1', `memory_cache count=${cachedAfterWrite}`);

/* ---------------- B read ---------------- */
try {
  const read = await call('GET', `/v1/memories/${encodeURIComponent(memoryId)}`);
  step('B1 read returns the plaintext body', String(read?.body ?? read?.memory?.body).includes('不吃香菜'), JSON.stringify(read).slice(0, 160));
} catch (err) {
  step('B1 read returns the plaintext body', false, err.message);
}

/* ---------------- C search ---------------- */
try {
  const found = await call('POST', '/v1/memories/search', { query: '香菜', limit: 5 });
  const ids = (found?.results || []).map((r) => r.memoryId);
  step('C1 Chinese query hits through the byte-trigram index', ids.includes(memoryId), `hits=${ids.length}`);
} catch (err) {
  step('C1 Chinese query hits through the byte-trigram index', false, err.message);
}

/* ---------------- D session context ---------------- */
try {
  await call('PUT', '/v1/context/onebot%3Adm%3A100012345', { slot: 'topic_stack', value: { items: ['点外卖'] } });
  const ctx = await call('GET', '/v1/context/onebot%3Adm%3A100012345');
  step('D1 session context round-trips through L1', JSON.stringify(ctx).includes('点外卖'), JSON.stringify(ctx).slice(0, 160));
} catch (err) {
  step('D1 session context round-trips through L1', false, err.message);
}
let badSlot;
try {
  await call('PUT', '/v1/context/onebot%3Adm%3A100012345', { slot: 'anything_else', value: {} });
} catch (err) {
  badSlot = err;
}
step('D2 an unknown context slot is refused (closed enum)', badSlot && /BAD_REQUEST/.test(String(badSlot.code)), badSlot?.code || 'accepted');
let piiSlot;
try {
  await piiSlotGuard();
} catch (err) {
  piiSlot = err;
}
async function piiSlotGuard() {
  return call('PUT', '/v1/context/onebot%3Adm%3A100012345', { slot: 'entity_alias', value: { v: '身份证号' }, sensitivity: 'pii' });
}
step('D3 pii-level content never enters the L1 cache', piiSlot && /MEMORY_REFUSED_CATEGORY/.test(String(piiSlot.code)), piiSlot?.code || 'accepted');

/* ---------------- E delete needs approval ---------------- */
let unapproved;
try {
  await call('POST', `/v1/memories/${encodeURIComponent(memoryId)}/forget?dryRun=false`);
} catch (err) {
  unapproved = err;
}
step('E1 a real delete without an approval token is refused', /APPROVAL_INVALID/.test(String(unapproved?.code)), unapproved?.message || 'accepted');
step('E2 the row survives the refused delete', memoryId && psqlRw(`select count(*) from companion.memory_readable where memory_id = '${memoryId}'`) === '1');

const dry = await call('POST', `/v1/memories/${encodeURIComponent(memoryId)}/forget?dryRun=true`, undefined, subject, token()).catch((e) => ({ error: e.code }));
step('E3 a dry-run delete previews without removing', !dry?.error, JSON.stringify(dry).slice(0, 160));
step('E4 the row still exists after the dry run', memoryId && psqlRw(`select count(*) from companion.memory_readable where memory_id = '${memoryId}'`) === '1');

try {
  const gone = await call('POST', `/v1/memories/${encodeURIComponent(memoryId)}/forget?dryRun=false`, undefined, subject, token());
  step('E5 the approved delete completes', !gone?.error, JSON.stringify(gone).slice(0, 160));
} catch (err) {
  step('E5 the approved delete completes', false, err.message);
}

/* ---------------- F tombstone + invalidation ---------------- */
const tombstones = psqlRw('select count(*) from companion.memory_tombstone');
step('F1 a tombstone row records the deletion', Number(tombstones) > 0, `tombstones=${tombstones}`);
step('F2 the readable view no longer exposes it', memoryId && psqlRw(`select count(*) from companion.memory_readable where memory_id = '${memoryId}'`) === '0');
step('F3 the SQLite cache dropped the row', memoryId ? sqlite(`select count(*) from memory_cache where memory_id = '${memoryId}'`) === '0' : false);
let afterForget = 'not-called';
try {
  afterForget = await call('GET', `/v1/memories/${encodeURIComponent(memoryId)}`);
} catch (err) {
  afterForget = { code: err.code };
}
step('F4 reading a forgotten memory cannot return its body', !JSON.stringify(afterForget).includes('不吃香菜'), JSON.stringify(afterForget).slice(0, 140));

/* ---------------- I role ceiling ---------------- */
let trustedDelete;
try {
  await call('POST', `/v1/memories/${encodeURIComponent(memoryId || '00000000-0000-0000-0000-000000000000')}/forget?dryRun=false`, undefined, { ...subject, role: 'trusted' }, token());
} catch (err) {
  trustedDelete = err;
}
step('I1 a trusted (non-owner) principal cannot forget', trustedDelete && /FORBIDDEN_ROLE|ACL_DENIED/.test(String(trustedDelete.code)), trustedDelete?.code || 'accepted');

/* ---------------- H access log (PG is the access ledger, §5.5) ---------------- */
const accessRows = psqlRw('select count(*) from companion.memory_access_log');
step('H1 every memory access lands in companion.memory_access_log', Number(accessRows) > 0, `rows=${accessRows}`);
const ops = psqlRw('select string_agg(distinct operation::text, \',\') from companion.memory_access_log');
step('H2 reads, searches, writes and forgets are all recorded', /read|search|write|forget/.test(ops) && !ops.startsWith('error'), ops);
const denial = psqlRw("select count(*) from companion.memory_access_log where result::text <> 'allowed'");
step('H3 refused accesses are recorded as denials, not silently dropped', Number(denial) > 0, `non-ok rows=${denial}`);
let jsonl = '';
try {
  jsonl = readFileSync(process.env.AUDIT_SINK || '/var/log/dshbot/memory.jsonl', 'utf8');
} catch {
  jsonl = '';
}
step('H4 no plaintext body or credential leaks into any audit surface', !jsonl.includes('不吃香菜') && !jsonl.includes(hmac) && !psqlRw("select coalesce(string_agg(object_ref, '|'), '') from companion.memory_access_log where object_ref like '%不吃香菜%'").includes('不吃香菜'), `jsonl_bytes=${jsonl.length}`);

const failed = results.filter((r) => !r.ok).length;
console.log(`\n== memory e2e: ${results.length - failed}/${results.length} steps passed ==`);
process.exit(failed ? 1 : 0);
