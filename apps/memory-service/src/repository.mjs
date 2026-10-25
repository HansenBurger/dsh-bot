/**
 * repository — PG-side memory operations (t4 §4 / §5 / §7).
 *
 * Every method here is the only place that touches authority tables; the HTTP
 * layer stays policy-free and the L1 cache stays disposable.
 *
 * Invariants enforced in code, mirroring DB CHECKs so a failure is a clean 4xx
 * rather than a 500 from a constraint violation:
 *   - exactly one of plain/encrypted value is written (§3.3 CHECK)
 *   - sensitivity 'secret' is refused outright, never stored encrypted (§5.1)
 *   - read paths run on the `ro` pool; writes on `rw`
 *   - every access, including denials, lands in memory_access_log (§5.5)
 */

import { createHash, randomUUID } from 'node:crypto';
import { sanitizeForStorage, detectSecretClass, tagRisk } from '@dsh-bot/bot-sanitize';

const sha256 = (s) => createHash('sha256').update(String(s ?? ''), 'utf8').digest('hex');

/** Closed vocabulary from companion.memory_class (M-01 asserts 8 enums exist). */
export const MEMORY_CLASSES = Object.freeze(['profile', 'preference', 'commitment', 'episode', 'sentiment', 'session_ctx', 'pii_raw']);
export const SENSITIVITIES = Object.freeze(['public', 'internal', 'pii', 'secret']);
export const VISIBILITIES = Object.freeze(['private', 'peer', 'owner', 'admin']);

export class ServiceError extends Error {
  constructor(code, message, status = 400, details) {
    super(message);
    this.name = 'ServiceError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export class MemoryRepository {
  /**
   * @param {{pg: import('./pg.mjs').PgAccess, l1: import('./l1.mjs').L1Cache, config: {kek:string, maxSearchRows:number, maxSearchChars:number}}} deps
   */
  constructor(deps) {
    this.pg = deps.pg;
    this.l1 = deps.l1;
    this.cache = deps.cache || null;
    this.config = deps.config;
    this.audit = deps.audit || null;
    this.policyCache = null;
    this.policyCachedAt = 0;
    this.cacheStats = { put: 0, hit: 0, miss: 0, refused: 0 };
  }

  /**
   * Dual-write helper (task requirement "写入时双写 PG + SQLite").
   * PG already committed when this runs, so a cache failure can only ever degrade
   * latency — it must never turn a successful write into a 500.
   */
  #cachePut(memory) {
    if (!this.cache) return;
    if (memory.sensitivity === 'pii' || memory.sensitivity === 'secret') return;
    try {
      const stored = this.cache.put(memory);
      if (stored) this.cacheStats.put += 1;
      else this.cacheStats.refused += 1;
    } catch (err) {
      process.stderr.write(`${JSON.stringify({ ts: Date.now(), type: 'sandbox.denied', service: 'memory-service', stage: 'cache-put', message: String(err.message).slice(0, 100) })}\n`);
    }
  }

  /**
   * Any durable change invalidates every search projection. Generation bumping is
   * cheap and coarse on purpose: the alternative (per-key invalidation) is where
   * cache-consistency bugs live.
   */
  #invalidateSearches() {
    if (!this.cache) return;
    try {
      this.cache.bumpGeneration();
    } catch (err) {
      process.stderr.write(`${JSON.stringify({ ts: Date.now(), type: 'sandbox.denied', service: 'memory-service', stage: 'cache-invalidate', message: String(err.message).slice(0, 100) })}\n`);
    }
  }

  cacheStatsReport() {
    const total = this.cacheStats.hit + this.cacheStats.miss;
    return { ...this.cacheStats, hitRate: total ? Number((this.cacheStats.hit / total).toFixed(4)) : 0 };
  }

  /* ---------------------------------------------------------------- *
   * policy (class → ttl / approval / encryption), cached 60 s
   * ---------------------------------------------------------------- */

  async policyFor(class_) {
    const now = Date.now();
    if (!this.policyCache || now - this.policyCachedAt > 60_000) {
      const { rows } = await this.pg.query(
        'ro',
        `SELECT class, layer, ttl_days, requires_approval, encrypt_at_rest, max_body_chars, recency_half_life_days, allow_auto_write
           FROM companion.memory_class_policy`,
      );
      this.policyCache = new Map(rows.map((r) => [r.class, r]));
      this.policyCachedAt = now;
    }
    return this.policyCache.get(class_);
  }

  /** DEK derived per class from the KEK (HKDF-lite via HMAC of the domain string). */
  /**
   * The crypto domain a row's DEK is derived from (t4 §5.2: "DEK（per-class）, 由
   * KEK + class 派生").
   *
   * ⚠ Measured deviation, on purpose: a `pii_raw` write lands in `user_profile`
   * (layer 2 per 003_seed_policy.sql), and `companion.memory_readable` reports the
   * class of every profile row as `'profile'`. Keying the DEK on the requested class
   * therefore produces a ciphertext the read path cannot open — the second read of a
   * PII row failed with pgcrypto "Wrong key or corrupt data" (not a corruption of the
   * data, an unrecoverable key mismatch). The domain must be a value that survives
   * the round trip, so encrypted rows are keyed on **sensitivity**, which the view
   * preserves verbatim; unencrypted classes keep their class-derived domain.
   * Today only pii_raw / sensitivity=pii is ever encrypted, so this is one stable
   * domain, not a per-row secret.
   */
  cryptoDomain({ class: class_, sensitivity }) {
    if (sensitivity === 'pii' || sensitivity === 'secret') return `sens:${sensitivity}`;
    return `class:${class_}`;
  }

  dekFor(domain) {
    const key = this.config.kek;
    if (!key || key.length < 16) throw new ServiceError('INTERNAL', 'memory KEK unavailable', 503);
    // Domain separation keeps a per-domain DEK from being reproducible across domains.
    return sha256(`dshbot-memory-dek:v1:${domain}:${key}`);
  }

  /* ---------------------------------------------------------------- *
   * subject resolution
   * ---------------------------------------------------------------- */

  /**
   * Upsert the subject row for a structured key like `telegram:dm:111`.
   * identity_trust decides whether owner is even possible (C-03/A3: QQ has no
   * server-backed identity, so the DB CHECK rejects owner there).
   */
  async ensureSubject({ subjectKey, channel, externalId, peerKind, identityTrust = 'unknown', isOwner = false }) {
    if (!/^[a-z0-9_]+:[a-z]+:.+$/.test(subjectKey)) {
      throw new ServiceError('BAD_REQUEST', 'subjectKey must be channel:kind:id', 400);
    }
    const trust = ['server_backed', 'unbacked', 'unknown'].includes(identityTrust) ? identityTrust : 'unknown';
    const owner = Boolean(isOwner) && trust === 'server_backed';
    // pg.transaction() resolves to whatever the callback returns (an array of rows
    // here) — NOT a {rows} object like pool.query(). Conflating the two shapes is an
    // undefined-at-runtime bug, so the shape is spelled out at each call site.
    const rows = await this.pg.transaction('rw', async (client) => {
      const res = await client.query(
        `INSERT INTO companion.subject (subject_key, channel, external_id, peer_kind, identity_trust, is_owner)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (subject_key) DO UPDATE
           SET last_seen_at = now(),
               -- never downgrade an existing owner flag silently; upsert only strengthens
               -- trust evidence when the channel actually provides it
               identity_trust = CASE WHEN EXCLUDED.identity_trust = 'server_backed' THEN EXCLUDED.identity_trust ELSE companion.subject.identity_trust END,
               is_owner = companion.subject.is_owner OR EXCLUDED.is_owner
         RETURNING subject_id`,
        [subjectKey, channel, externalId, peerKind, trust, owner],
      );
      return res.rows;
    });
    return rows[0].subject_id;
  }

  async subjectByKey(subjectKey) {
    const { rows } = await this.pg.query('ro', `SELECT subject_id, identity_trust, is_owner FROM companion.subject WHERE subject_key = $1`, [subjectKey]);
    return rows[0] || null;
  }

  /* ---------------------------------------------------------------- *
   * WRITE (L2 upsert / L3 insert) — §4.1
   * ---------------------------------------------------------------- */

  /**
   * @param {object} req - validated WriteRequest body
   * @param {object} principal - verified {channel, chatId, userId, role}
   * @returns {{memoryId:string, deduped:boolean, conflict:boolean, encrypted:boolean, sanitizedRiskTags:string[], version:number}}
   */
  async write(req, principal) {
    const policy = await this.policyFor(req.class);
    if (!policy) throw new ServiceError('UNKNOWN_CLASS', 'class is not in the policy table', 400, { class: req.class });

    // §5.1 secret class: refuse, do not encrypt-and-store.
    const secretHit = detectSecretClass(req.body);
    if (secretHit.refused || req.sensitivity === 'secret') {
      await this.logAccess({ principal, operation: 'refuse', objectRef: sha256(`${req.subjectKey}|${req.class}|${req.attrKey || ''}`), class_: req.class, sensitivity: 'secret', result: 'denied', approved: false, riskTags: [`secret-class:${secretHit.reason}`] });
      throw new ServiceError('MEMORY_REFUSED_CATEGORY', '该类别的内容不会被记住（密码/密钥类一律拒存）', 422, { reason: secretHit.reason });
    }

    // §4.5 rule 1 — write-side decontamination before anything durable happens.
    const sanitized = sanitizeForStorage(req.body, { maxChars: Number(policy.max_body_chars) });
    if (sanitized.emptyAfterSanitize) {
      throw new ServiceError('SANITIZED_EMPTY', '内容消毒后为空，未写入', 422);
    }

    // High-risk candidates are never auto-frozen: they queue for a human instead
    // (A6 "tag, don't drop" applied to the storage side).
    const incomingTags = [...new Set([...(req.riskTags || []), ...tagRisk(sanitized.text)])];
    const poisonSuspect = incomingTags.length > 0;

    const normalized = normalizeText(sanitized.text);
    const dedupeKey = sha256(`${req.subjectKey}|${req.class}|${normalized}`);
    const subjectId = await this.ensureSubject({
      subjectKey: req.subjectKey,
      channel: String(req.subjectKey.split(':')[0]),
      externalId: String(req.subjectKey.split(':').slice(2).join(':')),
      peerKind: peerKindFromScope(req.scope),
      identityTrust: principal.channel === 'telegram' ? 'server_backed' : 'unbacked',
      isOwner: principal.role === 'owner',
    });

    const sensitivity = req.sensitivity || (req.class === 'pii_raw' ? 'pii' : 'internal');
    const encrypt = Boolean(policy.encrypt_at_rest) || sensitivity === 'pii' || req.class === 'pii_raw';
    const visibility = req.visibility || (req.scope === 'group' ? 'peer' : 'private');

    // Approval requirement is re-checked server-side: the tool gate is the first
    // line, but a direct caller must not get a pass because it skipped the agent.
    if (policy.requires_approval && !req.approvalId) {
      await this.logAccess({ principal, operation: 'write', objectRef: dedupeKey, class_: req.class, sensitivity, result: 'denied', approved: false, riskTags: incomingTags });
      throw new ServiceError('APPROVAL_REQUIRED', '写入长期记忆需要一次性审批令牌', 403);
    }

    if (poisonSuspect) {
      const conflictId = await this.queueConflict({
        subjectId,
        attrKey: req.attrKey || `${req.class}:body`,
        existingKind: req.class === 'preference' ? 'preference' : 'episode',
        existingRef: null,
        incomingHash: sha256(sanitized.text),
        incomingMeta: { class: req.class, sensitivity, risk_tags: incomingTags, source_ref: req.sourceRef || null },
        reason: 'risk_tagged',
      });
      await this.logAccess({ principal, operation: 'write', objectRef: conflictId, class_: req.class, sensitivity, result: 'allowed', approved: true, riskTags: incomingTags, note: 'queued-as-conflict' });
      return { memoryId: conflictId, deduped: false, conflict: true, encrypted: false, sanitizedRiskTags: sanitized.stripped, version: 0 };
    }

    const body = sanitized.text;
    const domain = this.cryptoDomain({ class: req.class, sensitivity });
    const valueEnc = encrypt ? await this.encrypt(body, domain) : null;
    const valuePlain = encrypt ? null : body;

    if (req.class === 'profile' || req.class === 'pii_raw') {
      return this.upsertProfile({ subjectId, attrKey: req.attrKey || defaultAttrKey(req.class, body), valuePlain, valueEnc, sensitivity, visibility, dedupeKey, confidence: req.confidence ?? 0.5, sourceRef: req.sourceRef, principal, encrypted: encrypt, stripped: sanitized.stripped });
    }
    if (req.class === 'preference') {
      return this.upsertPreference({ subjectId, scope: req.scope || 'dm', scopePeer: req.scopePeer, prefKey: req.attrKey || defaultAttrKey(req.class, body), valuePlain, valueEnc, sensitivity, visibility, dedupeKey, sourceRef: req.sourceRef, principal, encrypted: encrypt, stripped: sanitized.stripped });
    }
    // L3 episodic family: commitment / episode / sentiment
    return this.insertEpisode({
      subjectId,
      peerKey: `${principal.channel}:${principal.chatId}`,
      class: req.class,
      bodyPlain: valuePlain,
      bodyEnc: valueEnc,
      sensitivity,
      visibility,
      occurredAt: req.occurredAt || new Date().toISOString(),
      expiresAt: expiresFrom(req.ttlDays, policy.ttl_days),
      confidence: req.confidence ?? 0.5,
      riskTags: incomingTags,
      sourceChannel: principal.channel,
      sourceRef: req.sourceRef,
      approvedBy: req.approvalId,
      dedupeKey,
      principal,
      encrypted: encrypt,
      stripped: sanitized.stripped,
    });
  }

  async upsertProfile(fields) {
    const result = await this.pg.transaction('rw', async (client) => {
      // Dedupe first: same subject+attr with identical normalized text bumps counters
      // instead of creating a second active row (§4.1 —伴侣场景重复率极高).
      const dup = await client.query(
        `SELECT profile_id, version, value_plain FROM companion.user_profile
          WHERE subject_id = $1 AND attr_key = $2 AND superseded_by IS NULL`,
        [fields.subjectId, fields.attrKey],
      );
      if (dup.rows.length === 0) {
        const ins = await client.query(
          `INSERT INTO companion.user_profile
             (subject_id, attr_key, value_plain, value_enc, sensitivity, confidence, dedupe_key, source_ref, version, visibility)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,1,$9) RETURNING profile_id, version`,
          [fields.subjectId, fields.attrKey, fields.valuePlain, fields.valueEnc, fields.sensitivity, fields.confidence, fields.dedupeKey, fields.sourceRef ?? null, fields.visibility],
        );
        return { memoryId: ins.rows[0].profile_id, deduped: false, conflict: false, version: 1 };
      }
      const existing = dup.rows[0];
      const sameValue = fields.valuePlain !== null && normalizeText(existing.value_plain || '') === normalizeText(fields.valuePlain);
      if (sameValue) {
        await client.query(`UPDATE companion.user_profile SET hit_count = hit_count + 1, updated_at = now() WHERE profile_id = $1`, [existing.profile_id]);
        return { memoryId: existing.profile_id, deduped: true, conflict: false, version: Number(existing.version) };
      }
      // §4.4: never silently overwrite a contradicting fact — open a conflict row and
      // leave both values in place for the owner to adjudicate.
      const conflictId = await this.queueConflict({
        subjectId: fields.subjectId,
        attrKey: fields.attrKey,
        existingKind: 'profile',
        existingRef: existing.profile_id,
        incomingHash: sha256(fields.valuePlain ?? 'encrypted'),
        incomingMeta: { sensitivity: fields.sensitivity, source_ref: fields.sourceRef ?? null },
        reason: 'contradiction',
      }, client);
      return { memoryId: conflictId, deduped: false, conflict: true, version: Number(existing.version) };
    });
    await this.logAccess({ principal: fields.principal, operation: 'write', objectRef: result.memoryId, objectKind: 'profile', class_: 'profile', sensitivity: fields.sensitivity, result: 'allowed', approved: true, riskTags: [] });
    if (!result.conflict) {
      this.#cachePut({
        memoryId: result.memoryId,
        kind: 'profile',
        subjectId: fields.subjectId,
        peerKey: null,
        class: 'profile',
        attrKey: fields.attrKey,
        body: fields.valuePlain,
        sensitivity: fields.sensitivity,
        visibility: fields.visibility,
        occurredAt: new Date().toISOString(),
        expiresAt: null,
      });
      this.#invalidateSearches();
    }
    return { ...result, encrypted: fields.encrypted, sanitizedRiskTags: fields.stripped };
  }

  async upsertPreference(fields) {
    const scope = fields.scope || 'dm';
    const scopePeer = scope === 'global' ? null : fields.scopePeer || null;
    if (scope !== 'global' && !scopePeer) throw new ServiceError('BAD_REQUEST', '非 global 作用域需要 scopePeer', 400);
    // pg.transaction() resolves to whatever the callback returns (an array of rows
    // here) — NOT a {rows} object like pool.query(). Conflating the two shapes is an
    // undefined-at-runtime bug, so the shape is spelled out at each call site.
    const rows = await this.pg.transaction('rw', async (client) => {
      const res = await client.query(
        `INSERT INTO companion.user_preference
           (subject_id, scope, scope_peer, pref_key, value_plain, value_enc, sensitivity, dedupe_key, source_ref, visibility)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
         ON CONFLICT (subject_id, scope, peer_slot, pref_key) DO UPDATE
           SET value_plain = EXCLUDED.value_plain,
               value_enc   = EXCLUDED.value_enc,
               sensitivity = EXCLUDED.sensitivity,
               updated_at  = now()
         RETURNING pref_id AS id`,
        [fields.subjectId, scope, scopePeer, fields.prefKey, fields.valuePlain, fields.valueEnc, fields.sensitivity, fields.dedupeKey, fields.sourceRef ?? null, fields.visibility],
      );
      return res.rows;
    });
    await this.logAccess({ principal: fields.principal, operation: 'write', objectRef: rows[0].id, objectKind: 'preference', class_: 'preference', sensitivity: fields.sensitivity, result: 'allowed', approved: true, riskTags: [] });
    this.#cachePut({
      memoryId: rows[0].id,
      kind: 'preference',
      subjectId: fields.subjectId,
      peerKey: fields.scopePeer ?? null,
      class: 'preference',
      body: fields.valuePlain,
      sensitivity: fields.sensitivity,
      visibility: fields.visibility,
      occurredAt: new Date().toISOString(),
      expiresAt: null,
    });
    this.#invalidateSearches();
    return { memoryId: rows[0].id, deduped: false, conflict: false, encrypted: fields.encrypted, sanitizedRiskTags: fields.stripped, version: 1 };
  }

  async insertEpisode(fields) {
    // Dedupe window: identical episode for the same subject bumps the counter only.
    const seen = await this.pg.query(
      'rw',
      `SELECT episode_id FROM companion.memory_episode WHERE subject_id = $1 AND dedupe_key = $2 AND superseded_by IS NULL LIMIT 1`,
      [fields.subjectId, fields.dedupeKey],
    );
    if (seen.rows.length > 0) {
      await this.pg.query('rw', `UPDATE companion.memory_episode SET hit_count = hit_count + 1, last_seen_at = now() WHERE episode_id = $1`, [seen.rows[0].episode_id]);
      await this.logAccess({ principal: fields.principal, operation: 'write', objectRef: seen.rows[0].episode_id, objectKind: 'episode', class_: fields.class, sensitivity: fields.sensitivity, result: 'allowed', approved: true, riskTags: fields.riskTags });
      return { memoryId: seen.rows[0].episode_id, deduped: true, conflict: false, encrypted: fields.encrypted, sanitizedRiskTags: fields.stripped, version: 1 };
    }
    const { rows } = await this.pg.query(
      'rw',
      `INSERT INTO companion.memory_episode
         (subject_id, peer_key, class, body_plain, body_enc, body_hash, dedupe_key, sensitivity, visibility,
          occurred_at, expires_at, confidence, risk_tags, source_channel, source_ref, approved_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
       RETURNING episode_id`,
      [
        fields.subjectId, fields.peerKey, fields.class, fields.bodyPlain, fields.bodyEnc,
        sha256(fields.bodyPlain ?? `enc:${fields.subjectId}:${fields.dedupeKey}`), fields.dedupeKey,
        fields.sensitivity, fields.visibility, fields.occurredAt, fields.expiresAt, fields.confidence,
        fields.riskTags, fields.sourceChannel, fields.sourceRef ?? null, fields.approvedBy ?? null,
      ],
    );
    const memoryId = rows[0].episode_id;
    await this.logAccess({ principal: fields.principal, operation: 'write', objectRef: memoryId, objectKind: 'episode', class_: fields.class, sensitivity: fields.sensitivity, result: 'allowed', approved: true, riskTags: fields.riskTags });
    // Dual-write (PG committed → SQLite projection). Encrypted rows are skipped by
    // the cache itself, so this call is what guarantees "no plaintext copy in L1".
    this.#cachePut({
      memoryId,
      kind: 'episode',
      subjectId: fields.subjectId,
      peerKey: fields.peerKey,
      class: fields.class,
      body: fields.bodyPlain,
      sensitivity: fields.sensitivity,
      visibility: fields.visibility,
      occurredAt: fields.occurredAt,
      expiresAt: fields.expiresAt,
    });
    this.#invalidateSearches();
    return { memoryId, deduped: false, conflict: false, encrypted: fields.encrypted, sanitizedRiskTags: fields.stripped, version: 1 };
  }

  /* ---------------------------------------------------------------- *
   * READ — single memory with ACL (§5.6) + decrypt audit (§5.5)
   * ---------------------------------------------------------------- */

  async read(memoryId, principal) {
    principal = await this.#withCallerSubjects(principal);
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(memoryId)) {
      throw new ServiceError('BAD_REQUEST', 'memoryId must be a uuid', 400);
    }
    // SQLite first (task requirement). An L1 hit still runs `assertVisible`, because
    // a cache that skipped the ACL would be an information leak, not an optimisation.
    if (this.cache) {
      const cached = this.cache.get(memoryId);
      if (cached) {
        this.assertVisible(cached, principal);
        this.cacheStats.hit += 1;
        await this.logAccess({ principal, operation: 'read', objectRef: memoryId, objectKind: cached.kind, class_: cached.class, sensitivity: cached.sensitivity, result: 'allowed', approved: true, riskTags: [], source: 'l1-cache' });
        return { ...cached, retrievalStrategy: 'l1-cache' };
      }
      this.cacheStats.miss += 1;
    }
    const { rows } = await this.pg.query(
      'ro',
      `SELECT memory_id, kind, subject_id, peer_key, class, body_plain, body_enc, sensitivity, visibility,
              occurred_at, expires_at, hit_count, confidence, risk_tags, source_channel
         FROM companion.memory_readable
        WHERE memory_id = $1`,
      [memoryId],
    );
    // 404 covers "absent", "deleted" and "not visible to you" identically so the
    // response cannot be used to probe which memories exist (openapi §/v1/memories/{id}).
    if (rows.length === 0) {
      await this.logAccess({ principal, operation: 'read', objectRef: memoryId, result: 'denied', approved: false, riskTags: [] });
      throw new ServiceError('ACL_DENIED', '记忆不存在或不可见', 404);
    }
    const row = rows[0];
    this.assertVisible(row, principal);

    let body = row.body_plain;
    if (row.body_enc !== null) {
      body = await this.decrypt(row.body_enc, this.cryptoDomain(row));
      await this.logAccess({ principal, operation: 'decrypt', objectRef: memoryId, objectKind: row.kind, class_: row.class, sensitivity: row.sensitivity, result: 'allowed', approved: true, riskTags: [] });
    }
    await this.pg.query('rw', `UPDATE companion.memory_episode SET hit_count = hit_count + 1, last_seen_at = now() WHERE episode_id = $1`, [memoryId]).catch(() => {});
    await this.logAccess({ principal, operation: 'read', objectRef: memoryId, objectKind: row.kind, class_: row.class, sensitivity: row.sensitivity, result: 'allowed', approved: true, riskTags: row.risk_tags || [], source: 'pg' });
    const mapped = mapMemory(row, body);
    // Backfill only unencrypted rows: §5.2 forbids a plaintext copy of PII in L1.
    this.#cachePut(mapped);
    return mapped;
  }

  /**
   * Turn a cached id projection into full rows. Every id must resolve from L1 and
   * pass the same ACL as a PG read; anything missing demotes the whole lookup to a
   * PG query (correctness over partial hits — a truncated result set would look
   * like "I remember less" rather than like a cache miss).
   */
  async #hydrateSearch(projected, principal, limit) {
    const rows = [];
    for (const id of projected.memoryIds.slice(0, limit)) {
      const row = this.cache.get(id);
      if (!row) return null;
      try {
        this.assertVisible(row, principal);
      } catch {
        return null;
      }
      rows.push(row);
    }
    if (rows.length === 0 && projected.memoryIds.length > 0) return null;
    let chars = 0;
    for (const r of rows) chars += String(r.body ?? '').length;
    this.cacheStats.hit += 1;
    return { results: rows.map((r) => ({ ...r, retrievalStrategy: 'l1-cache' })), truncated: projected.truncated, strategy: projected.strategy || {}, chars };
  }

  /**
   * Review R2: the owner exemption is bound to the owner's *identity*, not to the
   * role bit. whitelist.json may legitimately carry one owner entry per channel, so
   * `role === 'owner'` alone says nothing about WHO the row belongs to — a second
   * owner on another channel would otherwise read the first owner's private rows.
   * The bypass therefore requires the row to be the caller's own: filed under the
   * caller's DM subject (`channel:dm:userId` → subject_id) or banked in the caller's
   * own DM peer. Rows without either link stay peer-bound for every caller.
   * Dual-shape reads: PG rows carry snake_case, L1 cache rows carry camelCase.
   */
  #rowBelongsToCaller(row, principal) {
    const peer = row.peer_key ?? row.peerKey ?? null;
    const subject = row.subject_id ?? row.subjectId ?? null;
    const ownDmPeer = `${principal.channel}:${principal.userId}`;
    const ownChatPeer = `${principal.channel}:${principal.chatId}`;
    if (peer && (peer === ownDmPeer || peer === ownChatPeer)) return true;
    return Boolean(principal.dmSubjectId) && subject === principal.dmSubjectId;
  }

  /**
   * Resolve the caller's subject identities once per request. R2 bound the *owner*
   * bypass to `channel:dm:userId`; review N1 extends the same identity machinery to
   * every caller, because the L2 KV legs carry no reliable peer_key - the subject link
   * is the only identity they have, and without it any non-owner caller read every
   * other subject's profile/preference rows. `groupSubjectId` is resolved only when
   * the call arrives from a chat that is not the caller's own DM.
   */
  async #withCallerSubjects(principal) {
    if (principal.dmSubjectId !== undefined) return principal;
    const dm = await this.subjectByKey(`${principal.channel}:dm:${principal.userId}`);
    let group = null;
    if (principal.chatId !== principal.userId) {
      group = await this.subjectByKey(`${principal.channel}:group:${principal.chatId}`);
    }
    return {
      ...principal,
      dmSubjectId: dm?.subject_id ?? null,
      groupSubjectId: group?.subject_id ?? null,
    };
  }

  /** Rows without a peer dimension (profiles, global prefs) are scoped by subject. */
  #subjectIsCaller(row, principal) {
    const subject = row.subject_id ?? row.subjectId ?? null;
    if (!subject || principal.role === 'public') return false;
    if (principal.dmSubjectId && subject === principal.dmSubjectId) return true;
    return Boolean(principal.groupSubjectId) && subject === principal.groupSubjectId;
  }

  assertVisible(row, principal) {
    const peerKey = `${principal.channel}:${principal.chatId}`;
    const rowPeer = row.peer_key ?? row.peerKey ?? null;
    const ownerSelf = principal.role === 'owner' && this.#rowBelongsToCaller(row, principal);
    switch (row.visibility) {
      case 'admin':
        // Never model-visible: only the owner CLI path may read it.
        throw new ServiceError('ACL_DENIED', '记忆不存在或不可见', 404);
      case 'owner':
        if (principal.role !== 'owner') throw new ServiceError('ACL_DENIED', '记忆不存在或不可见', 404);
        if (!ownerSelf) throw new ServiceError('ACL_DENIED', '记忆不存在或不可见', 404);
        return;
      case 'peer':
        if (rowPeer && rowPeer !== peerKey && !ownerSelf) {
          throw new ServiceError('PEER_BOUNDARY_VIOLATION', '记忆不存在或不可见', 404);
        }
        // Review N1: a 'peer' row *without* a peer dimension (profile KV) has no chat
        // to hide behind - fall back to the subject link, exactly like the SQL legs.
        if (!rowPeer && !ownerSelf && !this.#subjectIsCaller(row, principal)) {
          throw new ServiceError('PEER_BOUNDARY_VIOLATION', '记忆不存在或不可见', 404);
        }
        return;
      case 'private':
      default:
        // private: readable by the subject themself in their own DM, or by the owner
        // of the row's identity (never merely by "some" owner on some channel).
        const isOwnDm = rowPeer === peerKey && principal.role !== 'public';
        // Review N1: peer-less private KV (profiles, global prefs) is scoped by subject.
        const isSelfSubject = rowPeer === null && this.#subjectIsCaller(row, principal);
        if (!isOwnDm && !isSelfSubject && !ownerSelf) throw new ServiceError('ACL_DENIED', '记忆不存在或不可见', 404);
    }
  }

  /* ---------------------------------------------------------------- *
   * SEARCH — §7.1 three-way fusion (KV + byte trigram + FTS + trgm)
   * ---------------------------------------------------------------- */

  /**
   * Phase-1 recall without vectors. Byte-trigram overlap is the CJK main path
   * because pg_trgm similarity is 0.0000 for Chinese (measured, t4 §7.1).
   *
   * @param {{query:string, class?:string[], limit?:number, since?:string, until?:string, includeExpired?:boolean}} req
   * @param {object} principal
   */
  async search(req, principal) {
    const started = Date.now();
    principal = await this.#withCallerSubjects(principal);
    const limit = Math.min(Math.max(1, Number(req.limit ?? 10)), this.config.maxSearchRows);
    const queryNorm = normalizeText(req.query);
    const qTrigrams = byteTrigrams(queryNorm);

    // ---- L1 query projection (task requirement: 读取先查 SQLite，miss 再查 PG 并回填).
    //      The key carries the *peer scope*, so one chat's projection can never be
    //      served into another chat even if the query text is identical (§5.6/M-15).
    const generationAtStart = this.cache ? this.cache.generation() : null;
    const cacheKey = this.cache
      ? sha256(`${generationAtStart}|${principal.channel}:${principal.chatId}|${principal.role}|${queryNorm}|${limit}|${(req.class || []).join(',')}|${req.since ?? ''}|${req.until ?? ''}`)
      : null;
    if (cacheKey) {
      const projected = this.cache.lookupSearch(cacheKey);
      if (projected) {
        const hydrated = await this.#hydrateSearch(projected, principal, limit);
        if (hydrated) {
          const accessLogId = await this.logAccess({ principal, operation: 'search', objectRef: sha256(queryNorm), result: 'allowed', approved: true, riskTags: [], rowsReturned: hydrated.results.length, bytesOut: hydrated.chars, latencyMs: Date.now() - started, source: 'l1-cache' });
          return { ...hydrated, tookMs: Date.now() - started, accessLogId, cacheHit: true };
        }
      }
      this.cacheStats.miss += 1;
    }

    // ---- L3 episodes: byte-trigram recall through the GIN index (CJK main path).
    //      $1 channel, $2 chatId, $3 role, $4 raw query, $5 userId, $6 owner subject id.
    const epParams = [principal.channel, principal.chatId, principal.role, req.query, principal.userId, principal.dmSubjectId ?? null];
    // Review R2: the "$3 = 'owner'" bypass is bound to the caller's own identity —
    // rows filed under channel:dm:userId, or banked in the caller's own DM peer.
    // A second owner entry on another channel matches neither and reads nothing.
    const ownerSelf = "(e.peer_key = $1 || ':' || $5 OR e.subject_id = $6)";
    const epWhere = [
      'e.superseded_by IS NULL',
      '(e.expires_at IS NULL OR e.expires_at > now())',
      // ACL predicate lives in SQL, not in JS string concatenation (§5.6).
      `(
           (e.visibility = 'owner' AND $3 = 'owner' AND ${ownerSelf})
        OR (e.visibility IN ('private','peer') AND (e.peer_key = $1 || ':' || $2 OR ($3 = 'owner' AND ${ownerSelf})))
       )`,
      "companion.byte_trgm(coalesce(e.body_plain, '')) && companion.byte_trgm($4)",
    ];
    if (Array.isArray(req.class) && req.class.length > 0) {
      for (const c of req.class) {
        if (!MEMORY_CLASSES.includes(c)) throw new ServiceError('UNKNOWN_CLASS', 'class 不在封闭枚举内', 400, { class: c });
      }
      epParams.push(req.class);
      epWhere.push(`e.class = ANY($${epParams.length}::companion.memory_class[])`);
    }
    if (req.since) {
      epParams.push(req.since);
      epWhere.push(`e.occurred_at >= $${epParams.length}`);
    }
    if (req.until) {
      epParams.push(req.until);
      epWhere.push(`e.occurred_at <= $${epParams.length}`);
    }
    epParams.push(limit * 4); // over-fetch: scoring happens in JS, then we trim

    const episodeSql = `
      SELECT e.episode_id AS memory_id, 'episode' AS kind, e.subject_id, e.peer_key, e.class::text AS class,
             e.body_plain, e.body_enc, e.sensitivity::text AS sensitivity, e.visibility::text AS visibility,
             e.occurred_at, e.expires_at, e.hit_count, e.confidence, e.risk_tags, e.source_channel, e.source_ref,
             companion.byte_trgm(coalesce(e.body_plain, '')) AS row_trigrams,
             to_tsvector('simple', coalesce(e.body_plain, '')) @@ plainto_tsquery('simple', $4) AS fts_hit,
             COALESCE(similarity(lower(coalesce(e.body_plain, '')), lower($4)), 0) AS trgm_sim,
             GREATEST(EXTRACT(epoch FROM (now() - e.occurred_at)) / 86400.0, 0) AS age_days
        FROM companion.memory_episode e
       WHERE ${epWhere.join('\n         AND ')}
       ORDER BY e.occurred_at DESC
       LIMIT $${epParams.length}`;

    // ---- L2 profile/preference KV hits: attribute or value match wins outright.
    //      Review N1: the KV legs used to filter visibility only - any non-owner
    //      caller fetched every other subject's rows. KV carries no episode-style
    //      peer key, so the identity predicate is the *subject* link ($5 own dm,
    //      $6 own group), with the preference leg additionally honouring rows filed
    //      in the caller's own chat ($7:$8). Same construction as the episode leg.
    const kvParams = [
      req.query,
      principal.role,
      queryNorm.slice(0, 64),
      limit,
      principal.dmSubjectId ?? null,
      principal.groupSubjectId ?? null,
    ];
    // the preference leg additionally binds the caller's own chat for scope_peer
    const prefParams = [...kvParams, principal.channel, principal.chatId];
    const kvSql = `
      SELECT p.profile_id AS memory_id, 'profile' AS kind, p.subject_id, NULL::text AS peer_key,
             'profile' AS class, p.attr_key, p.value_plain AS body_plain, p.value_enc AS body_enc,
             p.sensitivity::text AS sensitivity, p.visibility::text AS visibility,
             p.created_at AS occurred_at, NULL::timestamptz AS expires_at, p.hit_count, p.confidence,
             '{}'::text[] AS risk_tags, NULL::text AS source_channel, p.source_ref
        FROM companion.user_profile p
       WHERE p.superseded_by IS NULL
         AND p.visibility <> 'admin'
         AND (p.visibility <> 'owner' OR ($2 = 'owner' AND p.subject_id = $5))
         AND (p.subject_id = $5 OR p.subject_id = $6)
         AND (companion.byte_trgm(coalesce(p.value_plain, '')) && companion.byte_trgm($1)
              OR lower(coalesce(p.value_plain, '')) LIKE '%' || $3 || '%'
              OR lower(p.attr_key) LIKE '%' || $3 || '%')
       ORDER BY p.updated_at DESC
       LIMIT $4`;

    const prefSql = `
      SELECT f.pref_id AS memory_id, 'preference' AS kind, f.subject_id, f.scope_peer AS peer_key,
             'preference' AS class, f.pref_key AS attr_key, f.value_plain AS body_plain, f.value_enc AS body_enc,
             f.sensitivity::text AS sensitivity, f.visibility::text AS visibility,
             f.created_at AS occurred_at, NULL::timestamptz AS expires_at, 1 AS hit_count, 1.0::real AS confidence,
             '{}'::text[] AS risk_tags, NULL::text AS source_channel, f.source_ref
        FROM companion.user_preference f
       WHERE f.visibility <> 'admin'
         AND (f.visibility <> 'owner' OR ($2 = 'owner' AND f.subject_id = $5))
         AND (f.subject_id = $5 OR f.subject_id = $6 OR f.scope_peer = $7 || ':' || $8)
         AND (companion.byte_trgm(coalesce(f.value_plain, '')) && companion.byte_trgm($1)
              OR lower(coalesce(f.value_plain, '')) LIKE '%' || $3 || '%'
              OR lower(f.pref_key) LIKE '%' || $3 || '%')
       ORDER BY f.updated_at DESC
       LIMIT $4`;

    const [episodes, profiles, preferences] = await Promise.all([
      this.pg.query('ro', episodeSql, epParams).then((r) => r.rows),
      this.pg.query('ro', kvSql, kvParams).then((r) => r.rows),
      this.pg.query('ro', prefSql, prefParams).then((r) => r.rows),
    ]);

    const scored = [];
    for (const row of episodes) {
      const rowTri = new Set(row.row_trigrams || []);
      let intersection = 0;
      for (const t of qTrigrams) if (rowTri.has(t)) intersection += 1;
      const overlap = qTrigrams.size ? intersection / qTrigrams.size : 0;
      const halfLife = HALF_LIFE[row.class] ?? null;
      const decay = halfLife ? Math.exp(-Number(row.age_days) / halfLife) : 1;
      const score = 0.5 * overlap + 0.25 * (row.fts_hit ? 1 : 0) + 0.15 * Number(row.trgm_sim) + 0.1 * decay;
      scored.push({ row, score, strategy: 'byte_trgm' });
    }
    for (const row of [...profiles, ...preferences]) scored.push({ row, score: 1.0, strategy: 'kv' });
    scored.sort((a, b) => b.score - a.score);

    // Budget guardrail: ≤20 rows and ≤4000 characters total (E-1/E-4, M-18).
    const results = [];
    let chars = 0;
    let truncated = false;
    for (const item of scored) {
      if (results.length >= limit) {
        truncated = true;
        break;
      }
      let body = item.row.body_plain;
      if (body === null && item.row.body_enc !== null) {
        try {
          body = await this.decrypt(item.row.body_enc, this.cryptoDomain(item.row));
          await this.logAccess({ principal, operation: 'decrypt', objectRef: item.row.memory_id, objectKind: item.row.kind, class_: item.row.class, sensitivity: item.row.sensitivity, result: 'allowed', approved: true, riskTags: [] });
        } catch {
          continue; // an undecryptable row must not abort the whole search
        }
      }
      const text = String(body ?? '');
      if (chars + text.length > this.config.maxSearchChars) {
        truncated = true;
        break;
      }
      chars += text.length;
      results.push(mapMemory(item.row, text, item.strategy));
    }

    // Backfill the projection: ids only, plus the row bodies that are cacheable.
    if (this.cache && cacheKey) {
      for (const r of results) this.#cachePut(r);
      this.cache.putSearch(
        cacheKey,
        results.map((r) => r.memoryId),
        truncated,
        { kvHits: profiles.length + preferences.length, byteTrigramHits: episodes.length },
        generationAtStart,
      );
    }

    const accessLogId = await this.logAccess({
      principal,
      operation: 'search',
      // D5: the audit trail stores the query hash, never the query text.
      objectRef: sha256(queryNorm),
      result: 'allowed',
      approved: true,
      riskTags: [],
      rowsReturned: results.length,
      bytesOut: chars,
      latencyMs: Date.now() - started,
    });

    return {
      results,
      truncated,
      strategy: {
        kvHits: profiles.length + preferences.length,
        byteTrigramHits: episodes.length,
        ftsHits: episodes.filter((e) => e.fts_hit).length,
        trgmHits: episodes.filter((e) => Number(e.trgm_sim) > 0.25).length,
      },
      tookMs: Date.now() - started,
      accessLogId,
    };
  }
  /* ---------------------------------------------------------------- *
   * FORGET — §5.4 physical delete + tombstone
   * ---------------------------------------------------------------- */

  /**
   * Single-memory forget. dry_run defaults to true everywhere (fail-safe).
   * The service performs the delete itself (the DB function
   * `forget_by_subject` is deliberately NOT granted to rw — belt and braces),
   * writing the tombstone BEFORE the DELETE so "what was deleted" stays provable.
   */
  async forget(memoryId, { principal, dryRun = true, approvalId }) {
    const found = await this.pg.query('ro', `SELECT memory_id, kind, class, sensitivity, body_hash, body_plain FROM companion.memory_readable WHERE memory_id = $1`, [memoryId]);
    if (found.rows.length === 0) throw new ServiceError('ACL_DENIED', '记忆不存在或已删除', 404);
    const row = found.rows[0];
    // Review R2: forget is a *role* capability (owner + approval id below), not a
    // visibility read — the owner must still be able to tombstone rows belonging to
    // other subjects (synthetic test data, moderation). The old `assertVisible(
    // {...row, visibility:'owner'})` tricked the read boundary into an admin check;
    // with the owner exemption now identity-bound that trick would deny legitimate
    // tombstones, so the gate is stated plainly instead.
    if (principal.role !== 'owner') throw new ServiceError('FORBIDDEN_ROLE', '遗忘仅限 owner', 403);

    if (dryRun) {
      return {
        dryRun: true,
        deletedCount: 0,
        tombstones: [{ objectKind: row.kind, objectHash: row.body_hash || sha256(row.body_plain ?? row.memory_id), class: row.class, preview: previewOf(row.body_plain) }],
        backupNote: '备份中仍含该条直至下次轮换（§8.6 / R-6）',
      };
    }
    if (!approvalId || String(approvalId).length < 8) {
      throw new ServiceError('APPROVAL_INVALID', '非 dry-run 的遗忘必须携带一次性审批令牌', 403);
    }

    const deleted = await this.pg.transaction('rw', async (client) => {
      // companion.memory_readable has exactly three branches (episode / profile /
      // preference), so the kind it reports decides which table to lock. The first cut
      // of this function covered only episode + profile: an approved delete of a
      // *preference* — the most common long-term class for this companion ("不吃香菜") —
      // came back as a misleading 404 while the row stayed in place.
      if (row.kind === 'preference') {
        const pref = await client.query(`SELECT pref_id, value_plain, value_enc, sensitivity FROM companion.user_preference WHERE pref_id = $1 FOR UPDATE`, [memoryId]);
        if (pref.rows.length === 0) throw new ServiceError('ACL_DENIED', '记忆不存在或已删除', 404);
        const p = pref.rows[0];
        const prefHash = sha256(p.value_plain ?? p.value_enc ?? `id:${memoryId}`);
        await client.query(
          `INSERT INTO companion.memory_tombstone (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
           VALUES ('preference', $1, $2, $3, $4, 'user_forget', $5)`,
          [prefHash, row.class, p.sensitivity, `agent:${principal.userId}`, approvalId],
        );
        await client.query(`DELETE FROM companion.memory_embedding WHERE object_kind = 'preference' AND object_ref = $1`, [memoryId]);
        await client.query(`DELETE FROM companion.user_preference WHERE pref_id = $1`, [memoryId]);
        return [{ objectKind: 'preference', objectHash: prefHash, class: row.class }];
      }
      const lock = await client.query(`SELECT episode_id, body_hash, class, sensitivity FROM companion.memory_episode WHERE episode_id = $1 FOR UPDATE`, [memoryId]);
      if (lock.rows.length === 0) {
        // profile branch
        const prof = await client.query(`SELECT profile_id, value_plain FROM companion.user_profile WHERE profile_id = $1 FOR UPDATE`, [memoryId]);
        if (prof.rows.length === 0) throw new ServiceError('ACL_DENIED', '记忆不存在或已删除', 404);
        const hash = sha256(prof.rows[0].value_plain ?? `id:${memoryId}`);
        await client.query(
          `INSERT INTO companion.memory_tombstone (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
           VALUES ('profile', $1, 'profile', (SELECT sensitivity FROM companion.user_profile WHERE profile_id = $2), $3, 'user_forget', $4)`,
          [hash, memoryId, `agent:${principal.userId}`, approvalId],
        );
        await client.query(`DELETE FROM companion.user_profile WHERE profile_id = $1`, [memoryId]);
        return [{ objectKind: 'profile', objectHash: hash, class: 'profile' }];
      }
      const e = lock.rows[0];
      await client.query(
        `INSERT INTO companion.memory_tombstone (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
         VALUES ('episode', $1, $2, $3, $4, 'user_forget', $5)`,
        [e.body_hash, e.class, e.sensitivity, `agent:${principal.userId}`, approvalId],
      );
      await client.query(`DELETE FROM companion.memory_embedding WHERE object_kind = 'episode' AND object_ref = $1`, [memoryId]);
      await client.query(`DELETE FROM companion.memory_episode WHERE episode_id = $1`, [memoryId]);
      return [{ objectKind: 'episode', objectHash: e.body_hash, class: e.class }];
    });

    this.l1.forgetDedupe(memoryId);
    if (this.cache) {
      this.cache.invalidate(memoryId);
      this.#invalidateSearches();
    }
    await this.logAccess({ principal, operation: 'delete', objectRef: memoryId, result: 'allowed', approved: true, approvalId, riskTags: [] });
    return { dryRun: false, deletedCount: deleted.length, tombstones: deleted, backupNote: '备份中仍含已删数据直至下次轮换（§8.6 / R-6）' };
  }

  /**
   * Whole-subject forget. Mirrors `companion.forget_by_subject`, which the rw role
   * cannot execute — the service therefore does the same steps under its own grants
   * while keeping the tombstone-before-delete ordering (M-06).
   */
  async forgetSubject(subjectKey, { principal, dryRun = true, approvalId }) {
    if (principal.role !== 'owner') throw new ServiceError('FORBIDDEN_ROLE', '全量遗忘仅限 owner', 403);
    if (!dryRun && (!approvalId || String(approvalId).length < 8)) {
      throw new ServiceError('APPROVAL_INVALID', 'non-dry-run requires a real approval id', 403);
    }
    const subject = await this.subjectByKey(subjectKey);
    if (!subject) throw new ServiceError('ACL_DENIED', '主体不存在', 404);

    const listing = await this.pg.query(
      'ro',
      `SELECT 'episode' AS kind, episode_id AS id, body_hash AS hash, class::text FROM companion.memory_episode WHERE subject_id = $1
       UNION ALL SELECT 'profile', profile_id, NULL, 'profile' FROM companion.user_profile WHERE subject_id = $1
       UNION ALL SELECT 'preference', pref_id, NULL, 'preference' FROM companion.user_preference WHERE subject_id = $1`,
      [subject.subject_id],
    );
    const items = listing.rows;
    if (dryRun) {
      return {
        dryRun: true,
        deletedCount: 0,
        tombstones: items.slice(0, 200).map((r) => ({ objectKind: r.kind, objectHash: r.hash || sha256(`id:${r.id}`), class: r.class })),
        backupNote: '清单式一次审批：批准后一次性执行，避免逐条弹窗造成审批疲劳（§5.4）',
      };
    }

    const tombstones = await this.pg.transaction('rw', async (client) => {
      const out = [];
      const eps = await client.query(`SELECT episode_id, body_hash, class, sensitivity FROM companion.memory_episode WHERE subject_id = $1 FOR UPDATE`, [subject.subject_id]);
      for (const e of eps.rows) {
        await client.query(
          `INSERT INTO companion.memory_tombstone (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
           VALUES ('episode', $1, $2, $3, $4, 'user_forget', $5)`,
          [e.body_hash, e.class, e.sensitivity, `owner_cli:${principal.userId}`, approvalId],
        );
        out.push({ objectKind: 'episode', objectHash: e.body_hash, class: e.class });
      }
      const pr = await client.query(`SELECT profile_id, value_plain, sensitivity FROM companion.user_profile WHERE subject_id = $1 FOR UPDATE`, [subject.subject_id]);
      for (const p of pr.rows) {
        const hash = sha256(p.value_plain ?? `id:${p.profile_id}`);
        await client.query(
          `INSERT INTO companion.memory_tombstone (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
           VALUES ('profile', $1, 'profile', $2, $3, 'user_forget', $4)`,
          [hash, p.sensitivity, `owner_cli:${principal.userId}`, approvalId],
        );
        out.push({ objectKind: 'profile', objectHash: hash, class: 'profile' });
      }
      const pf = await client.query(`SELECT pref_id, value_plain, sensitivity FROM companion.user_preference WHERE subject_id = $1 FOR UPDATE`, [subject.subject_id]);
      for (const p of pf.rows) {
        const hash = sha256(p.value_plain ?? `id:${p.pref_id}`);
        await client.query(
          `INSERT INTO companion.memory_tombstone (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
           VALUES ('preference', $1, 'preference', $2, $3, 'user_forget', $4)`,
          [hash, p.sensitivity, `owner_cli:${principal.userId}`, approvalId],
        );
        out.push({ objectKind: 'preference', objectHash: hash, class: 'preference' });
      }
      // CASCADE clears embedding/conflict rows (§5.4 step 3).
      for (const table of ['memory_episode', 'user_profile', 'user_preference', 'memory_fact', 'session_context', 'profile_conflict']) {
        await client.query(`DELETE FROM companion.${table} WHERE subject_id = $1`, [subject.subject_id]);
      }
      await client.query(
        `INSERT INTO companion.memory_access_log (actor_kind, actor_id, channel, chat_id, user_id, operation, object_kind, object_ref, approved, approval_id, result, rows_returned)
         VALUES ('owner_cli', $1, $2, $3, $4, 'delete', 'subject', $5, true, $6, 'allowed', $7)`,
        [`owner_cli:${principal.userId}`, principal.channel, principal.chatId, principal.userId, subject.subject_id, approvalId, out.length],
      );
      return out;
    });

    // Delete-propagation to L1 (t4 §8.6): the cache must not keep a copy of what
    // the owner just erased, and the tombstone is already durable in PG.
    if (this.cache) {
      for (const item of tombstones.length ? tombstones : []) this.cache.invalidate(item.objectHash);
      for (const r of items) this.cache.invalidate(r.id);
      this.#invalidateSearches();
    }

    // Full forget triggers the mandatory backup rotation marker (M-22 / R-6).
    await this.pg
      .query(
        'rw',
        `UPDATE companion.memory_tombstone SET backup_rotated = false WHERE deleted_by = $1 AND approval_id = $2`,
        [`owner_cli:${principal.userId}`, approvalId],
      )
      .catch(() => {});

    return {
      dryRun: false,
      deletedCount: tombstones.length,
      tombstones: tombstones.slice(0, 200),
      backupNote: '全量遗忘已标记备份轮换待办（§8.6）',
    };
  }

  /* ---------------------------------------------------------------- *
   * L1 context endpoints (§2.1 / §4.3)
   * ---------------------------------------------------------------- */

  getContext(peerKey, principal) {
    // A context read is scoped to the caller's own peer unless it is the owner:
    // group A's working memory must not surface inside group B (D-06 isolation).
    const ownPeer = `${principal.channel}:${principal.chatId}`;
    const ownDmPeer = `${principal.channel}:${principal.userId}`;
    // R2: the owner bypass is identity-bound — the caller's own chat, or the caller's
    // own DM slot on the caller's own channel. Never another channel's "owner".
    if (peerKey !== ownPeer && peerKey !== ownDmPeer && !(principal.role === 'owner' && peerKey.startsWith(`${principal.channel}:`))) {
      throw new ServiceError('PEER_BOUNDARY_VIOLATION', '上下文仅本会话可读', 403);
    }
    const ctx = this.l1.getContext(peerKey);
    return { peerKey, ...ctx };
  }

  putContext(peerKey, body, principal) {
    const ownPeer = `${principal.channel}:${principal.chatId}`;
    const ownDmPeer = `${principal.channel}:${principal.userId}`;
    if (peerKey !== ownPeer && peerKey !== ownDmPeer && !(principal.role === 'owner' && peerKey.startsWith(`${principal.channel}:`))) {
      throw new ServiceError('PEER_BOUNDARY_VIOLATION', '上下文仅本会话可写', 403);
    }
    const serialized = JSON.stringify(body.value);
    if (serialized.length > 8192) throw new ServiceError('BODY_TOO_LARGE', '上下文槽位超过 8 KiB', 413);
    const res = this.l1.putContext({ peerKey, slot: body.slot, valueJson: serialized, sensitivity: body.sensitivity || 'internal', sourceMsgId: body.sourceMsgId });
    return res;
  }

  /* ---------------------------------------------------------------- *
   * crypto helpers (§5.2) — pgcrypto keeps the DEK out of JS land
   * ---------------------------------------------------------------- */

  async encrypt(plaintext, domain) {
    const dek = this.dekFor(domain);
    const { rows } = await this.pg.query('rw', `SELECT pgp_sym_encrypt($1, $2, 'cipher-algo=aes256') AS enc`, [plaintext, dek]);
    return rows[0].enc;
  }

  /**
   * Decrypt inside PG so the DEK never has to leave as a JS string beyond this call.
   * ⚠ measured: `pgp_sym_decrypt` returns `bytea`, and there is no
   *   `convert_from(text, unknown)` overload — the cast must be explicit or every PII
   *   read fails with "function convert_from(bytea, unknown) does not exist".
   */
  async decrypt(ciphertext, domain) {
    const dek = this.dekFor(domain);
    const { rows } = await this.pg.query('rw', `SELECT convert_from(pgp_sym_decrypt($1::bytea, $2)::bytea, 'UTF8') AS body`, [ciphertext, dek]);
    return rows[0].body;
  }

  /* ---------------------------------------------------------------- *
   * audit (§5.5) — dual-write: JSONL sink is the source of truth (F3)
   * ---------------------------------------------------------------- */

  async logAccess(entry) {
    const p = entry.principal || {};
    const params = [
      p.sessionId ? 'agent' : 'service',
      p.sessionId || 'memory-service',
      p.channel ?? null,
      p.chatId ?? null,
      p.userId ?? null,
      entry.operation,
      entry.objectKind ?? null,
      entry.objectRef ?? null,
      entry.class_ ?? null,
      entry.sensitivity ?? null,
      Boolean(entry.approved),
      entry.approvalId ?? null,
      entry.result || 'allowed',
      entry.riskTags || [],
      entry.rowsReturned ?? 0,
      entry.bytesOut ?? 0,
      entry.latencyMs ?? null,
    ];
    try {
      const { rows } = await this.pg.query(
        'rw',
        `INSERT INTO companion.memory_access_log
           (actor_kind, actor_id, channel, chat_id, user_id, operation, object_kind, object_ref, class, sensitivity,
            approved, approval_id, result, risk_tags, rows_returned, bytes_out, latency_ms, principal_sock)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::companion.memory_class,$10::companion.sensitivity_level,$11,$12,$13::companion.access_result,$14,$15,$16,$17,'service')
         RETURNING log_id`,
        params,
      );
      return `al-${rows[0]?.log_id ?? randomUUID().slice(0, 8)}`;
    } catch (err) {
      // Audit write failure must not lose the request silently: stderr keeps the
      // watcher's "log stopped growing" signal alive (TM-014).
      process.stderr.write(`${JSON.stringify({ ts: Date.now(), type: 'memory.access', service: 'memory-service', result: 'error', message: String(err.message).slice(0, 120) })}\n`);
      return 'al-unavailable';
    }
  }

  /**
   * Open a conflict-queue row (§4.4). `existing_ref` is NOT NULL, so a risk-tagged
   * candidate that has nothing to point at yet gets a deterministic uuid derived
   * from the incoming hash instead of a nullable column that would break the schema.
   * @param {object} fields
   * @param {{query:(sql:string, params:any[])=>Promise<any>}} [client] - pass one to join a transaction
   */
  async queueConflict(fields, client = null) {
    const existingRef = fields.existingRef || uuidFromHash(fields.incomingHash);
    const sql = `INSERT INTO companion.profile_conflict (subject_id, attr_key, existing_kind, existing_ref, incoming_hash, incoming_meta, reason)
                  VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING conflict_id`;
    const params = [fields.subjectId, fields.attrKey, fields.existingKind, existingRef, fields.incomingHash, JSON.stringify(fields.incomingMeta || {}), fields.reason];
    const res = client ? await client.query(sql, params) : await this.pg.query('rw', sql, params);
    return res.rows[0].conflict_id;
  }
}

/* ------------------------------------------------------------------ *
 * pure helpers
 * ------------------------------------------------------------------ */

const HALF_LIFE = { commitment: 7, episode: 60, sentiment: 7, session_ctx: 1 };

/** Lower-case + collapse whitespace/punctuation, matching §4.1's `normalize`. */
export function normalizeText(text) {
  return String(text ?? '')
    .toLowerCase()
    .replace(/[\s　]+/g, ' ')
    .replace(/[，。！？、；：,.!?;:"'()\[\]{}<>《》【】…—~`@#$%^&*_+=|\\/]/g, '')
    .trim();
}

/** UTF-8 byte trigrams, mirroring companion.byte_trgm() so JS and SQL agree. */
export function byteTrigrams(text) {
  const buf = Buffer.from(normalizeText(text), 'utf8');
  const out = new Set();
  for (let i = 0; i + 3 <= buf.length; i += 1) out.add(buf.subarray(i, i + 3).toString('hex'));
  if (out.size === 0 && buf.length > 0) out.add(buf.toString('hex'));
  return out;
}

function peerKindFromScope(scope) {
  if (scope === 'group') return 'group';
  if (scope === 'global') return 'channel';
  return 'dm';
}

function defaultAttrKey(class_, body) {
  return `${class_}:${sha256(normalizeText(body)).slice(0, 12)}`;
}

/**
 * TTL: the policy value is an **upper bound**; a caller may shorten it but never
 * lengthen it (openapi WriteRequest.ttlDays description).
 */
function expiresFrom(requestedTtlDays, policyTtlDays) {
  const policy = Number(policyTtlDays);
  if (!Number.isFinite(policy) || policy <= 0) return null; // permanent
  const requested = Number(requestedTtlDays);
  const days = Number.isFinite(requested) && requested > 0 ? Math.min(requested, policy) : policy;
  return new Date(Date.now() + days * 86_400_000).toISOString();
}

function mapMemory(row, body, strategy) {
  return {
    memoryId: row.memory_id,
    kind: row.kind,
    subjectId: row.subject_id,
    // openapi `Memory` requires createdAt; the view exposes created_at as occurred_at
    // for episodes and created_at for L2 rows, so prefer the explicit column.
    createdAt: iso(row.created_at ?? row.occurred_at),
    attrKey: row.attr_key ?? undefined,
    class: row.class,
    body,
    sensitivity: row.sensitivity,
    visibility: row.visibility,
    occurredAt: iso(row.occurred_at),
    expiresAt: iso(row.expires_at),
    hitCount: Number(row.hit_count ?? 0),
    confidence: Number(row.confidence ?? 0),
    riskTags: row.risk_tags || [],
    provenance: { sourceChannel: row.source_channel ?? null, sourceRef: row.source_ref ?? null, createdByIdentity: row.subject_id ?? null },
    retrievalStrategy: strategy,
  };
}

/** PG returns Date objects over the wire; the contract wants ISO strings (and null). */
function iso(value) {
  if (value === null || value === undefined) return null;
  if (value instanceof Date) return value.toISOString();
  return String(value);
}

/** §5.3: PII preview shows at most 8 characters plus a mask. */
function previewOf(body) {
  if (typeof body !== 'string' || body.length === 0) return undefined;
  return `${body.slice(0, 8)}***`;
}

/** Deterministic uuid (v4 shape) derived from a sha256 hex prefix. */
function uuidFromHash(hash) {
  const h = String(hash).padEnd(32, '0').slice(0, 32);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`;
}
