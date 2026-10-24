-- =====================================================================
-- t4 · 保留期 / 过期清理 / 遗忘执行 / 运维辅助函数
-- 前置：001_schema.sql、002_roles.sql、003_seed_policy.sql
-- 执行：sudo -u postgres psql -d dsh_companion -v ON_ERROR_STOP=1 -f 004_retention.sql
-- 依据：arch §4.3（TTL）· §5.4（forget 物理删除）· §8.1（不用 pg_cron，服务内调度）· §7.4（向量升级位）
-- ⚠ 本文件创建的对象**不自动运行任何定时任务**：调度由 memory-service 进程发起
--   （宿主无 pg_cron 保证；§1.4 实测扩展目录未见 pg_cron）。
-- =====================================================================

BEGIN;

SET search_path = companion, public;

-- ---------------------------------------------------------------------
-- 1. purge_expired() —— L3 过期物理删除 + tombstone（arch §4.3 / §5.4）
--    SECURITY DEFINER 但 owner 保持超级用户：只有服务角色被 EXECUTE 授权。
--    返回被删行数；调用方负责写 job_run。
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION companion.purge_expired(p_batch_size integer DEFAULT 5000)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = companion, public, pg_temp
AS $$
DECLARE
  v_ids   uuid[];
  v_count integer;
BEGIN
  IF p_batch_size < 1 OR p_batch_size > 50000 THEN
    RAISE EXCEPTION 'batch size out of range';
  END IF;

  -- 1) 锁定到期行（跳过已锁定的并发批次）
  SELECT array_agg(episode_id) INTO v_ids
  FROM (
    SELECT episode_id
      FROM companion.memory_episode
     WHERE expires_at IS NOT NULL
       AND expires_at < now()
       AND superseded_by IS NULL
     ORDER BY expires_at
     LIMIT p_batch_size
     FOR UPDATE SKIP LOCKED
  ) s;

  IF v_ids IS NULL OR array_length(v_ids, 1) IS NULL THEN
    RETURN 0;
  END IF;

  -- 2) 先留删除证明（只含不可逆摘要），再物理删除
  INSERT INTO companion.memory_tombstone
    (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, cascade_count)
  SELECT 'episode', e.body_hash, e.class, e.sensitivity, 'job:purge_expired', 'ttl_expired', 0
    FROM companion.memory_episode e
   WHERE e.episode_id = ANY (v_ids);

  DELETE FROM companion.memory_embedding
   WHERE object_kind = 'episode' AND object_ref = ANY (v_ids);

  DELETE FROM companion.profile_conflict
   WHERE existing_ref = ANY (v_ids) AND status = 'open';

  DELETE FROM companion.memory_episode WHERE episode_id = ANY (v_ids);

  GET DIAGNOSTICS v_count = ROW_COUNT;

  INSERT INTO companion.memory_access_log
    (actor_kind, actor_id, operation, object_kind, object_ref, result, rows_returned)
  VALUES ('job', 'purge_expired', 'purge', 'episode', 'batch:' || v_count, 'allowed', v_count);

  RETURN v_count;
END $$;

COMMENT ON FUNCTION companion.purge_expired(integer) IS
  'Hourly. Writes tombstone BEFORE delete so "what was deleted" stays provable while content is gone (arch §4.3, F3 vs privacy).';

-- ---------------------------------------------------------------------
-- 2. forget_by_subject() —— 全量遗忘（GDPR 式），逐条留痕（arch §5.4 / §5.7）
--    调用前必须已有 owner 审批；本函数不判断审批，只判断入参完整性 ——
--    判决留在应用层与 DSH 工具闸（C-10/C-15），DB 不做业务策略。
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION companion.forget_by_subject(
  p_subject_id uuid,
  p_actor      text,
  p_approval_id text,
  p_dry_run    boolean DEFAULT true
)
RETURNS TABLE (object_kind text, object_ref uuid, body_hash text, class companion.memory_class)
LANGUAGE plpgsql
SECURITY DEFINER
-- ⚠ search_path 必须包含 public：pgcrypto 的 digest()/encode() 与 md5() 都在 public，
--   只写 `companion, pg_temp` 会让 INSERT…SELECT 里的 digest(...) 解析失败（实测报错）。
SET search_path = companion, public, pg_temp
AS $$
DECLARE
  v_rows bigint;
BEGIN
  IF p_subject_id IS NULL THEN
    RAISE EXCEPTION 'subject_id required';
  END IF;
  IF NOT p_dry_run AND (p_approval_id IS NULL OR length(trim(p_approval_id)) < 8) THEN
    RAISE EXCEPTION 'non-dry-run requires a real approval id';   -- fail closed
  END IF;

  RETURN QUERY
    SELECT 'episode'::text, e.episode_id, e.body_hash, e.class
      FROM companion.memory_episode e
     WHERE e.subject_id = p_subject_id
     ORDER BY e.occurred_at;

  -- dry_run：到此为止，不动数据
  IF p_dry_run THEN
    RETURN;
  END IF;

  -- 1) 证明先行（profile/preference 无 body_hash 列，故对明文取 sha256；
  --    加密列无法在 DB 侧解密 → 退化为"行 id 的哈希"，仍不可逆、仍可证明确实删过）
  INSERT INTO companion.memory_tombstone
    (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
  SELECT 'episode', e.body_hash, e.class, e.sensitivity, p_actor, 'user_forget', p_approval_id
    FROM companion.memory_episode e WHERE e.subject_id = p_subject_id;

  INSERT INTO companion.memory_tombstone
    (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
  SELECT 'profile',
         encode(public.digest(coalesce(p.value_plain, md5(p.profile_id::text)), 'sha256'::text), 'hex'::text),
         'profile'::companion.memory_class, p.sensitivity, p_actor, 'user_forget', p_approval_id
    FROM companion.user_profile p WHERE p.subject_id = p_subject_id;

  INSERT INTO companion.memory_tombstone
    (object_kind, object_hash, class, sensitivity, deleted_by, reason_code, approval_id)
  SELECT 'preference',
         encode(public.digest(coalesce(f.value_plain, md5(f.pref_id::text)), 'sha256'::text), 'hex'::text),
         'preference'::companion.memory_class, f.sensitivity, p_actor, 'user_forget', p_approval_id
    FROM companion.user_preference f WHERE f.subject_id = p_subject_id;

  -- 2) 物理删除（CASCADE 清 embedding/conflict）
  DELETE FROM companion.memory_episode    WHERE subject_id = p_subject_id;
  DELETE FROM companion.user_profile      WHERE subject_id = p_subject_id;
  DELETE FROM companion.user_preference   WHERE subject_id = p_subject_id;
  DELETE FROM companion.memory_fact       WHERE subject_id = p_subject_id;
  DELETE FROM companion.session_context   WHERE subject_id = p_subject_id;
  DELETE FROM companion.profile_conflict  WHERE subject_id = p_subject_id;

  GET DIAGNOSTICS v_rows = ROW_COUNT;

  INSERT INTO companion.memory_access_log
    (actor_kind, actor_id, operation, object_kind, object_ref, approved, approval_id, result, rows_returned)
  VALUES ('owner_cli', p_actor, 'delete', 'subject', p_subject_id::text, true, p_approval_id, 'allowed', v_rows::int);
END $$;

-- ---------------------------------------------------------------------
-- 3. l1_promotion_candidates() —— arch §2.3 的保守判据（≥2 次或跨 ≥2 session）
--    产出**提案**写入 conflict 队列，绝不自动写 L2。
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION companion.collect_promotion_candidates(p_peer_key text)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = companion, public, pg_temp
AS $$
DECLARE v_count integer;
BEGIN
  WITH cand AS (
    SELECT sc.ctx_id, sc.subject_id, el.elem ->> 'attr_key'          AS attr_key,
           el.elem ->> 'value_hash'                                  AS value_hash,
           (el.elem ->> 'observations')::int                          AS observations,
           jsonb_array_length(sc.candidate_promotions)                AS sessions
      FROM companion.session_context sc,
           LATERAL jsonb_array_elements(sc.topic_stack) AS el(elem)
     WHERE sc.peer_key = p_peer_key
       AND sc.expires_at > now()
       AND sc.subject_id IS NOT NULL
       AND (el.elem ->> 'attr_key') IS NOT NULL
  ),
  qualified AS (
    SELECT * FROM cand WHERE observations >= 2 OR sessions >= 2
  )
  INSERT INTO companion.profile_conflict
    (subject_id, attr_key, existing_kind, existing_ref, incoming_hash, incoming_meta, reason)
  SELECT q.subject_id, q.attr_key, 'episode', q.ctx_id, q.value_hash,
         jsonb_build_object('observations', q.observations, 'sessions', q.sessions),
         'promotion_candidate'
    FROM qualified q
  ON CONFLICT DO NOTHING;

  GET DIAGNOSTICS v_count = ROW_COUNT;

  INSERT INTO companion.job_run (job, started_at, finished_at, rows_affected, status)
  VALUES ('promote_candidates', now(), now(), v_count, 'ok');

  RETURN v_count;
END $$;

-- ---------------------------------------------------------------------
-- 4. prune_access_log() —— 审计保留期（arch §5.7：默认 365d，下限 90d）
--    按分区 DETACH 而非 DELETE：大表删除会产生死元组并拖慢在线读。
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION companion.prune_access_log(p_keep_days integer DEFAULT 365)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = companion, public, pg_temp
AS $$
DECLARE v_cut timestamptz; v_n integer := 0; r record;
BEGIN
  IF p_keep_days < 90 THEN
    RAISE EXCEPTION 'access log retention floor is 90 days (F5 correlation ability)';
  END IF;
  v_cut := now() - make_interval(days => p_keep_days);

  -- 用分区边界判断，而非扫描数据：只有「整个分区的上界都早于保留期」才允许 detach。
  -- 分区名形状由 001_schema.sql 保证：memory_access_log_YYYYMM（default 分区不匹配，永不清除）。
  FOR r IN
    SELECT c.relname,
           substring(pg_get_expr(c.relpartbound, c.oid) from 'TO \(''([^'']+)''')::timestamptz AS upper_bound
      FROM pg_class c
      JOIN pg_inherits i ON i.inhrelid = c.oid
     WHERE i.inhparent = 'companion.memory_access_log'::regclass
       AND c.relname ~ '^memory_access_log_[0-9]{6}$'
     ORDER BY c.relname
  LOOP
    IF r.upper_bound < v_cut THEN
      EXECUTE format('ALTER TABLE companion.memory_access_log DETACH TABLE %I', r.relname);
      EXECUTE format('DROP TABLE companion.%I', r.relname);
      v_n := v_n + 1;
    END IF;
  END LOOP;

  INSERT INTO companion.job_run (job, started_at, finished_at, rows_affected, status)
  VALUES ('prune_access_log', now(), now(), v_n, 'ok');
  RETURN v_n;
END $$;

-- ---------------------------------------------------------------------
-- 5. enable_vector_slot() —— pgvector 到位后才添加 vector 列（arch §7.4）
--    host PG 当前无该扩展（§1.4 实测）→ 本函数在无扩展时安全 no-op。
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION companion.enable_vector_slot(p_dim integer DEFAULT 1024)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = companion, public, pg_temp
AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
                  WHERE e.extname = 'vector') THEN
    RETURN 'skipped: pgvector not installed (arch §1.4). Phase-1 keeps vec_jsonb.';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                  WHERE table_schema='companion' AND table_name='memory_embedding' AND column_name='vec') THEN
    EXECUTE format('ALTER TABLE companion.memory_embedding ADD COLUMN vec vector(%s)', p_dim);
    EXECUTE 'CREATE INDEX memory_embedding_vec_hnsw_idx ON companion.memory_embedding USING hnsw (vec vector_cosine_ops)';
  END IF;
  RETURN 'ok: vector slot enabled';
END $$;

-- ---------------------------------------------------------------------
-- 6. health 视图：供 watcher 判定作业心跳（arch §8.1「沉默即告警」/ E7）
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW companion.job_heartbeat AS
SELECT j.job,
       max(j.started_at)                                            AS last_run,
       EXTRACT(epoch FROM (now() - max(j.started_at)))::bigint       AS age_seconds,
       count(*)                                                      AS runs,
       bool_or(j.status = 'failed')                                  AS any_failed
  FROM companion.job_run j
 GROUP BY j.job;

CREATE OR REPLACE VIEW companion.memory_stats AS
SELECT 'user_profile'     AS object, count(*) AS rows, pg_size_pretty(pg_total_relation_size('companion.user_profile'))     AS size FROM companion.user_profile
UNION ALL SELECT 'user_preference', count(*), pg_size_pretty(pg_total_relation_size('companion.user_preference')) FROM companion.user_preference
UNION ALL SELECT 'memory_episode',  count(*), pg_size_pretty(pg_total_relation_size('companion.memory_episode'))  FROM companion.memory_episode
UNION ALL SELECT 'session_context', count(*), pg_size_pretty(pg_total_relation_size('companion.session_context')) FROM companion.session_context
UNION ALL SELECT 'tombstone',       count(*), pg_size_pretty(pg_total_relation_size('companion.memory_tombstone')) FROM companion.memory_tombstone
UNION ALL SELECT 'conflict_open',   count(*), NULL FROM companion.profile_conflict WHERE status = 'open';

-- ---------------------------------------------------------------------
-- 7. 维护函数的权限：**显式白名单，绝不使用 ALL FUNCTIONS**（见 002 §6 的教训）
--    ro 一律不可执行任何维护函数；forget/prune 连服务写角色也不给。
-- ---------------------------------------------------------------------
-- PostgreSQL 无 `REVOKE ... ON FUNCTION ALL IN SCHEMA` 语法（实测报错），用目录遍历兜底。
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'companion' AND p.prokind = 'f'
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', r.sig);
  END LOOP;
END
$$;

GRANT EXECUTE ON FUNCTION
  companion.purge_expired(integer),
  companion.collect_promotion_candidates(text),
  companion.enable_vector_slot(integer)
TO dsh_companion_rw;

-- forget_by_subject / prune_access_log **不授予任何服务角色**：
-- 只留给运维身份（owner_cli 通道）。这是「agent/服务无法触发全量遗忘」在 DB 层的第二道保证
-- （第一道是 bot-core 的 tools.guard + approval:ask）。
-- 若将来需要让服务代执行，必须新增独立角色并配审批令牌校验，不得放宽 rw。

GRANT SELECT ON companion.job_heartbeat, companion.memory_stats TO dsh_companion_ro, dsh_companion_rw;

COMMIT;

-- =====================================================================
-- Post-check（对应验收 M-06/M-08/M-19）：
--   SELECT companion.purge_expired(100);                       → 0（无到期行）
--   SELECT * FROM companion.job_heartbeat;                     → 有 job_run 记录
--   SELECT companion.forget_by_subject(NULL,'x','y',true);     → ERROR subject_id required
--   SET ROLE dsh_companion_ro; SELECT companion.purge_expired(); → permission denied
-- =====================================================================
