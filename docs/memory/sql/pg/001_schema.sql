-- =====================================================================
-- t4 · DSH 大肥鱼机器伴侣 — 长期记忆权威库结构
-- 目标：Host PostgreSQL 16（实测 16.15）· database: dsh_companion · schema: companion
-- 幂等：可重复执行。依赖扩展 pgcrypto / pg_trgm / btree_gin（§1.4 实测均已安装）。
-- 执行：sudo -u postgres psql -d dsh_companion -v ON_ERROR_STOP=1 -f 001_schema.sql
-- 配套设计：docs/memory/t4-memory-architecture.md §3 / §4 / §5 / §7 / §8
-- =====================================================================

BEGIN;

-- ---------------------------------------------------------------------
-- 1. 扩展
-- ---------------------------------------------------------------------
CREATE SCHEMA IF NOT EXISTS companion;

-- ⚠ 扩展必须建在 **public**，不要先 SET search_path = companion：
--   否则 pgcrypto/pg_trgm 的 ~150 个函数会落在 companion 里，
--   应用侧 `SELECT pgp_sym_encrypt(...)` 解析不到（实测报 "No function matches"），
--   且批量授权极易把解密原语误授给只读角色。002_roles.sql §9 有兜底修正，但以本文件为准。
SET search_path = public, companion;

-- gen_random_uuid() + pgp_sym_encrypt/decrypt
CREATE EXTENSION IF NOT EXISTS pgcrypto;
-- 模糊匹配：⚠ 实测对**中文无效**（pg_trgm 按字符取三元组，2 字查询只产出 1 个 token，
--   similarity('我喜欢香菜和花生','香菜') = 0.0000）。保留它只为英文/拼音混排兜底；
--   中文召回由下方 companion.byte_trgm() + GIN(array_ops) 承担（见 §7.1 修正）。
CREATE EXTENSION IF NOT EXISTS pg_trgm;
-- 复合 GIN 索引需要（text/array 与 btree 类型混排）
CREATE EXTENSION IF NOT EXISTS btree_gin;

SET search_path = companion, public;

-- ---------------------------------------------------------------------
-- 1b. byte_trgm —— UTF-8 字节级三元组（CJK 可用的模糊召回基础）
--     实测：`byte_trgm(body) && byte_trgm('香菜')` → Bitmap Index Scan 命中，
--           '天气' 对照不命中；短查询(1 个三元组)会放大噪声，故排序用 overlap 计数而非布尔。
--     IMMUTABLE 是建索引的前提；convert_to(...,'UTF8') 不接受非法 UTF8 → 用异常安全包装。
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION companion.byte_trgm_raw(p_text text)
RETURNS text[] LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
  SELECT CASE
    WHEN p_text IS NULL OR p_text = '' THEN '{}'::text[]
    ELSE array(
      SELECT encode(substring(convert_to(lower(p_text),'UTF8') FROM i FOR 3), 'hex')
        FROM generate_series(1, greatest(octet_length(convert_to(lower(p_text),'UTF8')) - 2, 1)) AS i
    )
  END
$$;

-- 非法 UTF8 输入不得让索引写入失败（A6/健壮性）：捕获后回退为空数组并交由上层打标。
CREATE OR REPLACE FUNCTION companion.byte_trgm(p_text text)
RETURNS text[] LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE AS $$
BEGIN
  RETURN companion.byte_trgm_raw(p_text);
EXCEPTION WHEN others THEN
  RETURN '{}'::text[];
END $$;

COMMENT ON FUNCTION companion.byte_trgm(text) IS
  'UTF-8 byte trigrams (3-byte windows) for CJK fuzzy recall. pg_trgm alone returns similarity=0 for Chinese (measured). Lower-cased inside.';

COMMENT ON SCHEMA companion IS
  'DSH big-fish companion long-term memory (L2 profile / L3 episodic / audit). Authoritative store.';

-- ---------------------------------------------------------------------
-- 2. 封闭枚举词汇表（arch §2.2 / §5.1 / §5.6）
--    刻意用 enum 而非 free text：未知值在入库前即失败，与 C-23「严格 schema」同姿态。
-- ---------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'memory_class') THEN
    CREATE TYPE companion.memory_class AS ENUM (
      'profile',       -- 稳定属性                        L2 permanent
      'preference',    -- 偏好与禁忌                      L2 permanent
      'commitment',    -- bot 承诺/待办                   L3 expires+7d
      'episode',       -- 单次事件叙述                    L3 expires+180d
      'sentiment',     -- 情绪语境快照（低精度）           L3 expires+7d
      'session_ctx',   -- L1 投影元数据（不存原文）         L1 ttl=24h
      'pii_raw'        -- 强制加密                        L2/L3 permanent
    );
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'sensitivity_level') THEN
    CREATE TYPE companion.sensitivity_level AS ENUM ('public','internal','pii','secret');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'visibility_level') THEN
    CREATE TYPE companion.visibility_level AS ENUM ('private','peer','owner','admin');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'identity_trust') THEN
    CREATE TYPE companion.identity_trust AS ENUM ('server_backed','unbacked','unknown');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'access_operation') THEN
    CREATE TYPE companion.access_operation AS ENUM
      ('read','write','search','delete','decrypt','promote','purge','refuse');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'access_result') THEN
    CREATE TYPE companion.access_result AS ENUM ('allowed','denied','error','unavailable');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'actor_kind') THEN
    CREATE TYPE companion.actor_kind AS ENUM ('agent','service','owner_cli','job');
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'conflict_status') THEN
    CREATE TYPE companion.conflict_status AS ENUM ('open','resolved_keep_old','resolved_keep_new','expired','rejected_poison');
  END IF;
END
$$;

-- ---------------------------------------------------------------------
-- 3. memory_class_policy —— 每类的 TTL / 审批要求 / 是否加密（arch §2.1 / §2.2）
--    策略数据化而非硬编码：变更走审计（A9），无需改代码即可收紧保留期。
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.memory_class_policy (
  class                 companion.memory_class PRIMARY KEY,
  layer                 smallint      NOT NULL CHECK (layer BETWEEN 1 AND 4),
  ttl_days              integer       CHECK (ttl_days IS NULL OR ttl_days > 0),  -- NULL = 永久
  requires_approval     boolean       NOT NULL DEFAULT true,
  encrypt_at_rest       boolean       NOT NULL DEFAULT false,
  max_body_chars        integer       NOT NULL DEFAULT 2000 CHECK (max_body_chars BETWEEN 200 AND 8000),
  recency_half_life_days integer      CHECK (recency_half_life_days IS NULL OR recency_half_life_days > 0),
                                                          -- NULL = 不衰减（arch §7.1 half_life=∞，profile/preference/pii）
  allow_auto_write      boolean       NOT NULL DEFAULT false, -- true 仅 session_ctx/sentiment
  note                  text,
  updated_at            timestamptz   NOT NULL DEFAULT now()
);

COMMENT ON TABLE companion.memory_class_policy IS
  'Closed vocabulary of memory classes with retention/approval/crypto policy. Seed: 003_seed_policy.sql';

-- ---------------------------------------------------------------------
-- 4. subject —— 记忆主体（arch §3.3）
--    identity_trust 直接承接 t3 arch §5.4「新通道必须声明是否提供服务器背书 user_id」。
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.subject (
  subject_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_key       text UNIQUE NOT NULL,          -- 'telegram:dm:111' | 'onebot:group:123456:member:777'
  channel           text NOT NULL,                 -- 结构化字段；永不存显示名（C-03/A-2）
  external_id       text NOT NULL,
  peer_kind         text NOT NULL CHECK (peer_kind IN ('dm','group','channel')),
  identity_trust    companion.identity_trust NOT NULL DEFAULT 'unknown',
  is_owner          boolean NOT NULL DEFAULT false,
  created_at        timestamptz NOT NULL DEFAULT now(),
  last_seen_at      timestamptz NOT NULL DEFAULT now(),
  -- owner 判定只能来自 server_backed 通道（QQ 无平台背书 → 不得授予 owner）
  CONSTRAINT owner_requires_trusted_channel
    CHECK (NOT is_owner OR identity_trust = 'server_backed'),
  CONSTRAINT subject_key_shape CHECK (subject_key ~ '^[a-z0-9_]+:[a-z]+:.+$')
);

CREATE INDEX IF NOT EXISTS subject_channel_ext_idx ON companion.subject (channel, external_id);

-- ---------------------------------------------------------------------
-- 5. user_profile —— L2 稳定属性（KV，值可加密）（arch §3.3 / §5.2）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.user_profile (
  profile_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_id      uuid NOT NULL REFERENCES companion.subject(subject_id) ON DELETE CASCADE,
  attr_key        text NOT NULL,                   -- 'call_me','timezone','allergy','family.member'
  value_plain     text,                            -- sensitivity < pii 时使用
  value_enc       bytea,                           -- sensitivity >= pii：pgp_sym_encrypt 密文
  sensitivity     companion.sensitivity_level NOT NULL DEFAULT 'internal',
  confidence      real NOT NULL DEFAULT 0.5 CHECK (confidence BETWEEN 0 AND 1),
  hit_count       integer NOT NULL DEFAULT 1,
  dedupe_key      text NOT NULL,
  source_ref      text,                             -- 'episode:<uuid>' | 'chat:<msg_id>'，不落原文
  version         integer NOT NULL DEFAULT 1,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now(),
  superseded_by   uuid REFERENCES companion.user_profile(profile_id),
  visibility      companion.visibility_level NOT NULL DEFAULT 'private',
  -- 二者恰有其一：避免"以为加密了其实存了明文"这类静默失败
  CONSTRAINT profile_value_exactly_one CHECK (
    (value_plain IS NOT NULL AND value_enc IS NULL AND sensitivity NOT IN ('pii','secret'))
    OR (value_enc IS NOT NULL AND value_plain IS NULL AND sensitivity IN ('pii','secret'))
  ),
  CONSTRAINT profile_no_secret_stored CHECK (sensitivity <> 'secret'),
  CONSTRAINT user_profile_subject_attr_uq UNIQUE (subject_id, attr_key, version)
);

COMMENT ON CONSTRAINT profile_no_secret_stored ON companion.user_profile IS
  'arch §5.1: password/token class is REFUSED at write time, never stored encrypted. Same-host KEK would not protect it (axiom 2).';

CREATE INDEX IF NOT EXISTS profile_subject_key_idx ON companion.user_profile (subject_id, attr_key)
  WHERE superseded_by IS NULL;
CREATE INDEX IF NOT EXISTS profile_dedupe_idx ON companion.user_profile (dedupe_key);
CREATE INDEX IF NOT EXISTS profile_byte_trgm_idx ON companion.user_profile
  USING gin (companion.byte_trgm(value_plain) array_ops);
CREATE INDEX IF NOT EXISTS profile_trgm_idx ON companion.user_profile USING gin (value_plain gin_trgm_ops);

-- ---------------------------------------------------------------------
-- 6. user_preference —— L2 偏好/禁忌（带作用域）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.user_preference (
  pref_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_id     uuid NOT NULL REFERENCES companion.subject(subject_id) ON DELETE CASCADE,
  scope          text NOT NULL CHECK (scope IN ('global','dm','group')),
  scope_peer     text,                              -- scope<>global 时限定 chat_id
  pref_key       text NOT NULL,                     -- 'food.avoid','notify.quiet_hours','tone'
  value_plain    text,
  value_enc      bytea,
  sensitivity    companion.sensitivity_level NOT NULL DEFAULT 'internal',
  is_veto        boolean NOT NULL DEFAULT false,    -- true = 禁忌，检索时优先级最高
  peer_slot      text GENERATED ALWAYS AS (COALESCE(scope_peer,'')) STORED,  -- UNIQUE 需确定性列，故物化
  dedupe_key     text NOT NULL,
  source_ref     text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  visibility     companion.visibility_level NOT NULL DEFAULT 'private',
  CONSTRAINT pref_value_exactly_one CHECK (
    (value_plain IS NOT NULL AND value_enc IS NULL AND sensitivity NOT IN ('pii','secret'))
    OR (value_enc IS NOT NULL AND value_plain IS NULL AND sensitivity IN ('pii','secret'))
  ),
  CONSTRAINT pref_scope_peer_consistent CHECK (
    (scope = 'global' AND scope_peer IS NULL) OR (scope <> 'global' AND scope_peer IS NOT NULL)
  ),
  CONSTRAINT pref_no_secret CHECK (sensitivity <> 'secret'),
  CONSTRAINT pref_subject_scope_key_uq UNIQUE (subject_id, scope, peer_slot, pref_key)
);

CREATE INDEX IF NOT EXISTS pref_subject_scope_idx ON companion.user_preference (subject_id, scope);

-- ---------------------------------------------------------------------
-- 7. memory_episode —— L3 事件记忆（正文可加密 + FTS + trgm）（arch §3.3 / §7.2）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.memory_episode (
  episode_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_id     uuid NOT NULL REFERENCES companion.subject(subject_id) ON DELETE CASCADE,
  peer_key       text NOT NULL,                     -- 产生该记忆的会话对（ACL 判定输入）
  class          companion.memory_class NOT NULL,
  body_plain     text,
  body_enc       bytea,
  body_hash      text NOT NULL,                     -- sha256(明文)，tombstone 关联用，不含内容
  dedupe_key     text NOT NULL,
  sensitivity    companion.sensitivity_level NOT NULL DEFAULT 'internal',
  visibility     companion.visibility_level NOT NULL DEFAULT 'peer',
  occurred_at    timestamptz NOT NULL,
  expires_at     timestamptz,                       -- NULL = 不过期（仅 policy 允许时）
  hit_count      integer NOT NULL DEFAULT 0,
  last_seen_at   timestamptz NOT NULL DEFAULT now(),
  confidence     real NOT NULL DEFAULT 0.5 CHECK (confidence BETWEEN 0 AND 1),
  risk_tags      text[] NOT NULL DEFAULT '{}',      -- 透传 ingress 的 RiskTag（A6）
  source_channel text NOT NULL,
  source_ref     text,
  approved_by    text,                              -- approval request id（opaque，非凭据）
  created_at     timestamptz NOT NULL DEFAULT now(),
  superseded_by  uuid REFERENCES companion.memory_episode(episode_id),
  CONSTRAINT episode_body_exactly_one CHECK (
    (body_plain IS NOT NULL AND body_enc IS NULL) OR (body_enc IS NOT NULL AND body_plain IS NULL)
  ),
  CONSTRAINT episode_no_secret CHECK (sensitivity <> 'secret'),
  CONSTRAINT episode_expiry_sane CHECK (expires_at IS NULL OR expires_at > occurred_at)
);

COMMENT ON COLUMN companion.memory_episode.risk_tags IS
  'Ingress-assigned RiskTag[]. Non-empty ⇒ write path must route to conflict queue, not straight to storage (arch §4.5 rule 1).';

-- ⚠ 中文正文的 FTS('simple') 会把整段切成**单个 token**（实测：'我喜欢香菜和花生' → 一个 lexeme），
--   因此该索引只对空格分词的混排文本（英文、拼音、带标点分隔）有效；主召回走 byte_trgm。
CREATE INDEX IF NOT EXISTS episode_ts_idx ON companion.memory_episode
  USING gin (to_tsvector('simple', coalesce(body_plain,'')));
-- CJK 主召回路径（实测可用，见 §7.1）。
-- ★ 刻意**不加** `WHERE body_plain IS NOT NULL`：partial GIN 表达式索引只有在查询里也出现
--   完全相同的严格谓词时才会被规划器采用（实测：缺谓词 → Seq Scan）。把这条约束写进索引
--   定义等于给检索 API 埋一个"忘了加就全表扫"的坑，故改为无条件索引 + 函数自身对 NULL 返回 '{}'。
CREATE INDEX IF NOT EXISTS episode_byte_trgm_idx ON companion.memory_episode
  USING gin (companion.byte_trgm(body_plain) array_ops);
-- 拉丁文兜底（对中文无效，保留成本极低；同为非 partial，理由同上）
CREATE INDEX IF NOT EXISTS episode_trgm_idx ON companion.memory_episode
  USING gin (body_plain gin_trgm_ops);
CREATE INDEX IF NOT EXISTS episode_sub_cls_exp_idx ON companion.memory_episode (subject_id, class, expires_at)
  WHERE superseded_by IS NULL;
CREATE INDEX IF NOT EXISTS episode_peer_visibility_idx ON companion.memory_episode (peer_key, visibility);
CREATE INDEX IF NOT EXISTS episode_dedupe_idx ON companion.memory_episode (dedupe_key);
CREATE INDEX IF NOT EXISTS episode_tags_gin_idx ON companion.memory_episode USING gin (risk_tags);

-- ---------------------------------------------------------------------
-- 8. session_context —— L1 的 PG 侧投影（只存元数据，绝不存原文）（arch §3.3）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.session_context (
  ctx_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  peer_key       text NOT NULL,
  subject_id     uuid REFERENCES companion.subject(subject_id) ON DELETE SET NULL,
  topic_stack    jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary_hash   text NOT NULL,                     -- 摘要 sha256；原文只在 SQLite L1（24h）
  candidate_promotions jsonb NOT NULL DEFAULT '[]'::jsonb,
  token_estimate integer NOT NULL DEFAULT 0 CHECK (token_estimate >= 0),
  expires_at     timestamptz NOT NULL,              -- created_at + 24h（arch §2.1）
  promoted_to    uuid,                              -- 晋升后指向 episode/profile id
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ctx_ttl_positive CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS ctx_exp_idx ON companion.session_context (expires_at);
CREATE INDEX IF NOT EXISTS ctx_peer_idx ON companion.session_context (peer_key, updated_at DESC);

COMMENT ON TABLE companion.session_context IS
  'Authoritative trace of what the disposable L1 SQLite cache held. Content deliberately absent: only hash + metadata (D5).';

-- ---------------------------------------------------------------------
-- 9. memory_fact —— L4 语义三元组（二期填充，一期可为空）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.memory_fact (
  fact_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_id     uuid NOT NULL REFERENCES companion.subject(subject_id) ON DELETE CASCADE,
  predicate      text NOT NULL,                     -- 'has_allergy','prefers_tone','resides_in'
  object_slot    text GENERATED ALWAYS AS (COALESCE(object_plain,'')) STORED,  -- UNIQUE 需确定性列
  object_plain   text,
  object_enc     bytea,
  sensitivity    companion.sensitivity_level NOT NULL DEFAULT 'internal',
  evidence_refs  uuid[] NOT NULL DEFAULT '{}',      -- 支撑该断言的 episode id 集合
  support_count  smallint NOT NULL DEFAULT 1,
  confidence     real NOT NULL DEFAULT 0.5 CHECK (confidence BETWEEN 0 AND 1),
  contradicts    uuid[] NOT NULL DEFAULT '{}',
  created_at     timestamptz NOT NULL DEFAULT now(),
  revised_at     timestamptz,
  CONSTRAINT fact_object_exactly_one CHECK (
    (object_plain IS NOT NULL AND object_enc IS NULL) OR (object_enc IS NOT NULL AND object_plain IS NULL)
  ),
  CONSTRAINT fact_subject_pred_uq UNIQUE (subject_id, predicate, object_slot)
);

CREATE INDEX IF NOT EXISTS fact_subject_pred_idx ON companion.memory_fact (subject_id, predicate);
CREATE INDEX IF NOT EXISTS fact_evidence_gin_idx ON companion.memory_fact USING gin (evidence_refs);

-- ---------------------------------------------------------------------
-- 10. memory_embedding —— 向量升级位（arch §7.4：一期建空表，避免未来大改 schema）
--     ⚠ `vec` 列**不在本脚本创建**：host PG 未安装 pgvector（arch §1.4 实测），
--       引用 vector 类型会让整个迁移失败。启用 pgvector 时由 004_retention.sql 的
--       companion.enable_vector_slot() 做 guarded ALTER。一期只填 vec_jsonb。
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.memory_embedding (
  embedding_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  object_kind    text NOT NULL CHECK (object_kind IN ('episode','profile','preference','fact')),
  object_ref     uuid NOT NULL,
  model          text NOT NULL,                     -- 'bge-m3@sha256:...' —— 版本必须固定（G1 同纪律）
  dim            smallint NOT NULL CHECK (dim BETWEEN 64 AND 4096),
  vec_jsonb      jsonb,                              -- 一期占位；上 pgvector 后退役
  created_at     timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT emb_object_uq UNIQUE (object_kind, object_ref, model)
);

COMMENT ON TABLE companion.memory_embedding IS
  'Phase-2 slot. Empty in phase 1. The vector column is added only by enable_vector_slot() when pgvector exists (arch §1.4: host lacks it).';

-- ---------------------------------------------------------------------
-- 11. memory_access_log —— 字段级访问审计（arch §5.5）· 按月分区
--     真源仍是 JSONL + collector 异地副本（F3）；本表是查询视图。
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.memory_access_log (
  log_id         bigint GENERATED ALWAYS AS IDENTITY,
  ts             timestamptz NOT NULL DEFAULT now(),
  actor_kind     companion.actor_kind NOT NULL,
  actor_id       text NOT NULL,                     -- session id / service name / job name
  channel        text,
  chat_id        text,
  user_id        text,
  operation      companion.access_operation NOT NULL,
  object_kind    text,
  object_ref     text,                              -- memory id 或 query 的 sha256，不含查询原文
  class          companion.memory_class,
  sensitivity    companion.sensitivity_level,
  approved       boolean NOT NULL DEFAULT false,
  approval_id    text,
  result         companion.access_result NOT NULL,
  risk_tags      text[] NOT NULL DEFAULT '{}',
  rows_returned  integer NOT NULL DEFAULT 0,
  bytes_out      integer NOT NULL DEFAULT 0,
  latency_ms     integer,
  principal_sock text,                              -- 来源标识（容器 IP），非终端用户 IP
  PRIMARY KEY (log_id, ts)
) PARTITION BY RANGE (ts);

COMMENT ON COLUMN companion.memory_access_log.operation IS
  '''decrypt'' is a first-class operation: who unlocked which PII must be answerable even if the value was unused (arch §5.5).';
COMMENT ON COLUMN companion.memory_access_log.object_ref IS
  'Never plaintext. Query strings are stored as sha256 to keep secrets out of the audit trail (D5).';

-- monthly partitions + a default catch-all so an unmapped month cannot lose rows.
-- ⚠ 分区名必须匹配 ^memory_access_log_[0-9]{6}$（004_retention.prune_access_log 依赖该形状）；
--   故用 format('%s%02s', y, m) 显式补零，不能用 m::text。
DO $$
DECLARE y int; m int; start_ts text; end_ts text; part text; ey int; em int;
BEGIN
  FOR y IN SELECT generate_series(extract(year from now())::int, extract(year from now())::int + 1) LOOP
    FOR m IN SELECT generate_series(1,12) LOOP
      -- 次年月份进位：m=12 → 次年 1 月
      ey := y + (m / 12);
      em := (m % 12) + 1;
      start_ts := format('%s-%s-01', y, lpad(m::text,2,'0'));
      end_ts   := format('%s-%s-01', ey, lpad(em::text,2,'0'));
      part     := format('memory_access_log_%s%s', y, lpad(m::text,2,'0'));
      BEGIN
        EXECUTE format(
          'CREATE TABLE IF NOT EXISTS companion.%I PARTITION OF companion.memory_access_log FOR VALUES FROM (%L) TO (%L)',
          part, start_ts::timestamptz, end_ts::timestamptz);
      EXCEPTION WHEN duplicate_table THEN NULL;
      END;
    END LOOP;
  END LOOP;
  EXECUTE 'CREATE TABLE IF NOT EXISTS companion.memory_access_log_default PARTITION OF companion.memory_access_log DEFAULT';
END
$$;

CREATE INDEX IF NOT EXISTS access_actor_ts_idx ON companion.memory_access_log (actor_id, ts);
CREATE INDEX IF NOT EXISTS access_obj_ts_idx   ON companion.memory_access_log (object_ref, ts);
CREATE INDEX IF NOT EXISTS access_result_idx   ON companion.memory_access_log (result, ts);
CREATE INDEX IF NOT EXISTS access_sens_idx     ON companion.memory_access_log (sensitivity, operation, ts);

-- ---------------------------------------------------------------------
-- 12. memory_tombstone —— 删除证明（只含不可逆摘要）（arch §5.4 / §5.7）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.memory_tombstone (
  tombstone_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  object_kind    text NOT NULL,
  object_hash    text NOT NULL,                     -- 被删内容 sha256
  class          companion.memory_class,
  sensitivity    companion.sensitivity_level,
  deleted_at     timestamptz NOT NULL DEFAULT now(),
  deleted_by     text NOT NULL,
  reason_code    text NOT NULL,                     -- 'user_forget'|'ttl_expired'|'poison_reject'|'conflict_supersede'
  approval_id    text,
  backup_rotated boolean NOT NULL DEFAULT false,
  cascade_count  smallint NOT NULL DEFAULT 0,
  CONSTRAINT tombstone_irreversible CHECK (object_hash ~ '^[0-9a-f]{64}$')
);

COMMENT ON TABLE companion.memory_tombstone IS
  'Append-only proof-of-deletion. Owner may NOT delete rows here (arch §5.7): otherwise hiding a failed forget becomes possible (TM-014 analogue).';

CREATE INDEX IF NOT EXISTS tomb_hash_idx ON companion.memory_tombstone (object_hash);
CREATE INDEX IF NOT EXISTS tomb_time_idx ON companion.memory_tombstone (deleted_at DESC);

-- ---------------------------------------------------------------------
-- 13. profile_conflict —— 冲突队列（不自动覆盖）（arch §4.4 / §4.5）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.profile_conflict (
  conflict_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_id     uuid NOT NULL REFERENCES companion.subject(subject_id) ON DELETE CASCADE,
  attr_key       text NOT NULL,
  existing_kind  text NOT NULL CHECK (existing_kind IN ('profile','preference','episode')),
  existing_ref   uuid NOT NULL,
  incoming_hash  text NOT NULL,
  incoming_meta  jsonb NOT NULL DEFAULT '{}'::jsonb, -- class/sensitivity/source/risk_tags（无原文）
  reason         text NOT NULL CHECK (reason IN ('contradiction','low_confidence','risk_tagged','promotion_candidate')),
  status         companion.conflict_status NOT NULL DEFAULT 'open',
  resolved_by    text,
  resolved_at    timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now(),
  expires_at     timestamptz
);

CREATE INDEX IF NOT EXISTS conflict_open_idx ON companion.profile_conflict (subject_id, attr_key)
  WHERE status = 'open';

-- ---------------------------------------------------------------------
-- 14. job_run / artifact_baseline —— 运维可见性（arch §8.1 / §8.6）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS companion.job_run (
  job            text NOT NULL,
  started_at     timestamptz NOT NULL,
  finished_at    timestamptz,
  rows_affected  integer NOT NULL DEFAULT 0,
  status         text NOT NULL CHECK (status IN ('running','ok','failed')),
  detail_hash    text,                              -- 错误摘要哈希，不含堆栈原文（A7）
  PRIMARY KEY (job, started_at)
);

COMMENT ON TABLE companion.job_run IS
  'Silence is an alarm: watcher alerts when the newest ok row for a daily job is older than 26h (arch §8.1, E7).';

CREATE TABLE IF NOT EXISTS companion.artifact_baseline (
  path        text PRIMARY KEY,
  sha256      text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  recorded_at timestamptz NOT NULL DEFAULT now(),
  note        text
);

-- ---------------------------------------------------------------------
-- 15. 触发器：updated_at 维护 + 写入守卫
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION companion.touch_updated_at() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_profile_touch ON companion.user_profile;
CREATE TRIGGER trg_profile_touch BEFORE UPDATE ON companion.user_profile
  FOR EACH ROW EXECUTE FUNCTION companion.touch_updated_at();
DROP TRIGGER IF EXISTS trg_pref_touch ON companion.user_preference;
CREATE TRIGGER trg_pref_touch BEFORE UPDATE ON companion.user_preference
  FOR EACH ROW EXECUTE FUNCTION companion.touch_updated_at();
DROP TRIGGER IF EXISTS trg_ctx_touch ON companion.session_context;
CREATE TRIGGER trg_ctx_touch BEFORE UPDATE ON companion.session_context
  FOR EACH ROW EXECUTE FUNCTION companion.touch_updated_at();
DROP TRIGGER IF EXISTS trg_policy_touch ON companion.memory_class_policy;
CREATE TRIGGER trg_policy_touch BEFORE UPDATE ON companion.memory_class_policy
  FOR EACH ROW EXECUTE FUNCTION companion.touch_updated_at();

-- ---------------------------------------------------------------------
-- 16. 可读视图（服务侧解密前的行过滤集中在这里，避免应用层散落 ACL）
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW companion.memory_readable AS
SELECT e.episode_id AS memory_id, 'episode'::text AS kind, e.subject_id, e.peer_key, e.class,
       e.body_plain, e.body_enc, e.body_hash, e.sensitivity, e.visibility,
       e.occurred_at, e.expires_at, e.hit_count, e.confidence, e.risk_tags, e.source_channel
  FROM companion.memory_episode e
 WHERE e.superseded_by IS NULL
UNION ALL
SELECT p.profile_id, 'profile', p.subject_id, NULL, 'profile'::companion.memory_class,
       p.value_plain, p.value_enc, NULL, p.sensitivity, p.visibility,
       p.created_at, NULL, p.hit_count, p.confidence, '{}', NULL
  FROM companion.user_profile p
 WHERE p.superseded_by IS NULL
UNION ALL
SELECT f.pref_id, 'preference', f.subject_id, f.scope_peer, 'preference'::companion.memory_class,
       f.value_plain, f.value_enc, NULL, f.sensitivity, f.visibility,
       f.created_at, NULL, 1, 1.0, '{}', NULL
  FROM companion.user_preference f;

COMMIT;

-- =====================================================================
-- Post-check（人工执行，对应验收 M-01）：
--   \dt companion.*      → 期望 ≥13 张表
--   \dv companion.*      → memory_readable
--   SELECT typname FROM pg_type WHERE typnamespace='companion'::regnamespace; → 8 个 enum
-- =====================================================================
