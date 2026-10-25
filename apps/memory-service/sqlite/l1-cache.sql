-- =====================================================================
-- t4 · L1 短期上下文缓存（SQLite）DDL
-- 载体：memory-service 容器命名卷 mem-l1 → /var/lib/dshbot-memory/l1.db（**非 tmpfs**）
-- 依据：用户确认选型「SQLite 文件存于 memory-service 容器持久卷，作为 L1 缓存」；arch §2.1 / §4.3 / §8.4
-- 引擎：SQLite 3.45（py sqlite3 实测同版本线）；Node 侧可用内置 node:sqlite（v22.23.4 实测可 require）
-- ---------------------------------------------------------------------
-- ★ 三条设计前提（与 PG 权威库的关系）
--   1) L1 是**可丢弃缓存**：任何不一致都以 PG 为准重建（arch §8.3 rebuild_l1_from_pg）。
--      删掉整个 l1.db 只导致"24h 内上下文丢失"，不丢长期记忆。
--   2) L1 **不是**隐私边界：内容明文落盘（性能与复杂度考虑），因此
--      - 卷权限 0700、属主 uid 10002（memory-service 独占）
--      - agent 容器无该路径挂载（compose 中 mem-l1 只出现在 memory 服务下）
--      - sensitivity >= pii 的内容**禁止**写入 L1（由服务层强制，见 CHECK 说明）
--   3) TTL 由服务定时器执行（每小时），SQLite 自身不做过期删除。
-- =====================================================================

PRAGMA journal_mode = WAL;            -- 崩溃安全 + 读并发；checkpoint 在 evict 作业里做
PRAGMA synchronous  = NORMAL;         -- WAL 下 NORMAL 已保证掉电不损坏（缓存语义可接受）
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;           -- 单写多读场景避免瞬时 SQLITE_BUSY 冒泡到请求路径
PRAGMA temp_store   = MEMORY;

-- ---------------------------------------------------------------------
-- 容量硬上限（arch §8.5：防 TM-012 把 L1 撑爆磁盘）
-- ⚠ 实测坑 1：`PRAGMA page_size` 只对**尚未创建第一页**的库生效；已有库返回旧值。
--              因此必须在建表前设置，且运维若换页大小需重建文件。
-- ⚠ 实测坑 2：max_page_count 触顶时报 "database or disk is full"（OperationalError），
--              服务层必须把它与真正的 ENOSPC 区分开（前者→丢弃最旧 slot 并重试）。
-- 计算：4096 B/page × 16384 pages = 67108864 B = 64 MiB
-- ---------------------------------------------------------------------
PRAGMA page_size      = 4096;
PRAGMA max_page_count = 16384;

-- ---------------------------------------------------------------------
-- 1. context_entry —— 进行中的话题栈 / 指代消解 / 未闭合问句
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS context_entry (
  peer_key       TEXT    NOT NULL,   -- 'telegram:dm:111' | 'onebot:group:123456'
  slot           TEXT    NOT NULL,   -- 'topic_stack','pending_question','entity_alias','last_intent'
  value_json     TEXT    NOT NULL,   -- JSON 文本；服务层负责序列化/校验
  sensitivity    TEXT    NOT NULL DEFAULT 'internal'
                    CHECK (sensitivity IN ('public','internal')),
                                  -- ⚠ 'pii'/'secret' 被 CHECK 直接排除：L1 不承载敏感值（前提 2）
  source_msg_id  TEXT,              -- 关联的 normalized message id（不含正文）
  hits           INTEGER NOT NULL DEFAULT 1,
  created_at     INTEGER NOT NULL,  -- epoch ms
  expires_at     INTEGER NOT NULL,  -- created_at + 24h（arch §2.1）
  updated_at     INTEGER NOT NULL,
  PRIMARY KEY (peer_key, slot)
);

CREATE INDEX IF NOT EXISTS ctx_exp_idx      ON context_entry (expires_at);
CREATE INDEX IF NOT EXISTS ctx_peer_hits_idx ON context_entry (peer_key, hits DESC);

-- ---------------------------------------------------------------------
-- 2. turn_window —— 最近 N 轮轻量摘要（供 prompt 背景注入）
--    刻意只存摘要 + 引用，不存原文：原文在 DSH Session JSONL（L0），避免双写（arch §2.4）。
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS turn_window (
  turn_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  peer_key       TEXT    NOT NULL,
  role           TEXT    NOT NULL CHECK (role IN ('inbound','outbound')),
  summary        TEXT    NOT NULL,          -- ≤200 字符，服务侧生成
  text_hash      TEXT    NOT NULL,          -- sha256(原文)，跨引擎对账用，不含内容
  session_ref    TEXT,                      -- DSH session id
  sender_user_id TEXT,                      -- 结构化 id（C-03：绝不存显示名）
  risk_tags      TEXT    NOT NULL DEFAULT '',  -- 逗号分隔，透传 ingress 标签
  created_at     INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS tw_peer_idx ON turn_window (peer_key, created_at DESC);
CREATE INDEX IF NOT EXISTS tw_exp_idx  ON turn_window (expires_at);

-- ---------------------------------------------------------------------
-- 3. promotion_candidate —— arch §2.3 的"出现 ≥2 次或跨 ≥2 session"判据统计位
--    注意：这里只产生**提案**，晋升动作必须经审批并写 PG（服务层 + bot-core 工具闸）。
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS promotion_candidate (
  cand_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  peer_key       TEXT    NOT NULL,
  subject_key    TEXT    NOT NULL,
  attr_key       TEXT    NOT NULL,
  value_hash     TEXT    NOT NULL,          -- sha256，绝不明文
  observations   INTEGER NOT NULL DEFAULT 1,
  session_count  INTEGER NOT NULL DEFAULT 1,
  -- distinct session ids that produced this value, comma-joined. §2.3's "跨 ≥2 session"
  -- judgement cannot be evaluated from a counter alone: incrementing it on every repeat
  -- would promote a single long conversation into a "stable" fact.
  sessions       TEXT    NOT NULL DEFAULT '',
  first_seen_at  INTEGER NOT NULL,
  last_seen_at   INTEGER NOT NULL,
  proposed       INTEGER NOT NULL DEFAULT 0,   -- 0=未上报, 1=已进 PG conflict 队列
  UNIQUE (subject_key, attr_key, value_hash)
);

CREATE INDEX IF NOT EXISTS pc_qualify_idx ON promotion_candidate (proposed, observations, session_count);

-- ---------------------------------------------------------------------
-- 4. dedupe_window —— 消息去重（t3 arch §5.2「以 message_id 做 7 天 LRU 去重」的服务侧对应物）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dedupe_window (
  dedupe_key     TEXT    PRIMARY KEY,       -- sha256(subject||class||normalized_body)
  memory_kind    TEXT    NOT NULL,
  memory_ref     TEXT    NOT NULL,          -- PG 侧 uuid（字符串存，避免类型耦合）
  hit_count      INTEGER NOT NULL DEFAULT 1,
  first_seen_at  INTEGER NOT NULL,
  last_seen_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS dd_lastseen_idx ON dedupe_window (last_seen_at);

-- ---------------------------------------------------------------------
-- 5. meta —— 构建/迁移标记与 L1 开关（arch §5.7「允许关闭 L1 持久化」）
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS meta (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);

INSERT OR IGNORE INTO meta (k, v) VALUES
  ('schema_version', '1'),
  ('ttl_hours',      '24'),
  ('l1_persistence', 'on'),      -- off ⇒ 服务改用 :memory: 并跳过备份（重启即失忆，属预期）
  ('built_by',       't4-memory-architecture §2.1');

-- ---------------------------------------------------------------------
-- 6. 视图：给运维/调试用的即时概览（不含任何正文）
--    ⚠ 不要用 pragma_integrity_check()：SQLite 没有该 SQL 函数（实测 "no such function"），
--      完整性检查只能走 `PRAGMA integrity_check` 语句，由服务的 healthz 端点单独执行。
-- ---------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS v_l1_health AS
SELECT
  (SELECT count(*) FROM context_entry)                                              AS live_ctx,
  (SELECT count(*) FROM context_entry WHERE expires_at < (CAST(strftime('%s','now') AS INTEGER)*1000)) AS overdue_ctx,
  (SELECT count(*) FROM turn_window)                                                AS turns,
  (SELECT count(*) FROM promotion_candidate WHERE proposed = 0)                     AS unpromoted_cands,
  (SELECT count(*) FROM dedupe_window)                                              AS dedupe_keys,
  (SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size())      AS db_bytes;

-- =====================================================================
-- 清理作业（由 memory-service 每小时调用；对应验收 M-08）
-- =====================================================================
-- DELETE FROM context_entry       WHERE expires_at < CAST(strftime('%s','now') AS INTEGER)*1000;
-- DELETE FROM turn_window         WHERE expires_at < CAST(strftime('%s','now') AS INTEGER)*1000;
-- DELETE FROM dedupe_window       WHERE last_seen_at < (CAST(strftime('%s','now') AS INTEGER)*1000) - 7*86400000;
-- VACUUM; PRAGMA wal_checkpoint(TRUNCATE);
--
-- 每日备份（arch §8.4）：VACUUM INTO '/tmp/l1-<date>.db' → age 加密 → rsync 到专用备份卷。
--   ⚠ 实测坑 3：`VACUUM` 不能在事务内执行（"cannot VACUUM from within a transaction"）。
--      Node/Python 驱动常隐式开启事务，因此备份必须在**独立连接**上、且处于 autocommit 时调用；
--      memory-service 的实现要求：备份作业先 commit/关闭写事务，再新开只读连接做 VACUUM INTO。
--   ⚠ 该流的发起方是 memory-service，**不是** dsh/agent 容器（C-08/U2 的禁令对象是 agent 可读面）。

-- =====================================================================
-- Post-check（可直接跑）：
--   INSERT INTO context_entry(peer_key,slot,value_json,created_at,expires_at,updated_at)
--     VALUES('telegram:dm:111','topic_stack','{"t":"周末计划"}',0,86400000,0);
--   INSERT INTO context_entry(...,sensitivity,...) VALUES(...,'pii',...) → CHECK constraint failed
--   SELECT * FROM v_l1_health;
-- =====================================================================
