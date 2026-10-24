-- =====================================================================
-- t5 · L1 读取缓存（memory-cache）— SQLite 侧的 PG 投影
-- 依据：docs/memory/t4-memory-architecture.md §2.1 / §4.2 / §8.3；
--       任务书要求「写入双写（PG + SQLite），读取先查 SQLite miss 再查 PG 并回填」。
--
-- 与 t1 交付的 l1-cache.sql 的关系：
--   * l1-cache.sql 管 **工作记忆**（context_entry / turn_window / promotion_candidate /
--     dedupe_window）——那些 PG 没有对应行的东西。
--   * 本文件管 **L2/L3 行的读投影缓存**——PG 永远是权威，这里只是加速器。
--   两者同库不同表，故本文件单独一份，不改 t1 的 DDL（避免与已验证脚本漂移）。
--
-- ⚠ 三条不变式（实现侧强制，DDL 只是第二道）：
--   1. `encrypted = 0` 恒成立：PII/pii_raw 行的**明文永不落 L1**（t4 §5.2）。
--      加密行的缓存价值 = 密文 + 元数据，读命中后仍需 PG 解密，因此根本不缓存其正文。
--   2. `visibility = 'admin'` 的行不缓存：admin 行只允许 owner CLI 路径读取，
--      缓存会把"不可见"变成"在磁盘上可读"。
--   3. 任何写入/遗忘都会 bump `cache_meta.generation`，读路径带 generation 谓词，
--      因此过期投影不可能被当成当前值返回（§8.3 一致性）。
-- =====================================================================

CREATE TABLE IF NOT EXISTS memory_cache (
  memory_id   TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('profile','preference','episode')),
  class       TEXT NOT NULL,
  subject_key TEXT,
  peer_key    TEXT,
  visibility  TEXT NOT NULL CHECK (visibility IN ('private','peer','owner')),
  sensitivity TEXT NOT NULL CHECK (sensitivity IN ('public','internal')),
  body        TEXT NOT NULL,
  encrypted   INTEGER NOT NULL DEFAULT 0 CHECK (encrypted = 0),
  occurred_at TEXT,
  expires_at  INTEGER,
  generation  INTEGER NOT NULL,
  cached_at   INTEGER NOT NULL,
  hits        INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS mc_exp_idx      ON memory_cache (expires_at);
CREATE INDEX IF NOT EXISTS mc_peer_idx     ON memory_cache (peer_key, occurred_at DESC);
CREATE INDEX IF NOT EXISTS mc_subject_idx  ON memory_cache (subject_key, class);

-- 查询级投影缓存（search 的结果 id 列表，不含正文；正文仍走 memory_cache/PG）。
CREATE TABLE IF NOT EXISTS search_cache (
  cache_key   TEXT PRIMARY KEY,
  generation  INTEGER NOT NULL,
  memory_ids  TEXT NOT NULL,
  meta_json   TEXT NOT NULL DEFAULT '{}',
  truncated   INTEGER NOT NULL DEFAULT 0,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sc_exp_idx ON search_cache (expires_at);

CREATE TABLE IF NOT EXISTS cache_meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO cache_meta (key, value) VALUES ('generation', '1');

-- 缓存健康视图（§8.5 容量与命中率可观测）。
CREATE VIEW IF NOT EXISTS v_cache_health AS
SELECT
  (SELECT count(*) FROM memory_cache)                                   AS rows_cached,
  (SELECT count(*) FROM memory_cache WHERE expires_at IS NOT NULL
     AND expires_at < (SELECT cast(strftime('%s','now') AS integer)*1000)) AS rows_stale,
  (SELECT cast(value AS integer) FROM cache_meta WHERE key='generation')  AS generation,
  (SELECT count(*) FROM search_cache)                                   AS queries_cached;
