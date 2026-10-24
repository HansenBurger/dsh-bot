-- =====================================================================
-- t4 · class 策略种子（arch §2.1 / §2.2 / §7.1）
-- 前置：001_schema.sql、002_roles.sql
-- 执行：sudo -u postgres psql -d dsh_companion -v ON_ERROR_STOP=1 -f 003_seed_policy.sql
-- 幂等：ON CONFLICT (class) DO NOTHING —— 已存在则不覆盖，允许运维手工收紧后不被冲掉。
--       需要"恢复默认"时显式 DELETE 后重跑本文件（该操作本身属高危，走审批）。
-- =====================================================================

BEGIN;

SET search_path = companion, public;

INSERT INTO companion.memory_class_policy
  (class, layer, ttl_days, requires_approval, encrypt_at_rest, max_body_chars,
   recency_half_life_days, allow_auto_write, note)
VALUES
  -- L2 稳定属性：永久、必审批、不加密（除非标 pii）
  ('profile',     2, NULL,  true,  false, 2000,  NULL, false,
   'Stable attributes. Permanent until owner forgets. Never auto-written.'),

  -- L2 偏好/禁忌：永久、必审批；is_veto 项在检索中优先级最高
  ('preference',  2, NULL,  true,  false, 1000,  NULL, false,
   'Preferences and taboos. Scope-aware (global/dm/group).'),

  -- L3 承诺/待办：短 TTL —— 过期的提醒没有价值，留着反而会让 bot 重复追问已完成的事
  ('commitment',  3, 7,     true,  false, 500,   7,    false,
   'Bot commitments. 7d TTL: a stale promise is worse than a forgotten one.'),

  -- L3 事件叙述：默认 180d（用户选型「episodic 可过期」）
  ('episode',     3, 180,   true,  false, 2000,  60,   false,
   'Episodic memory. Default 180d rolling window per arch §5.7.'),

  -- L3 情绪快照：低精度、短命、允许自动写（免审批以免弹窗疲劳，见 arch §11 R-9）
  ('sentiment',   3, 7,     false, false, 200,   7,    true,
   'Low-precision mood context. Auto-writable WITHOUT approval to avoid prompt fatigue; never promoted into profile.'),

  -- L1 投影：24h 硬 TTL（用户选型），元数据 only，绝不存原文
  ('session_ctx', 1, 1,     false, false, 400,   1,    true,
   'L1 SQLite cache projection. Metadata + hash only; body never stored here (D5).'),

  -- PII：永久 + 强制加密 + 审批 + 二次确认预览（arch §5.3）
  ('pii_raw',     2, NULL,  true,  true,  1000,  NULL, false,
   'PII. encrypt_at_rest is MANDATORY; write path must also require the second confirmation.')
ON CONFLICT (class) DO NOTHING;

-- ---------------------------------------------------------------------
-- artifact_baseline：把迁移脚本自身的校验和登记入库（arch §8.6 / B8 同类手法）
-- ⚠ 下列 sha256 为**占位**，部署时由 scripts/record-artifact-baseline.sh 计算真实值写入；
--   watcher 定期比对，不一致即告警（防止"改了 schema 但没人知道"）。
-- ---------------------------------------------------------------------
INSERT INTO companion.artifact_baseline (path, sha256, note) VALUES
  ('docs/memory/sql/pg/001_schema.sql', '__SHA256_PLACEHOLDER__', 'authoritative DDL'),
  ('docs/memory/sql/pg/002_roles.sql',  '__SHA256_PLACEHOLDER__', 'rw/ro grants'),
  ('docs/memory/sql/pg/003_seed_policy.sql', '__SHA256_PLACEHOLDER__', 'class policy seed'),
  ('docs/memory/sql/pg/004_retention.sql',   '__SHA256_PLACEHOLDER__', 'retention jobs'),
  ('docs/memory/sql/sqlite/l1-cache.sql',    '__SHA256_PLACEHOLDER__', 'L1 cache DDL')
ON CONFLICT (path) DO UPDATE SET sha256 = EXCLUDED.sha256, recorded_at = now(), note = EXCLUDED.note;

COMMIT;

-- =====================================================================
-- Post-check：
--   SELECT class, layer, ttl_days, requires_approval, encrypt_at_rest
--     FROM companion.memory_class_policy ORDER BY layer, class;   → 7 行
--   期望：session_ctx/sentiment 的 requires_approval = false；pii_raw 的 encrypt_at_rest = true
-- =====================================================================
