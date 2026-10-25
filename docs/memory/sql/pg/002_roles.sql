-- =====================================================================
-- t4 · 角色与最小授权（读写分离）
-- 依据：用户确认选型「独立数据库 dsh_companion + 只读/读写分离用户」；基线 D1/D2/B5
-- 前置：001_schema.sql 已执行
-- 执行：sudo -u postgres psql -d dsh_companion -v ON_ERROR_STOP=1 -f 002_roles.sql
-- 幂等：可重复执行（DO 块内判断存在性）
-- ⚠ 口令由运维在部署时注入，本文件**不含任何真实口令**（D4：仓库只有 .env.example）。
--    占位变量 :rw_password / :ro_password 通过 psql -v 传入，或由 CI 从 secret store 渲染。
-- =====================================================================

BEGIN;

SET search_path = companion, public;

-- ---------------------------------------------------------------------
-- 1. 两个 LOGIN 角色：rw（memory-service 写路径）/ ro（检索与只读路径）
--    刻意不给 CREATEDB/CREATEROLE/BYPASSRLS/SUPERUSER —— 全部 NOSUPERUSER。
-- ---------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dsh_companion_rw') THEN
    CREATE ROLE dsh_companion_rw LOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT 8
      PASSWORD '__RW_PASSWORD__';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dsh_companion_ro') THEN
    CREATE ROLE dsh_companion_ro LOGIN
      NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION CONNECTION LIMIT 8
      PASSWORD '__RO_PASSWORD__';
  END IF;
END
$$;

COMMENT ON ROLE dsh_companion_rw IS
  'memory-service write path: INSERT/UPDATE/DELETE on content tables, INSERT-only on audit/tombstone.';
COMMENT ON ROLE dsh_companion_ro IS
  'search/read path. Cannot mutate any memory row — a compromised read-only credential cannot erase or poison.';

-- ---------------------------------------------------------------------
-- 2. 库级/schema 级权限
-- ---------------------------------------------------------------------
REVOKE ALL ON SCHEMA companion FROM PUBLIC;
REVOKE ALL ON DATABASE dsh_companion FROM PUBLIC;

GRANT USAGE  ON SCHEMA companion TO dsh_companion_rw, dsh_companion_ro;
GRANT CONNECT ON DATABASE dsh_companion TO dsh_companion_rw, dsh_companion_ro;

-- ---------------------------------------------------------------------
-- 3. 内容表：ro 只读，rw 可写
-- ---------------------------------------------------------------------
GRANT SELECT ON ALL TABLES IN SCHEMA companion TO dsh_companion_ro;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  companion.memory_class_policy,
  companion.subject,
  companion.user_profile,
  companion.user_preference,
  companion.memory_episode,
  companion.session_context,
  companion.memory_fact,
  companion.memory_embedding
TO dsh_companion_rw;

-- ---------------------------------------------------------------------
-- 4. 审计与删除证明：**只允许追加**（F3 append-only 的 DB 侧表达）
--    ro 可读以便出报表；rw 无 UPDATE/DELETE ⇒ 服务无法改写或删除审计行。
-- ---------------------------------------------------------------------
GRANT SELECT, INSERT ON TABLE
  companion.memory_access_log,
  companion.memory_tombstone
TO dsh_companion_rw;

GRANT SELECT ON TABLE
  companion.memory_access_log,
  companion.memory_tombstone
TO dsh_companion_ro;

-- identity 列需要用到序列
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA companion TO dsh_companion_rw, dsh_companion_ro;

-- ---------------------------------------------------------------------
-- 5. job_run / artifact_baseline：仅作业身份可写
-- ---------------------------------------------------------------------
GRANT SELECT, INSERT, UPDATE ON TABLE companion.job_run TO dsh_companion_rw;
GRANT SELECT ON TABLE companion.artifact_baseline TO dsh_companion_ro;
GRANT INSERT, UPDATE ON TABLE companion.artifact_baseline TO dsh_companion_rw;

-- conflict 队列需要被裁决（UPDATE status），但不许删历史
GRANT SELECT, INSERT, UPDATE ON TABLE companion.profile_conflict TO dsh_companion_rw;

-- ---------------------------------------------------------------------
-- 6. 函数执行权：**逐个显式授权，绝不使用 ALL FUNCTIONS**
--    ⚠ 反例（本文件早期版本曾犯）：`GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA companion TO rw`
--      会把 pgcrypto/pg_trgm 装入本 schema 的 ~150 个内部函数一并授出去，
--      并且——更严重——把 004_retention.sql 里的 forget_by_subject/prune_access_log
--      也授予服务写角色，直接违背 §5.4「全量遗忘只能由 owner_cli 触发」。
--      ALTER DEFAULT PRIVILEGES 只影响**将来**创建的对象，救不了已经发生的批量授权。
--    因此这里只授"应用真正需要的那一个"，其余全部留给 004 的白名单 REVOKE/GRANT。
-- ---------------------------------------------------------------------
REVOKE ALL ON FUNCTION companion.touch_updated_at() FROM PUBLIC;
ALTER FUNCTION companion.touch_updated_at() OWNER TO dsh_companion_rw;
-- ↑ updated_at 触发器在 rw 会话内执行，故 owner 需为 rw（或保持 postgres 并 SECURITY INVOKER）。
--   触发器函数不做任何特权操作，两条路径都安全；此处选 owner=rw 以免依赖超级用户。

-- pgcrypto / pg_trgm 扩展对象归位与 PUBLIC 收紧见本节末尾的 EXTENSION FIXUP 段。

-- ---------------------------------------------------------------------
-- 7. 视图
-- ---------------------------------------------------------------------
GRANT SELECT ON companion.memory_readable TO dsh_companion_ro, dsh_companion_rw;

-- ---------------------------------------------------------------------
-- 8. 默认权限：将来新增表不会意外对 PUBLIC 开放
-- ---------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES IN SCHEMA companion REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA companion REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA companion GRANT SELECT ON TABLES TO dsh_companion_ro;

-- ---------------------------------------------------------------------
-- 9. EXTENSION FIXUP —— 三个必须修正的历史遗留问题
--    (a) 001_schema.sql 先 `SET search_path = companion` 再 CREATE EXTENSION，
--        导致 pgcrypto/pg_trgm/btree_gin 的全部对象落在 companion 而非 public →
--        `SELECT pgp_sym_encrypt(...)` 在任何非 companion 路径下都解析不到（实测报错）。
--        修正方式：迁移脚本改为在 public 下建扩展（见 001 顶部注释），本段兜底把已装错的
--        扩展重装到 public 并把 companion 里的残留清掉。
--    (b) PUBLIC 默认拿到这些函数的 EXECUTE：记忆服务的威胁模型里"任何能连库的角色
--        都能调用解密原语"是可接受但**不必要**的能力，收紧到 rw。
--    (c) ro 角色不应看到加密/解密函数存在于自己可枚举的命名空间里（最小惊讶原则）。
-- ---------------------------------------------------------------------
DO $$
DECLARE r record;
BEGIN
  -- 若扩展被装在 companion（历史错误形态），迁回 public
  IF EXISTS (SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
              WHERE e.extname='pgcrypto' AND n.nspname='companion') THEN
    EXECUTE 'ALTER EXTENSION pgcrypto SET SCHEMA public';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
              WHERE e.extname='pg_trgm' AND n.nspname='companion') THEN
    EXECUTE 'ALTER EXTENSION pg_trgm SET SCHEMA public';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_extension e JOIN pg_namespace n ON n.oid=e.extnamespace
              WHERE e.extname='btree_gin' AND n.nspname='companion') THEN
    EXECUTE 'ALTER EXTENSION btree_gin SET SCHEMA public';
  END IF;

  -- 收紧：pgcrypto 原语只给 rw（服务侧加解密），ro 一律不可执行
  FOR r IN
    SELECT p.oid::regprocedure AS sig FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public'
       AND (p.proname LIKE 'pgp_%' OR p.proname IN ('crypt','decrypt','encrypt','hmac','digest',
                                                    'gen_salt','gen_random_uuid','gen_random_bytes','dearmor','armor'))
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, dsh_companion_ro', r.sig);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO dsh_companion_rw', r.sig);
  END LOOP;
END
$$;

COMMIT;

-- =====================================================================
-- 9. pg_hba.conf 建议片段（**由运维手工追加到宿主 PG**，本脚本不自动改配置）
--    对应 arch §9.3 方案 A 的收敛措施 ①：按源地址限制，只允许该容器 IP。
--
--      # dsh_companion — memory-service container only (net-agent internal)
--      host  dsh_companion  dsh_companion_rw  172.28.0.50/32  scram-sha-256
--      host  dsh_companion  dsh_companion_ro  172.28.0.50/32  scram-sha-256
--      # 拒绝任何其他来源访问这两个角色
--      host  dsh_companion  dsh_companion_rw  0.0.0.0/0       reject
--      host  dsh_companion  dsh_companion_ro  0.0.0.0/0       reject
--
--    同时确认 listen_addresses = 'localhost'（实测已是 127.0.0.1:5432，C-1 满足）。
--    验证（M-12）：从 LAN 机器 `nc -zv <nas> 5432` → closed。
-- =====================================================================

-- =====================================================================
-- Post-check（对应验收 M-02）：
--   \du dsh_companion_*
--   SET ROLE dsh_companion_ro; INSERT INTO companion.memory_episode(...) → permission denied
--   SET ROLE dsh_companion_ro; DELETE FROM companion.memory_access_log → permission denied
--   SET ROLE dsh_companion_rw; DELETE FROM companion.memory_tombstone  → permission denied
-- =====================================================================
