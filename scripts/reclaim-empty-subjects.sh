#!/usr/bin/env bash
# reclaim-empty-subjects.sh — T9-F6: 合成主体壳残留的清理路径（数据卫生，无泄漏）。
#
# 背景（t9 报告 §7 T9-F6 + §9 未清理项）：测试用合成 principal 走过正式 owner forget
# 路径后，profile/preference/episode 行与 L1 缓存都清了、tombstone 落了，但
# `companion.subject` 的行本身留下来成为"空壳"——只是计数噪声，不影响身份边界。
# 本脚本给出那条被要求的"清理路径"：枚举零记忆主体 → 人工确认 → 删除。
#
# 安全性为什么够：
#   - `ensureSubject`（repository.mjs:141）是 upsert，删掉的壳会在下一次合法写入时
#     自动重建；`is_owner`/`identity_trust` 证据由服务端签名主体重新注入，不靠壳存活。
#   - 默认 DRY RUN（ro 角色只读）。删除必须显式 GO=1（rw 角色）。
#   - owner 主体的壳默认**不删**（INCLUDE_OWNER=1 才纳入）：真主人的壳是白名单证据的
#     落点，别顺手清掉。
#   - DELETE 语句内嵌同一组 NOT EXISTS 谓词，扫描与删除之间的写入竞态由数据库自己
#     兜底（要么仍然全空才删，要么根本不删）。
#   - ROLLBACK=1 可配合 GO=1 做机制演练：真实执行 DELETE 后回滚，零变更。
#
# 用法（宿主，postgres unix socket，密码走 PGPASSWORD 不进 argv）：
#   bash scripts/reclaim-empty-subjects.sh                        # 只列出
#   GRACE_HOURS=0 bash scripts/reclaim-empty-subjects.sh          # 去掉 24h 观察窗
#   GO=1 bash scripts/reclaim-empty-subjects.sh                   # 真删（不含 owner 壳）
#   GO=1 ROLLBACK=1 bash scripts/reclaim-empty-subjects.sh        # 演练：执行后回滚
set -euo pipefail

REPO="${REPO:-/home/burger/DSH-Bot}"
SOCKET_DIR="${MEM_PG_SOCKET_DIR:-/var/run/postgresql}"
DB="${MEM_PG_DB:-dsh_companion}"
GRACE_HOURS="${GRACE_HOURS:-24}"
RO_PWD_FILE="$REPO/deploy/secrets/mem-pg-ro-password"
RW_PWD_FILE="$REPO/deploy/secrets/mem-pg-rw-password"

psql_ro() { PGPASSWORD="$(cat "$RO_PWD_FILE")" psql -h "$SOCKET_DIR" -U dsh_companion_ro -d "$DB" -X -q -A -F'|' -t "$@"; }

# 六个引用 companion.subject 的行表全部为空，且 last_seen 超过观察窗，才算"壳"。
EMPTY_WHERE="
  s.last_seen_at < now() - make_interval(hours => ${GRACE_HOURS})
  AND NOT EXISTS (SELECT 1 FROM companion.user_profile      x WHERE x.subject_id = s.subject_id)
  AND NOT EXISTS (SELECT 1 FROM companion.user_preference   x WHERE x.subject_id = s.subject_id)
  AND NOT EXISTS (SELECT 1 FROM companion.memory_episode    x WHERE x.subject_id = s.subject_id)
  AND NOT EXISTS (SELECT 1 FROM companion.memory_fact       x WHERE x.subject_id = s.subject_id)
  AND NOT EXISTS (SELECT 1 FROM companion.session_context   x WHERE x.subject_id = s.subject_id)
  AND NOT EXISTS (SELECT 1 FROM companion.profile_conflict  x WHERE x.subject_id = s.subject_id)
"
OWNER_FILTER=""
[ "${INCLUDE_OWNER:-0}" = "1" ] || OWNER_FILTER="AND NOT s.is_owner"

echo "== 1/2 零记忆主体壳（grace=${GRACE_HOURS}h, owner 排除=${OWNER_FILTER:-无}）=="
mapfile -t shells < <(psql_ro -c "
  SELECT s.subject_key, s.subject_id, s.is_owner, s.last_seen_at
  FROM companion.subject s
  WHERE ${EMPTY_WHERE} ${OWNER_FILTER}
  ORDER BY s.last_seen_at")
if [ "${#shells[@]}" -eq 0 ]; then
  echo "  clean: 没有可回收的主体壳"
  exit 0
fi
for row in "${shells[@]}"; do echo "  shell  $row"; done

if [ "${GO:-0}" != "1" ]; then
  echo "DRY RUN：未删除任何东西。确认清单后 GO=1 重跑（ROLLBACK=1 可先演练）。"
  exit 0
fi

echo "== 2/2 GO=1：删除 ${#shells[@]} 个壳（逐条内嵌竞态谓词）=="
[ -r "$RW_PWD_FILE" ] || { echo "缺少 $RW_PWD_FILE（rw 密码）" >&2; exit 2; }
script="$(mktemp)"
trap 'rm -f "$script"' EXIT
{
  echo 'BEGIN;'
  for row in "${shells[@]}"; do
    key="${row%%|*}"; id="$(echo "$row" | cut -d'|' -f2)"
    printf "DELETE FROM companion.subject s WHERE s.subject_id = '%s'::uuid AND %s %s;\n" "$id" "$EMPTY_WHERE" "$OWNER_FILTER"
  done
  if [ "${ROLLBACK:-0}" = "1" ]; then echo 'ROLLBACK;'; else echo 'COMMIT;'; fi
} > "$script"
PGPASSWORD="$(cat "$RW_PWD_FILE")" psql -h "$SOCKET_DIR" -U dsh_companion_rw -d "$DB" -X -q -v ON_ERROR_STOP=1 -f "$script"
if [ "${ROLLBACK:-0}" = "1" ]; then echo "演练完成：DELETE 全部执行成功后 ROLLBACK，零变更。"; else echo "已提交删除 ${#shells[@]} 个主体壳。"; fi
echo "注意：这条流不落 memory.access JSONL（脚本绕过了服务），操作记录留在本机 stdout。"
