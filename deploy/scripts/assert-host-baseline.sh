#!/usr/bin/env bash
# assert-host-baseline.sh — 宿主监听漂移检测（E5 / C9 的具体实现）
#
# 把 docs/validation/port-audit.md §2.1 的既有非 loopback 监听固化为快照，
# 只在**发生变化**时报警：新增即失败，消失即警告。
#
# 为什么不直接把这些端口写进"允许集合"：那等于用门禁承认既成事实，
# 第三方软件改了绑址就再也看不见。漂移检测保留了发现能力（t2 E5）。
set -uo pipefail

BASELINE="${1:-deploy/config/host-listener-baseline.txt}"
if [ ! -f "${BASELINE}" ]; then
  echo "FAIL baseline not found: ${BASELINE}"
  exit 1
fi

current=$(ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/^*/0.0.0.0/' | grep -v '^127\.' | grep -v '^\[::1\]' | sort -u)
baseline=$(grep -v '^#' "${BASELINE}" | grep -v '^$' | sort -u)

added=$(comm -13 <(echo "${baseline}") <(echo "${current}"))
removed=$(comm -23 <(echo "${baseline}") <(echo "${current}"))

status=0
echo "== 新增非 loopback 监听 =="
if [ -z "${added}" ]; then
  echo "  none"
else
  while read -r line; do
    [ -n "${line}" ] || continue
    port="${line##*:}"
    owner=$(ss -ltnpH "sport = :${port}" 2>/dev/null | grep -o 'users:(([^)]*))' | head -1 || true)
    echo "  FAIL  ${line}  ${owner}"
    status=1
  done <<< "${added}"
  echo "  → 先确认归属，再决定关闭/改绑，或显式更新基线并在 port-audit 记录理由"
fi

echo "== 已消失的基线条目 =="
if [ -z "${removed}" ]; then
  echo "  none"
else
  while read -r line; do
    [ -n "${line}" ] || continue
    echo "  WARN  ${line}"
  done <<< "${removed}"
  echo "  → 服务停止或已被收紧；确认后请更新基线（保持快照与现实一致才有意义）"
fi

if [ "${status}" -eq 0 ]; then
  echo "OK host listeners match the frozen baseline (no drift)"
else
  echo "NO-GO: host listener drift detected"
fi
exit "${status}"
