#!/usr/bin/env bash
# assert-project-listeners.sh — 上线门禁（严格级）
#
# 只断言**本项目应当存在的监听**，每一个都必须绑在 127.0.0.1。
# 与 assert-host-baseline.sh 分工：本脚本管"我们开了什么"，基线脚本管"宿主有什么变化"。
# 拆开的理由见 docs/validation/port-audit.md §4.3 —— 原 t3 单条断言假设了干净宿主，
# 在共享 NAS VM 上会永远红，从而失去约束力。
#
# 用法：
#   bash deploy/scripts/assert-project-listeners.sh                 # S2' 起步形态
#   PROFILES=napcat bash deploy/scripts/assert-project-listeners.sh # 协议端已起
#   PROFILES=llbot  bash deploy/scripts/assert-project-listeners.sh
set -uo pipefail

DSH_GUI_PORT="${DSH_GUI_PORT:-3080}"
INGRESS_PORT="${INGRESS_PORT:-3001}"
MEMORY_ADMIN_PORT="${MEMORY_ADMIN_PORT:-8190}"

expected=("127.0.0.1:${DSH_GUI_PORT}" "127.0.0.1:${INGRESS_PORT}" "127.0.0.1:${MEMORY_ADMIN_PORT}")

case "${PROFILES:-}" in
  napcat) expected+=("127.0.0.1:3081") ;;
  llbot)  expected+=("127.0.0.1:3082") ;;
  both)   expected+=("127.0.0.1:3081" "127.0.0.1:3082") ;;
esac

fail=0

listening() {
  local addr="$1" port="${addr##*:}" ip="${addr%:*}"
  ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/^*/0.0.0.0/' | grep -qx "$ip:$port"
}

echo "== 1/2 期望监听存在性 =="
for addr in "${expected[@]}"; do
  if listening "$addr"; then
    echo "  ok       $addr"
  else
    echo "  MISSING  $addr"
    fail=1
  fi
done

echo "== 2/2 本项目不得额外发布宿主端口 =="
# 只检查本 compose project 的容器：宿主既有暴露由基线脚本负责，混在一起会互相稀释。
COMPOSE_PROJECT="${COMPOSE_PROJECT:-dsh-big-fish-bot}"
extra=0
while read -r name ports; do
  [ -z "${ports}" ] && continue
  # docker 输出形如 "127.0.0.1:3001->3001/tcp, 0.0.0.0:9999->9999/tcp"
  for mapping in $(echo "${ports}" | tr ',' '\n'); do
    host_part="${mapping%%->*}"
    case "${host_part}" in
      *127.0.0.1:*|*[::1]:*) ;;                       # loopback 前缀，合规
      *":"*)
        echo "  FAIL     non-loopback publication from ${name}: ${mapping}"
        extra=1
        ;;
      *) ;;                                            # 未发布到宿主，合规
    esac
  done
done < <(docker ps --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" --format '{{.Names}}\t{{.Ports}}' 2>/dev/null)

if [ "${extra}" -ne 0 ]; then
  echo "  → C-1 违背：compose 端口写法必须带 127.0.0.1: 前缀"
  fail=1
fi

if [ "${fail}" -eq 0 ]; then
  echo "OK project listeners match the expected set (C-1/C-16)"
else
  echo "NO-GO: project listener assertion failed"
fi
exit "${fail}"
