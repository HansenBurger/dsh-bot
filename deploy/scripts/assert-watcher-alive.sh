#!/usr/bin/env bash
# E7 — 「watcher 自身心跳告警（沉默即告警）」的外部观察端。
#
# 基线验收动作是「停 watcher → 收到 alive-missing」。要 *收到* 就必须有第二双眼睛：
# 一个组件无法给自己的死亡发通知。ops/watcher 每轮写 state/watcher.heartbeat（宿主可见），
# 本脚本只回答一个问题——那个文件还新不新——所以它可以挂在 NAS 的 cron 上，
# 也可以在演练里被人工执行。它不联网、不读密钥、不碰容器。
#
#   bash deploy/scripts/assert-watcher-alive.sh              # 默认阈值 = ALIVE_HEARTBEAT_MIN(5) 的 2 倍
#   MAX_AGE_S=120 bash deploy/scripts/assert-watcher-alive.sh
set -uo pipefail

STATE_FILE="${1:-state/watcher.heartbeat}"
MAX_AGE_S="${MAX_AGE_S:-600}" # 2 × ALIVE_HEARTBEAT_MIN(5)

if [[ ! -f "$STATE_FILE" ]]; then
  echo "FAIL alive-missing: $STATE_FILE 不存在（watcher 没跑过，或 state 挂载不对）"
  exit 1
fi

now=$(date +%s)
# GNU stat（NAS 上的 busybox/coreutils 均可用）；取 mtime 秒。
mtime=$(stat -c %Y "$STATE_FILE" 2>/dev/null || echo 0)
if [[ "$mtime" == "0" ]]; then
  echo "FAIL alive-unreadable: 无法 stat $STATE_FILE"
  exit 1
fi
age=$(( now - mtime ))
if (( age > MAX_AGE_S )); then
  echo "FAIL alive-stale: 心跳已 ${age}s 未更新（阈值 ${MAX_AGE_S}s）——watcher 沉默即告警（E7）"
  exit 1
fi
echo "OK alive: ${age}s 前 $(tail -1 "$STATE_FILE" 2>/dev/null | tr -d '\n' | cut -c1-160)"
exit 0
