# ops/watcher

栈外的看门狗：轮询 net-ops 上的必需依赖，读 `logs/*.jsonl` 审计流，把判定写成
`state/degraded` 旗标（E2/E3 的生产侧），并把告警作为结构化文件投给 gateway 的送达腿（F2）。
完整设计与残余缺口见 [`docs/validation/ops-watcher.md`](../docs/validation/ops-watcher.md)。

硬约束（改代码前先读）：**零 LLM token**、**不发布任何宿主端口**（`assert-listeners.sh` 必须一直绿）、
不依赖 npm 包、不碰 napcat、绝不删除人工写入的旗标。

## 运行

```bash
# 随栈起（compose 的 ops profile）
docker compose -f deploy/compose.yaml --profile ops up -d --build watcher
# 本地裸跑（指向仓库里的 logs/ 与 state/）
node ops/watcher/src/index.mjs
# 单测
npm run test:watcher
```

上线前必须先把队列目录以容器 uid（1000）建好，否则 Docker 会自动以 root 建目录导致 `EACCES`：

```bash
mkdir -p state/alerts/{pending,sent,dropped} && chmod -R 0777 state/alerts
```

## 配置（全部 env，皆有默认值）

| 变量 | 默认 | 含义 |
|---|---|---|
| `WATCHER_TARGETS` | broker/memory 必需 + proxy 可选 | `name=scheme://host:port[/path]:(required\|optional)` 逗号分隔；`tcp` 只做连通性探针，`http` 只要端口应答即算存活 |
| `WATCHER_INTERVAL_S` | 10 | 每轮间隔 |
| `WATCHER_FAIL_THRESHOLD` / `WATCHER_CLOSE_THRESHOLD` | 3 / 3 | 熔断 / 自动闭合所需的连续次数 |
| `WATCHER_PROBE_TIMEOUT_MS` | 2000 | 单探针超时（防一条腿卡死整轮） |
| `WATCHER_LOG_DIR` / `WATCHER_LOG_FILES` | `/var/log/dshbot` / `ingress,agent,broker,memory.jsonl` | 审计流来源 |
| `WATCHER_STALE_LOG_MIN` | 60 | 审计流停增多久算 E7 事件（只告警） |
| `DEGRADED_FLAG_PATH` / `WATCHER_STATE_DIR` | `/state/degraded` / `/state` | 旗标 + 心跳 + 游标 + 告警账本落点 |
| `WATCHER_CREDENTIAL_BURST` / `…_WINDOW_S` | 5 / 120 | E3 信号 1（凭据路径探测突发） |
| `WATCHER_EGRESS_DRIFT_STREAK` | 2 | E3 信号 2（非白名单出站点） |
| `WATCHER_APPROVAL_DENY_STREAK` | 3 | E3 信号 3（主人连续拒绝） |
| `WATCHER_SECURITY_HOLD_MIN` | 30 | security 类熔断的最短锁定 |
| `WATCHER_EGRESS_ALLOWLIST` | `deploy/egress-proxy/rules.conf` 的镜像 | 出站点白名单（与 squid 规则同源） |
| `WATCHER_ALERT_DRY_RUN` | **1** | 为 1 时 watcher 自己不发包，只写队列与账本 |
| `WATCHER_ALERT_QUEUE_DIR` | `/state/alerts` | 送达腿的落点（空字符串关闭） |
| `WATCHER_ALERT_COOLDOWN_S` | 300 | 同键告警冷却 |
| `TG_BOT_TOKEN` / `OWNER_CHAT_ID(_REF)` | 未配 | 设计原路：token 缺席即惰性跳过 |
| `WATCHER_QQ_ALERT_URL` / `…_TOKEN_REF` / `…_USER` | 未配 / `1035376945` | HTTP OB11 `send_private_msg` 直发；当前栈无此端点，故默认不配 |
| `WATCHER_ADMIN_PORT` | 8186 | 仅容器内 `127.0.0.1`，给 Docker HEALTHCHECK 用 |

## 一轮在做什么

1. 探针 → 2. tail 审计（byte 游标，抗 rotation/半行/坏 JSON）→ 3. 规则判定 →
4. 恢复的 availability 原因清除 → 5. 旗标 open/close（原子写）→ 6. 告警派发（状态跃迁强制，
其余受冷却）→ 7. 审计流停增检测 → 8. 游标与心跳落盘。

`GET http://127.0.0.1:8186/healthz`（容器内）返回探针状态、熔断原因与告警计数；
游标陈旧或末轮异常时该端点回 503，从而被 Docker 标记 unhealthy。

## 布局

```
src/config.mjs   env → 配置（含 target 解析）
src/probe.mjs    tcpProbe / HealthState（trip-recover 迟滞）
src/tail.mjs     JsonlTailer 增量读
src/rules.mjs    DetectionEngine：E3 三信号 + C-32 + E7，按现有审计词表
src/breaker.mjs  旗标读写：own/foreign、security 锁定、availability 自动闭合
src/alert.mjs    渲染 + 通道计划 + 冷却 + 本地账本 + 队列文件
src/index.mjs    tick 循环 / healthz / 冷启动 seek-to-EOF
```
