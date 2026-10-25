# ops/watcher — E3 自动熔断 + F2 旁路告警 + E7 沉默告警（t11，DEV-19）

基线出处：`docs/validation/security-baseline.md` 的 **E2 / E3 / E7 / F2** 行与 **DEV-19 / DEV-05**。
消费侧契约（早已存在，本次未改语义）：`apps/gateway/src/index.mjs` 的 `isDegraded()` ——
旗标存在或读失败即 fail-closed，回固定文案 `DEGRADED_TEXT`，审计 `authz.decision result=denied
reason=degraded-flag`。DEV-19 缺的是**产生侧**：没有任何组件会写那个旗标，也没有任何组件会告警。

## 1. 它是什么

`ops/watcher` 是 net-ops 上的一个独立容器（静态 IP `172.28.3.60`，`profiles: [ops]`），
**零依赖**（Node 22 stdlib，无 npm 包）、**零 LLM token**（源码里 `fetch` 只用于探针与告警，
永远不指向模型端点）、**不发布任何宿主端口**（`healthz` 只 bind 容器内 `127.0.0.1:8186`，
仅供 Docker HEALTHCHECK；C1 断言因此仍然绿）。

每 `WATCHER_INTERVAL_S`（默认 10s）一轮：

| 步 | 动作 | 契约来源 |
|---|---|---|
| 1 | 探针 TCP/HTTP 连通性 → 必需目标连续 `WATCHER_FAIL_THRESHOLD`（3）次失败 → 熔断；连续 `WATCHER_CLOSE_THRESHOLD`（3）次成功 → 自动闭合 | E3「连续失败达阈值」 |
| 2 | 增量 tail `logs/*.jsonl`（byte-offset，抗 rotation，抗半行，抗坏 JSON） | E7 / TM-014 信号 8 |
| 3 | 规则引擎扫审计流 | E3 三信号 |
| 4 | 熔断位写入 `state/degraded`（原子 tmp+rename，内容 `{managed_by, opened_at, reasons[]}`） | E2 |
| 5 | 告警派发（旁路，不经 agent/LLM/工具门） | F2 |
| 6 | 审计流停增检测 + 心跳文件 `state/watcher.heartbeat` | E7 |

熔断原因分两类，语义不同：**security**（凭据探测 / 出站点漂移 / 审批连拒）带
`WATCHER_SECURITY_HOLD_MIN`（30 分钟）锁定期，探针恢复不会提前放行；**availability**
（依赖掉线）随探针转绿自动闭合。人工 `touch state/degraded`（空文件或非本组件 JSON）
被识别为 foreign flag：watcher 既不接管也不删除，只告警一次。

## 2. 检测规则（审计词表按现状，不臆造）

| 规则 | 触发（真实存在的事件形状） | 动作 |
|---|---|---|
| `E3-credential-probe` | `credential.resolve result=denied reason∈{unknown-token,no-token,ref-not-authorized}` 在 120s 窗口内 ≥5 次；含 `authz.decision stage=ob11-handshake/ob11-self-id reason=token-fingerprint-mismatch/self-id-mismatch` | 熔断（security）+ 告警；≥3 次先出 `-early` 预警 |
| `E3-egress-drift` | `llm.egress.target` 的主机名不在 `deploy/egress-proxy/rules.conf` 的 dstdomain 白名单内，连续 2 次 | 熔断（security）+ 告警 |
| `E3-approval-denials` | `approval.outcome stage=decided decision=denied` 连续 3 次（`expired/orphan` 不计：主人睡着不是攻击） | 熔断（security）+ 告警；连拒期间不复位计数，避免在两次拒绝之间漂回闭合 |
| `E3-health-probe` | 必需依赖探针连续失败 | 熔断（availability）+ 告警；转绿自动闭合 |
| `E6-protocol-down/restore` | `session.lifecycle stage=ob11-handshake event=disconnected/connected` 或 napcat 腿失联 | **只告警，不熔断**（C-32：QQ 掉线时降级等于把主人关在门外） |
| `E7-audit-silence` | 审计文件 `size+mtime` 连续 `WATCHER_STALE_LOG_MIN`（60 分钟）无增长 | 只告警（TM-014 信号 8：停增比坏内容更可疑，但不该由它触发熔断） |

## 3. F2 旁路告警 —— 设计与现状的**差异必须如实记录**

设计原文的 F2 是「TG 旁路告警，不经 agent」。**DEV-05 已判定 TG 不可达、QQ 是唯一信道**，
因此这里的实现是 **TG→QQ-only 的替换**，且比设计多一跳：

1. watcher 侧通道：`TG_BOT_TOKEN`+`OWNER_CHAT_ID`（原路，未挂 token 时惰性跳过）→
   `WATCHER_QQ_ALERT_URL`（HTTP OB11 `send_private_msg`，**当前栈里没有这个端点**，
   实测 `172.28.0.20:3000` 无监听，故默认不配）→ **本地账本 `state/alerts.jsonl` + 容器日志（永远开）**。
2. 送达腿（captain 裁决 2026-10-25 18:47）：watcher 把结构化告警文件写进
   `state/alerts/pending/*.json`，由 **ingress 侧的 `AlertRelay`**（`apps/gateway/src/alert-relay.mjs`）
   经既有 `send_private_msg` 回程投给主人。理由：只有 gateway 持有反向 WS 适配口，
   watcher 在 net-ops 上摸不到它。
   四条约束落地方式：
   * **固定模板**：报文 = `[watcher 告警] <type> · <service> · <state> · <utc> [· <target>]`，
     `type` 必须命中 9 项枚举（`ALERT_TYPES`），字段级 `/^[A-Za-z0-9._:@/+-]{1,48}$/` 校验；
     **队列里的自由正文永不进报文**（`summary` 只留在本地账本）。未知 type → 丢弃 + 审计。
   * **限速**：同 type 最小间隔 5 分钟（`ALERT_RELAY_COOLDOWN_MS`）+ 积压上限 20
     （`ALERT_RELAY_MAX_QUEUE`，超限丢最旧并计入 `dropped/` 与审计）。
   * **挂载最小化**：ingress 只多一个 `../state/alerts:/state/alerts` 子挂载（rw，用于搬文件），
     `/state` 父挂载仍是 `:ro`，网络与其它挂载未动。
   * **自身 fail-closed**：适配口未连上时文件留在 pending 重试，`maxAttempts` 次后进 `dropped/`
     并审计 —— 不因暂时投不出去就丢掉告警。

`WATCHER_ALERT_DRY_RUN` 默认 **1**：watcher 自己一个包都不发；队列文件仍会写（演练要能验证
送达腿），真实外发由 relay 的通路与 owner id 决定。

## 4. 受控故障演练（2026-10-25，容器 `dsh-big-fish-bot-*`）

被停的是 **memory**（不是 napcat，遵守硬纪律）。`WATCHER_FAIL/CLOSE_THRESHOLD=3`，`INTERVAL_S=10`。
演练期把 relay 的 owner 指到合成号 `900000199`，**主人没有收到任何消息**。

| 时刻（本地） | 事件 | 证据 |
|---|---|---|
| 18:55:22 | 演练前基线：`state/` 除 cursor/heartbeat 外为空；watcher `degraded:false ticks:2 produced:0`；审计共 439 行 | `wc -l logs/*.jsonl` |
| 18:55:35 | `docker stop …memory-1` | — |
| 18:55:57 | **熔断自动置位**（4 次连续失败，探针 detail=`timeout`） | `state/degraded` → `managed_by: ops/watcher`，`reasons[0].key = E3-health-probe:memory`，`fails: 4` |
| 18:56:17 | 消费侧确认降级；告警已产出并入队；relay 已认领并尝试投递 | ingress `healthz`：`degraded:true`、`alerts:{queued:3,retried:5}`；`state/alerts.jsonl` 3 行含 `E3-health-probe` / `E3-breaker-open`；`logs/ingress.jsonl` 9 行 `authz.decision stage=alert-relay reason=adapter-unavailable alertType=…`（合成号必然失败） |
| 18:56:51 | `docker start …memory-1` | — |
| 18:59:29 | **自动闭合**：`state/degraded` 消失，账本尾行 `E3-breaker-close info`；watcher `degraded:false reasons:[]` | `ls state/degraded` → No such file |
| 全程 | `assert-listeners.sh` 仍 `OK every stack port is loopback-only`；watcher 未发布任何宿主端口 | 脚本输出 |

演练暴露并已修掉的两处真实缺陷（保留记录，不粉饰）：

1. **开机噪声**：新起的 watcher 曾为每个健康目标发一条「已恢复」告警（依赖从未掉过也会发）。
   改为只有先前 trip 过的目标才产生 `recovered`。
2. **告警刷屏**：一次 60 秒故障产出了 8 条告警 —— `degrade` 类发现此前绕过冷却。
   改为只有 `E3-breaker-open/close`、`E2-foreign-flag` 这类**状态跃迁**强制发送，
   其余一律受 5 分钟冷却约束；同一次故障现在是「1 条原因 + 1 条 open + 1 条 close」。
3. **部署陷阱**：Docker 会自动以 root 创建缺失的 bind 源目录，导致 uid 1000 的 watcher
   写 `state/alerts` 得到 `EACCES`。上线前必须
   `mkdir -p state/alerts/{pending,sent,dropped} && chmod -R 0777 state/alerts`（已写入 runbook）。

## 5. 残余缺口（未蒙绿的部分）

* **真实主人投递只做过合成号验证**：`send_private_msg` 到 `900000199` 被 NapCat 拒绝，
  证明回程被正确调用、失败被计入重试；但「一条真告警落到主人 QQ」尚未执行 ——
  等 captain 与用户确认时间窗后放行（captain 约束 4），届时把 `OWNER_QQ` 换回 `1035376945`
  或显式 `WATCHER_ALERT_DRY_RUN=0 + ALERT_OWNER_QQ` 并只发一条演练告警。
* **E3 的凭据/出站点/审批三信号只有审计注入演练**（单测 + 一条端到端 `E3-egress-drift`），
  没有真实攻击流量；阈值是工程判断值（5 次/120s、2 次、3 连拒），需在真实运行中调参。
* **E7 的心跳告警只做到了「可被外部观察」**：`deploy/scripts/assert-watcher-alive.sh`
  需要在 NAS cron 或宿主监控里挂上才成立 —— watcher 不能给自己的死亡发通知。
* NapCat 侧无 OB11 HTTP 监听，故 `E6-protocol-down` 依赖 ingress 审计里的
  `session.lifecycle stage=ob11-handshake` 事件；若 ingress 本身死了，则由「审计流停增」
  与 `assert-watcher-alive` 两条兜住，而不是由 E6 兜住。
* `watcher` 仍在 `ops` profile 里，**默认不随主栈启动**：是否把它转成常驻服务由 captain 决定。

## 6. 运维速查

```bash
npm run test:watcher                     # ops/watcher 单测
OWNER_QQ=… docker compose -f deploy/compose.yaml --profile ops up -d --build watcher
docker exec dsh-big-fish-bot-watcher-1 node -e \
  "fetch('http://127.0.0.1:8186/healthz').then(r=>r.json()).then(j=>console.log(JSON.stringify(j,null,1)))"
cat state/alerts.jsonl                    # 告警账本
cat state/degraded                        # 当前熔断原因（存在即降级）
bash deploy/scripts/assert-watcher-alive.sh
```

配置项全表见 `ops/watcher/README.md`。
