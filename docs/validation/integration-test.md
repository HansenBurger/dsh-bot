# t9 集成测试：多轮记忆 + 故障恢复矩阵 + 延迟/审计基准

执行：integration-tester（dsh-bot-finish）· 2026-10-25 16:29–16:49 (+08:00)
分支 `feature/core-impl` @ HEAD `e583908` · compose project `dsh-big-fish-bot` · 模型 `deepseek-flash`
预算口径：**计费推理调用 ≤10**（一次 `llm.call` 且 `completionTokens>0` 记 1 次；401/502/网络失败不计费但如实列出）

**结论速览**

| 项 | 结果 |
| --- | --- |
| 多轮对话记忆一致性（跨 bot-core 重启） | **通过**（召回正确、未编造缺失项） |
| 故障恢复矩阵 5 腿 | **5/5 fail-closed，无静默降级**；全部恢复 healthy |
| 审计链逐跳对账 | **可全量对账**（gate/submit 跳由 isolated 链路探针补齐） |
| 延迟基准 | 计费请求 p50 2216ms / max 5064ms；上游 egress p50 133ms |
| 计费调用用量 | **7 / 10**（2103 completion tokens，8359 prompt tokens） |
| 新发现缺陷 | 8 条（T9-F1…F8），无 blocker；**未自行修改任何产品代码** |

---

## 1. 方法与注入边界

**零真实消息**：全程未向 NapCat/QQ 发出任何字节，未使用真号 principal 走 E2E live 注入。

- 主注入路径：宿主机以 `@dsh-bot/bot-hmac` 的同一套 `signedHeaders()` 纪律，对 `http://172.28.1.11:3005/submit` 直发签名帧（bot-core intake 在 net-ingress 上宿主机可达，已验证）。密钥取 `deploy/secrets/mem-hmac-secret`（ACL 可读，未入库）。
- 合成 principal：`onebot:900000101`（会话主体）、`900000102/104`（写入/拒绝样本）、`900000199`（越权对照）。均为 `9` 开头 9 位合成号，与真主人 `1035376945`、机器人自身 `207346792` 无碰撞。
- gate/submit 跳：**isolated 模式**——在宿主进程内 `createGateway()` 起真 gateway（临时端口、临时白名单、临时审计文件），`BOT_CORE_SUBMIT_URL` 指向真实 intake；"适配器"是本脚本自己的 WebSocket 客户端，出站回复终止在本地，不经 NapCat。
- 组件级失败探针：同进程内直接实例化真实 `BotCoreSubmit` / `MemoryClient` 类打向真实端点（零 token）。
- 副作用控制：写入行落在合成主体上；真主人数据全程未动（只读 ro 角色 + `sqlite3` 只读查询）。测试结束按正式 forget 路径清理。

**已知边界（诚实标注）**：直连 intake 的流量不产生 ingress 侧 `gate`/`submit` 审计行；该两跳由 §5 的 isolated 链路探针与真实历史流量（46 条 submit）对账补足。记忆服务无 JSONL 访问流（见 T9-F8），其账本唯一来源是 PG `companion.memory_access_log`。

临时脚本（未入库，附录 A 给出最小复现配方）：`/tmp/dshbot-t9/probe.mjs`、`isolated-probe.mjs`、`chain-probe.mjs`、`cleanup.mjs`、`snapshot.sh`。

---

## 2. 预算账本

| # | 时刻(UTC) | 轮次 | llm.call | prompt | completion | ms | 计费 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 08:30:28 | 会话 A1 提议写入 | call=4 tool_calls | 1054 | 503 | 3114 | ✅ |
| 2 | 08:32:38 | 会话 B 召回第 1 轮 | call=1 tool_calls | 1044 | 114 | 1189 | ✅ |
| 3 | 08:32:40 | 会话 B 召回第 2 轮 | call=2 tool_calls | 1273 | 125 | 1183 | ✅ |
| 4 | 08:32:42 | 会话 B 召回第 3 轮 | call=3 stop | 1424 | 200 | 2216 | ✅ |
| 5 | 08:34:48 | 记忆故障样本提议写入 | call=1 tool_calls | 1050 | 736 | 5064 | ✅ |
| 6 | 08:38:59 | isolated 全链路探针轮 | call=5 stop | 1470 | 173 | 2347 | ✅ |
| 7 | 08:45:07 | 拒绝路径提议写入 | call=1 tool_calls | 1044 | 252 | 1742 | ✅ |
| — | 08:30:37 / 08:35:07 / 08:45:08 ×2 | 同意 / 拒绝 / 孤儿同意 | `calls:0` | — | — | 47–8052 | ⬜ 零 token |
| — | 08:40:34 | broker 停机探针 | `result=error reason=egress-failed` | — | — | 10493 | ⬜ 未触达上游 |
| — | 08:43:47 | proxy 停机探针 | `result=error reason=upstream-502` | — | — | 5009 | ⬜ 未触达上游 |

**合计 7/10 计费调用**（prompt 8359 / completion 2103 tokens）。剩余 3 次预算未动用（未做重复召回与多事实补记的正向复验，见 §7）。

零 token 的三个关键路径（预算能守住的原因）：
1. 审批落地走 `ApprovalQueue.resolvePending()`，**不再调用模型**（`agent.turn result=approval calls:0`，`logs/agent.jsonl:99`）；同意一次 85ms 返回。
2. 上游失败在 broker/proxy 侧就被挡住，`llm.call result=error` 不带 token 字段。
3. 检索/删除/对账全部用签名 REST + ro SQL，不进对话回路。

---

## 3. 多轮对话记忆一致性

### 3.1 会话 A（落库前，进程内历史）

| 轮 | 输入（合成 principal `onebot:900000101`） | 回复 | 审计 |
| --- | --- | --- | --- |
| A1 | "请记住：我的集成测试代号是 B-77，我喜欢吃蓝莓酸奶。这条是自动化集成测试写入。" | `这条内容会进入长期记忆，请确认…要记的是：主人的集成测试代号是 B-77…` | `llm.call`→`approval.outcome stage=requested approvalId=appr-1d08d069b1442b32`→`agent.turn calls=1 pending=true`（`logs/agent.jsonl:93-96`） |
| A2 | "同意" | `已记住。` | `approval.outcome stage=decided decision=approved waitedMs=8944`→`stage=applied result=allowed memoryId=2dce8bbd… deduped=false`→`agent.turn result=approval calls=0 applied=true`（`logs/agent.jsonl:97-100`） |

落库证据（PG 权威侧，ro 角色）：

```
subject_key           attr_key                   value_plain                                                     scope  visibility
onebot:dm:900000101   test.integration_codename  主人的集成测试代号是 B-77（主人明确要求记住，标注为自动化集成测试写入）。  dm     private
```

访问账本：`log_id=116  operation=write  result=allowed  approved=t  object_ref=2dce8bbd-dc3e-4397-8916-f900f58a786c  user_id=900000101`

L1 侧证据（memory 容器 `sqlite3 /var/lib/dshbot/memory/l1.db`）：

```
memory_cache: 2dce8bbd-dc3e-4397-8916-f900f58a786c | kind=profile | class=profile | generation=1 | hits=0
```

→ **双写成立**（PG 行 + L1 `memory_cache` 行同 id）。

### 3.2 中间动作：重启 bot-core 清进程内历史

见 §4 矩阵第 1 腿。重启后 `/healthz`：`stats.received=0 llmCalls=0 recentTurns=[]` → **进程内 10 轮历史确实清空**，会话 B 只能靠持久层召回。

### 3.3 会话 B（重启后，跨会话召回）

| 轮 | 输入 | 回复（原文节选） | 证据 |
| --- | --- | --- | --- |
| B1 | "对了，我之前让你记住的集成测试代号是什么？还有我喜欢吃什么？" | `代号我查到是 **B-77**。不过得提醒一句：这条记忆被标成了"自动化集成测试写入"……至于你爱吃啥——我这边真的没存到任何相关记录，搜饮食、口味、食物都是空的。是我漏记了，还是你根本没跟我说过？` | `logs/agent.jsonl:101-103`（3 次 `llm.call`，`agent.turn calls=3`）；账本 `log_id 118-121`：`search result=allowed rows_returned=1`（命中 B-77）+ 3 次 `rows_returned=0`（饮食检索确实为空）；`latency_ms=15/4/2/3` |

判定：
- **跨会话/跨进程持久召回 ✅**：清空历史后仍取回正确值，且取回内容与 PG 行逐字一致。
- **不编造 ✅**：对确实未落库的食物偏好，明确回答"没存到"并说明搜索维度，未虚构。
- 副作用为零：会话 B 纯读，`recentTurns` 未污染真主人（R2/N1 后 owner 旁路与调用者身份绑定，见 §6）。
- ⚠️ 但"没存到"本身是**写入侧缺陷**：A1 一句话含两个事实，只落了一条 → 见 **T9-F1**。

---

## 4. 故障恢复矩阵（逐腿 stop → 验证 fail-closed → start → 验证归队）

约定：每腿只停一个容器；`docker stop -t ≤10`（快停）、`docker start` 后轮询 healthcheck；napcat 按要求**未参与**。全程无连环重启。

| 腿 | 停机验证（fail-closed 证据） | 静默降级检查 | 恢复验证 | 停机时长 |
| --- | --- | --- | --- | --- |
| **bot-core** | ① 真实 `BotCoreSubmit` 打向停机 intake → `{ok:false,reason:"agent-unreachable"}`，临时审计落 `sandbox.denied stage=submit result=error message="This operation was aborted"`（isolated 探针，零 token）② 宿主直连 intake **connect 超时**（不是快速拒绝，见 T9-F4）③ `/healthz` 不可达 | gateway 侧非空回复 `AGENT_DOWN_TEXT`（代码路径 `apps/gateway/src/index.mjs:145`）；无假 200 | 16:32:16 start → **16:32:24 healthy（+8s）**；`llm.ready` 后 `agent.jsonl` 追加连续（行 92→100 未断裂）；`stats` 归零＝历史清空（会话 B 前置条件） | 33s |
| **memory** | ① 停机期间对**已挂起的审批**发"同意"（零 token）→ 回复 `写入失败了：记忆服务不可达。`；`logs/agent.jsonl:111-114`：`sandbox.denied stage=memory-client path=/v1/memories result=error`→`approval.outcome stage=applied result=error reason=记忆服务不可达`→`agent.turn applied=false calls=0` ② 真实 `MemoryClient` 探针 → `code=MEMORY_UNREACHABLE` + `sandbox.denied stage=memory-client`（无空列表伪装） | **PG 无残留**：`subject_key='onebot:dm:900000102'` 的 profile/preference 行数=0（未写半成品）；无 200 空结果冒充"查不到" | 16:35:29 start → **16:35:38 healthy（+9s）**；`/8190/healthz` `pg.up=true sqlite.up=true integrity=ok`；账本继续编号（122→123 无空洞） | 40s |
| **broker** | ① bot-core 内 `GET /v1/llm/models`（带 enrollment token）→ 不可达 ② 合成号对话探针 → 回复 `我现在连不上模型，稍后再试。`；`logs/agent.jsonl:118-119`：`llm.call result=error reason=egress-failed ms=10493 message="fetch failed"`→`agent.turn result=error calls=1` | 零 token（上游从未触达）；`llmFailureMessage(0)` 专属文案，不落"空回复"；intake 仍 200 但带错误文案（可见失败） | 16:40:55 start → **16:41:03 healthy（+8s）**；`GET /v1/llm/models` 恢复 200 且模型清单正确；后续 08:45:07 真实计费调用成功（闭环复验） | 40s |
| **proxy(squid)** | ① `GET /v1/llm/models` → `http=502 {"error":{"code":"UPSTREAM_UNREACHABLE","message":"模型上游不可达"}}` ② 对话探针 → 回复 `模型那头出错了，稍后再试。`；`logs/broker.jsonl:87-88`：`llm.egress result=error reason=proxy-unreachable message="proxy CONNECT timed out (172.28.3.40:3128)" ms=5002/5006`；`logs/agent.jsonl:121`：`llm.call result=error reason=upstream-502 ms=5009` | 零 token；CONNECT 超时被 5s 上界挡住（无挂死）；无回退直连（S1/P1–P3 断言在恢复后仍全绿，见下） | ≈16:44:05 start → Up（squid 无 healthcheck，`docker ps` 口径）；`scripts/assert-egress-allowlist.sh` → **4 pass / 0 fail**（S1 顺序、P1 放行 200、P2 域名外 403、P3 RFC1918 侧洞 403） | ≈33s |
| **ingress** | ① 宿主 `127.0.0.1:3001` 监听消失（`ss` 计数 0、curl 连接失败）② NapCat 容器内 `curl http://172.28.1.10:3001/` → `000`（反向 WS 断） ③ bot-core `/healthz` 仍 200（下游无级联） | 无假成功；`ingress.jsonl` 停机期间不增长（16:48:15→16:48:36 停在 213 行），恢复后继续追加 | 16:44:28 start → **16:44:36 healthy（+8s）**；NapCat 自动重连 `logs/ingress.jsonl:213 08:44:47 session.lifecycle ob11-handshake allowed connected socketId=172.28.0.20:…`（+19s）；`/8181/healthz` `adapters.ob11.connections[0].selfId=207346792 readyState=1`；第二轮 16:48:15 停→16:48:36 healthy→16:48:44 重连（行 214）。两轮一致：healthy 归队 +8s，NapCat 自动重连 +11~19s | 29s（第二轮逐秒实测） |

矩阵总判定：**5/5 通过**。每腿失败都：请求可见报错 + 专属错误文案 + 审计落盘 + 零 token 泄漏 + 无半成品写入；每腿恢复都：healthcheck 归队 ≤9s、审计文件追加连续、下游功能复验成功。

停机期间的真实流量：全窗口 `ingress.jsonl` 无新增 `gate/submit` 行，真主人未在这 20 分钟内发消息 → **未对真实用户产生可见失败**（这是运气，不是设计；见 T9-F4 关于用户可见等待时长的建议）。

---

## 5. 审计链逐跳对账

测试窗口 `ts ≥ 1792917000000`（16:30–16:49）逐跳计数：

| 跳 | 来源 | 事件/行 | 计数 | 对账 |
| --- | --- | --- | --- | --- |
| gate | `logs/ingress.jsonl` + isolated 链路探针 | `authz.decision stage=gate result=allowed role=owner` | 直连注入 0 / isolated 1 | isolated 探针补上该跳（见下） |
| SUB | 同上 / `BotCoreSubmit` | `authz.decision stage=submit result=allowed status=200 ms=2368` | isolated 1；真实历史 46 | ✅ |
| intake | `logs/agent.jsonl` | `authz.decision stage=intake result=allowed role=owner` | **11** | = `agent.turn` 11 ✅（每个进入的帧一跳，无丢失、无重复） |
| 对话轮 | `logs/agent.jsonl` | `agent.turn` | **11**（allowed 5 / approval 4 / error 2） | 与注入的 11 条帧一一对应 ✅ |
| 模型调用 | `logs/agent.jsonl` | `llm.call` | **9**（7 计费 + 2 error） | = 会话 A1(1)+B(3)+故障样本(1)+链路探针(1)+拒绝样本(1)=7 ✅ |
| 出口隧道 | `logs/broker.jsonl` | `llm.egress` | **10** = 8 次 status=200（7 次计费 chat/completions + 1 次零 token 的 `/v1/llm/models` 健康探测）+ 2 次 `result=error reason=proxy-unreachable` | 逐 ts 对齐：`1792917822613`(models 探测 err) 与 `1792917827715`(chat err)；后者与 `logs/agent.jsonl:121 llm.call reason=upstream-502` **同毫秒**咬合 ✅；9 次 `llm.call` ↔ 8 条成功/失败 egress + 1 条 broker 停机期缺失（见下行） |
| 出口隧道（broker 停机） | — | 无 `llm.egress` 行 | 0 | **预期不对称**：broker 自身停机时不存在它的账本，失败只在消费方留痕（`llm.call reason=egress-failed ms=10493`）。对账时需按"停机腿只看消费方"处理，不算断链 |
| memory.write | PG `memory_access_log` | `log_id 116 write allowed approved=t object_ref=2dce8bbd…` | 1 | ↔ `agent.jsonl:98 approval.outcome applied memoryId=2dce8bbd…`（同 id 双向可追）✅ |
| memory.search | 同上 | `log_id 117-122 search allowed` | 6 | 其中 118-121 = 会话 B 的 4 次工具检索（1 命中 + 3 空），与 `agent.turn calls=3/toolCalls=2,2,0` 一致 ✅ |
| memory.delete | 同上 | `log_id 123 delete allowed approved=t user_id=900000101` | 1 | ↔ `companion.memory_tombstone` 6→7、L1 `memory_cache` 该行清除 ✅ |
| memory JSONL | `memory.jsonl` | 仅 1 行 `authz.decision stage=memory-hmac denied UNAUTHENTICATED` | 1 | **访问账本不落 JSONL** → T9-F8 |

**无断链**：所有写/删的 `memoryId`、`approvalId`、`log_id`、审计行四处互相咬合；失败路径也有对应行（`sandbox.denied stage=memory-client`、`llm.egress reason=proxy-unreachable`、`llm.call reason=egress-failed`）。

**对账摩擦点（如实记录）**：
- 链上**无贯穿关联 id**（无 traceId/requestId），跨服务只能按 时间窗 + `clientId` + `chatId` + 计数 对齐；`approvalId`（`appr-…`）是 bot-core 内单例，broker 侧 `llm.egress` 完全不带会话身份。
- `agent.turn` **无 `ms` 字段** → 单轮端到端耗时无法从审计统计（见 T9-F3）。
- `approval.outcome` 的 `chatKey` 被整体脱敏成 `[REDACTED]` → 审批事件无法从审计按会话归因（见 T9-F2）。

### isolated 全链路探针（零真实消息，1 计费调用）

宿主进程内起真实 gateway → 真 intake，签名密钥取真 `mem-hmac-secret`，白名单为临时目录里的合成条目：

```
session.lifecycle stage=ob11-handshake result=allowed            ← 接入腿
authz.decision    stage=gate    result=allowed role=owner         ← A1 决策腿
authz.decision    stage=submit  result=allowed status=200 ms=2368 ← SUB 腿（真 HMAC + 防重放）
```
出站 `send_private_msg` **被本脚本自己的 socket 捕获**（记录后回 `retcode:0`），未流向 NapCat；网关临时审计文件随临时目录销毁，`logs/ingress.jsonl` 未被写入合成流量（保持生产账本干净）。

---

## 6. 身份边界复验（只读，零 token）

| 探针 | 期望 | 实测 |
| --- | --- | --- |
| 合成 owner `900000199` 检索 "香菜" | 不得看到真主人的行 | `log_id 117/122/125 rows_returned=0` ✅ |
| 合成 owner `900000101` 检索自身 | 应命中自己的行 | `log_id 118 rows_returned=1` ✅ |
| SQL 谓词复刻 repository 的 owner 腿（caller=真主人） | 合成行不得混入 | 合成行 `subject_key=onebot:dm:900000101` ≠ 真主人主体 → 不返回 ✅ |
| 真主人现有行 | 未被本次测试污染 | `companion.user_preference` 仍仅 `主人喜欢香菜。`（scope_peer=`onebot:1035376945`）1 行，未增未改 ✅ |

R2/N1 修复在真机组合（llm+memory+broker 全活）下成立：owner 旁路绑定调用者自身主体，跨主体/跨通道不再泄漏。

---

## 7. 缺陷与观察清单（只报不修）

| id | 严重度 | 现象与证据 | 影响 | 建议（派单参考，非本次改动） |
| --- | --- | --- | --- | --- |
| **T9-F1** | medium（功能） | **多事实消息只落一条记忆**：A1 原文同时含"代号 B-77"和"喜欢吃蓝莓酸奶"，`approval.outcome requested` 只提出代号一条（`logs/agent.jsonl:94`），落库仅 1 行 profile；会话 B 如实回答食物"没存到"（`log_id 119-121 rows_returned=0`） | 用户以为两句都记住了，实际静默丢半句；召回侧诚实但体验断裂 | 提示词/工具约束：一次消息内多个可记事实应逐条 `memory_write`（或在审批文案里显式说明"本条只提取了 X，其余未记"）。属 `apps/bot-core/src/companion-loop.mjs` PERSONA/MEMORY_HANDLING_PROMPT 范畴 |
| **T9-F2** | low（可观测性） | `approval.outcome` 的 `chatKey` 恒为 `[REDACTED]`（`logs/agent.jsonl:95/98/110/112`）。脱敏规则按字段名匹配 `/…|key$/i`，`chatKey` 被误命中：`packages/bot-audit/src/index.mjs:182` | 事后无法把审批事件归因到具体会话（只能靠相邻 `agent.turn` 的 `chatId` 猜时间序） | 白名单化"确属凭据"的字段名，或把 `chatKey` 改名为 `chatBinding`/输出散列短指纹 |
| **T9-F3** | low（可观测性） | `agent.turn` 无耗时字段（全库 0 行含 `ms`）；单轮延迟只能靠探针侧计时或跨行相减 | 无法用审计做 p50/p95 报表，本轮延迟基准部分是客户端口径 | `agent.turn` 增加 `ms`（入站到出回复），并加 `turnId` 关联 |
| **T9-F4** | medium（可用性） | **依赖失联是"超时"而不是"快速拒绝"**：容器停机后桥接 IP 无 RST → ① gateway→bot-core 探针 `AbortError`（本次给 8s 超时；生产默认 20s 会等满）② bot-core→broker `ms=10493` 才失败（`AbortSignal.timeout(60000)` 上限）③ memory 腿 `ms≈8000`。叠加 `MAX_CONCURRENT_RUNS=2`（`apps/bot-core/src/intake.mjs:48,149` + `deploy/compose.yaml:109`，**静态确认，未做饱和实验**）：**2 个卡住的请求即可占满 intake**，后续消息撞 429 `AGENT_BUSY` 而不是错误文案 | 单腿故障被放大成"整个伴侣无响应"，且用户等待 8–20s | 缩短出站超时（建议 submit 3s / llm 15s）+ 连续失败后短熔断快速失败；考虑健康探测驱动 `/healthz degraded` |
| **T9-F5** | low（措辞/归因） | proxy 故障（我方出口）经 broker 502 映射为面向用户的"模型那头出错了，稍后再试。"（`llmFailureMessage(502)`），而真因是 `reason=proxy-unreachable` | 用户/运维归因偏差；排障需回到 broker 审计才能分清 | 502/`UPSTREAM_UNREACHABLE` 单独文案（"我这边的出口不通"），并在文案里区分"上游拒了"vs"连不上上游" |
| **T9-F6** | low（数据卫生） | 合成主体行残留：`companion.subject` 多出一行 `onebot:dm:900000101`（其 profile/preference 已 0 行）；`memory_tombstone` 由 6→7；L1 `memory_cache` 只剩真主人的 `香菜` 行 | 无泄漏、无召回影响，纯计数噪声 | 若在意，可加"空主体回收"作业；或允许 `forget-all` 顺带删除主体壳 |
| **T9-F7** | info | 审批一次通过即零 token（`calls:0`，85ms/49ms），孤儿同意返回"现在没有等你确认的操作，所以什么都没做。"并落 `approval.outcome stage=orphan`；拒绝一次生效且不留行（`900000104` 行数 0） | 预算友好、语义正确 | 无需改动（本轮"拒绝/同意/孤儿"三态首次拿到**真机**证据，补齐 runbook §3.6 的缺口） |
| **T9-F8** | medium（审计链） | 记忆子系统**没有 JSONL 访问流**：`memory.jsonl` 全文仅 1 行（一次 HMAC 拒绝），13 条访问账本只在 PG `companion.memory_access_log`（`logAccess` 只做 INSERT，`repository.mjs:1058`）。而 `packages/bot-audit/src/index.mjs` 头注释宣称 `memory.access` 是"第 9 个强制事件类，JSONL 是真相源、PG 是查询视图（F3）" | 宣称与实际相反：**PG 不可用即访问账本同时丢失**，且 remote collector 采不到记忆腿；文档/口径风险 | 二选一：① `logAccess` 同时 emit `memory.access` 到 JSONL；② 改文档/注释，明确 PG 为唯一权威账本并把备份纳入轮换 |

其余观察（不构成缺陷，供 review 参考）：
- 会话 B 用了满额 3 轮工具调用（`maxRounds=3`）才收敛；若模型多问一次就会静默截断在工具轮——建议关注 `finishReason` 非 `stop` 收尾的比例（本窗口 7/7 正常收尾）。
- 记忆检索 `latency_ms` 2–15ms，PG `latencyMs=0–1`；不是延迟瓶颈，瓶颈全在模型往返（4 次 `llm.call` 约 6.9s，占端到端 >95%）。
- compose 侧 `restart=unless-stopped` 六容器全程未变；本轮手工 `docker stop/start` 不重置策略，daemon 重启后仍会自恢复。

---

## 8. 延迟基准（零额外计费，口径混合）

| 指标 | n | p50 | max | 口径 |
| --- | --- | --- | --- | --- |
| `llm.call`（计费成功轮） | 7 | **2216ms** | **5064ms** | bot-core 审计 `ms` |
| `llm.egress` status=200 | 8 | 133ms | 436ms | broker 审计 `ms`（含 squid CONNECT+TLS） |
| `llm.egress` result=error | 2 | 5002ms | 5006ms | 同上，proxy CONNECT 上界 5s |
| `llm.call` result=error | 2 | 5009ms | 10493ms | bot-core 审计（broker 停机腿走满 10.5s） |
| intake 端到端（探针侧，含工具轮+回复组装） | 11 | 3169ms | 10549ms | 探针计时（最慢 = broker 停机；最快 47ms = 孤儿同意） |
| 审批落地（零 token） | 4 | 49ms | 8052ms | 纯健康态 47–85ms；memory 停机腿 8052ms（=客户端超时上界） |
| 真实历史流量 `submit` 跳 | 46 | 3ms | 3040ms | `logs/ingress.jsonl`（t2 期真主人流量，非本轮产生） |
| memory REST 检索 | 6 | 15ms | 74ms | 签名探针 + PG `latency_ms` |

要点：**模型往返是唯一致命项**（单轮最多 5.06s，多轮召回 3 跳累计 ≈4.7s）；网关/记忆/PG 都在毫秒级；失败路径的可感知等待由"上游超时上界"决定（proxy 5s、memory 8s、broker 10.5s、gateway→bot-core 生产 20s），见 T9-F4。

---

## 9. 清理与终态

- 合成写入行已按**正式 owner forget 路径**清理：`POST /v1/memories/2dce8bbd…/forget?dryRun=false` + 绑定 `X-Bot-Approval` 的一次性令牌 → `deletedCount=1`，`log_id=123 delete allowed approved=t`，`companion.memory_tombstone` 6→7，L1 `memory_cache` 对应行消失，`companion.user_profile` 计数归 0。返回体含 `backupNote="备份中仍含已删数据直至下次轮换（§8.6 / R-6）"`（符合预期，未越权处理）。
- 未清理（有意保留）：`companion.subject` 的合成主体壳（T9-F6）。真主人数据 0 改动。
- 终态：6 容器在位，bot-core/broker/memory/ingress 全 `healthy`，proxy 在位，napcat 未动且反向 WS 重连正常；停机期间产生的错误审计行留存（不删，是证据）。
- 未动产品代码；本文件为唯一新增文件，独立 commit。

## 附录 A：最小复现配方

```bash
# 1) 签名帧直连 intake（合成 principal，零真实消息）
node - <<'JS'
import { readFileSync } from 'node:fs';
const R = '/home/burger/DSH-Bot';
const { signedHeaders } = await import(`${R}/packages/bot-hmac/src/index.mjs`);
const { buildNormalized } = await import(`${R}/packages/bot-normalize/src/index.mjs`);
const hmac = readFileSync(`${R}/deploy/secrets/mem-hmac-secret`, 'utf8').trim();
const P = { channel: 'onebot', chatId: '900000101', userId: '900000101', role: 'owner' };
const now = Date.now();
const message = buildNormalized({ channel: 'onebot', peer: { kind: 'dm', chatId: P.chatId },
  sender: { userId: P.userId }, text: '我的测试代号是什么？',
  rawRef: { messageId: `t9-${now}`, seq: 1 }, receivedAt: now });
const body = JSON.stringify({ v: 1, message, decision: { role: P.role, gatedAt: now } });
const res = await fetch('http://172.28.1.11:3005/submit', { method: 'POST',
  headers: { 'content-type': 'application/json', ...signedHeaders(hmac, { method: 'POST', path: '/submit', body, ...P }) },
  body, signal: AbortSignal.timeout(90000) });
console.log(res.status, await res.text());
JS

# 2) PG 权威侧账本
export PGPASSWORD="$(cat deploy/secrets/mem-pg-ro-password)"
psql -h /var/run/postgresql -U dsh_companion_ro -d dsh_companion -X -q -c \
  "select log_id,operation,result,approved,user_id,rows_returned from companion.memory_access_log order by log_id desc limit 20"

# 3) L1 侧
docker exec dsh-big-fish-bot-memory-1 sqlite3 /var/lib/dshbot/memory/l1.db \
  "select memory_id,kind,class,substr(body,1,40),hits from memory_cache;"

# 4) 逐腿故障矩阵（一次一腿）
docker stop -t 10 dsh-big-fish-bot-bot-core-1 && docker start dsh-big-fish-bot-bot-core-1
docker stop -t 10 dsh-big-fish-bot-memory-1  && docker start dsh-big-fish-bot-memory-1
docker stop -t 10 dsh-big-fish-bot-broker-1  && docker start dsh-big-fish-bot-broker-1
docker stop -t  5 dsh-big-fish-bot-proxy-1   && docker start dsh-big-fish-bot-proxy-1   && bash scripts/assert-egress-allowlist.sh
docker stop -t  5 dsh-big-fish-bot-ingress-1 && docker start dsh-big-fish-bot-ingress-1   # 之后确认 napcat 自动重连

# 5) 清理
docker exec dsh-big-fish-bot-bot-core-1 curl -sS http://127.0.0.1:8185/healthz   # pendingApprovals 应为 0
```
