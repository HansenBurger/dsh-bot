# t3 · 约束追溯表（Constraints Traceability）

> 用途：把 captain 转达的**用户已确认决策**与 t1/t2 硬约束逐条映射到 t3 设计落点，供 t4 验收与后续评审直接引用。
> 列说明：**落点** = 具体机制；**文件:节** = 可查阅位置；**状态** = `已设计` / `部分` / `移交 t4 验证`；**验收动作** = t4 应执行的可观察检查。

图例：U1–U3 = 用户本轮明确确认的三项安全决策；C-xx = 编号化约束条目。

---

## A. 用户确认的三项安全决策（最高优先级）

| ID | 约束原文（摘要） | 落点 | 文件:节 | 状态 | 验收动作（t4） |
|---|---|---|---|---|---|
| **C-01** | 仅白名单 `user_id` 可触发 Agent 响应 | 独立 ingress 容器内 `decide()` 默认拒绝；`policy.roleOf()` 未命中即 `public` → 不进 agent | arch §5.3.1、deploy §3(ingress) | 已设计 | 非白名单小号发消息 → 无 LLM 调用记录、无工具日志（对应基线 A1） |
| **C-02** | 授权判决必须在 LLM 调用之前完成 | 判决位于 L2 ingress，早于 `bot-core.route()`；架构图上表现为 `AZR --> deny fixed reply --> SAN` 旁路，不经 `LOOP` | arch §5.2 步骤 6、§7 图 | 已设计 | 审计时序比对：`authz.decision` 时间戳早于任何 `tool.call`/LLM 请求 |
| **C-03** | 只信结构化 `(channel, chat_id, user_id)`，禁止比对显示名 | `PeerKey`/`SenderKey` 仅含 id；`NormalizedMessage.sender.displayName` 标注「仅展示，永不参与判决」；OB11 的 `nickname` 在归一阶段**主动丢弃** | arch §5.3.1、§9.1 | 已设计 | `grep -rn "nickname\|card\|sender_name" apps/gateway/src/authz.ts` 为空（基线 A2） |
| **C-04** | 非白名单消息直接丢弃或回复固定提示，不得送入 LLM | `denyFixedReply()` + 可选固定文案回帖；`decision` 短路返回，不产生 Session 投递 | arch §5.2 步骤 6 | 已设计 | 同 C-01；另检查被拒消息仍写入审计（F1 第 1 类） |
| **C-05** | 身份判决不可被模型记忆绕过（本设计补强项） | `appendPluginRecord` 持久化 session↔(channel,chat_id) 绑定 + `ctx.tools.guard()` 校验 `exec.agent.id` 与最近一次放行的 sender role | arch §5.3.5 | 已设计 | 注入用例：诱导 bot「以 owner 身份执行 X」→ guard deny 且有审计 |
| **C-06** | `workspaceRoot` 限定在一次性容器卷内 | profile `sandbox-policy.workspaceRoot: /rw/work`；compose `work-rw` 卷 driver_opts `type: tmpfs, size=512M` | deploy §3、§4 | 已设计 | `docker inspect` 确认 `/rw/work` 来源为 tmpfs 卷；重启后目录为空 |
| **C-07** | 任务结束即销毁工作区 | tmpfs 卷随容器停止即消失；`dsh` 服务 `read_only: true` + `/run` tmpfs；每周重建镜像层（B7）叠加 | deploy §3（`volumes:` 段） | 已设计 | 停服→起服，`/rw/work/*` 不存在；session log 仍在 `data/dsh-home`（区分：历史持久、工作产物不持久） |
| **C-08** | **严禁挂载任何 NAS 共享目录** | dsh 服务 volumes 清单中不含 `/volume*`、DSM 共享路径或 NFS 挂载；文件内以显式注释声明该禁令 | deploy §3（⚠ 注释行） | 已设计 | `docker inspect --format '{{json .Mounts}}' dsh` 结果逐项比对期望集合，出现宿主共享路径即 No-Go |
| **C-09** | 未来若有共享目录需求须走独立审批流程重新评估 | 本文档记录为变更门槛：需新增威胁建模条目 + 用户批准后方可修改 compose | deploy §3、arch §8 残留风险 | 已设计（流程性约束） | 评审时检查 PR 是否附带新的威胁条目与用户确认记录 |
| **C-10** | 所有高危动作必须 `approval: ask` 人工确认 | `permission-presets.presets.bot-readonly-ask {sandbox: read-only, approval: ask}` + `defaultPreset` 指向它；表中**不存在** `danger-full-access` → 用户无法选择 | deploy §4、arch §5.6 | 已设计 | 尝试切到 full access：预设目录中无该项；写类工具触发审批而非静默失败 |
| **C-11** | 明确哪些操作类别触发审批 | 七类分类表：执行命令 / 写入文件 / 访问外部 API / 修改配置 / 破坏性不可逆 / 特权控制 / 只读问答，各自给出机制与默认值；配置固化在 `config/approval-categories.yml` | arch §5.6 表 | 已设计 | 每类各造一条用例，观察 `approval/asked` 是否按预期出现或缺席 |
| **C-12** | 审批通道优先 TG 私聊（跨通道二次确认） | answerer 并行发起，优先级 `[telegram, gui, onebot]`，first-answer-wins；QQ 管理类意图强制走 TG 确认 | arch §5.3.1（A3 分支）、§5.6 | 已设计 | QQ 群发「改配置」→ 无 TG 确认则不执行（基线 A3） |
| **C-13** | 超时回退策略：建议 5 min 无响应自动拒绝 | `approvalTimeoutMs: 300000` → 超时返回封闭词汇表中的 `'rejected'`；通道全不可用 → `'unavailable'`（fail closed，包文档语义） | arch §5.6、deploy §4 | 已设计 | 触发审批后静默 5 min → outcome=`rejected`，turn 继续且工具未执行 |
| **C-14** | QQ 群内审批仅作备用 | P3 仅在 P1/P2 均不可达且 sender 为 `trusted` 时启用，并要求输入一次性 nonce | arch §5.6 | 已设计 | 关闭 TG 通道可达性 → 群内审批可用且需 nonce；owner 判定不因群内审批而提升 |
| **C-15** | 审批是一次性的、不做长期豁免 | 只用 `allowed-once`；无缓存豁免表；每次审批都发新请求 | arch §5.6 | 已设计 | 连续两次同类调用 → 两次独立审批请求 |

## B. 沿用的既有硬约束

| ID | 约束 | 落点 | 文件:节 | 状态 | 验收动作 |
|---|---|---|---|---|---|
| **C-16** | LLBot WebUI 3080 与 DSH GUI 3080 冲突必须解决 | 端口分配表：DSH GUI 保 3080；NapCat WebUI `127.0.0.1:3081`（容器内 6099）；LLBot WebUI `127.0.0.1:3082`（容器内 3080）。处置原则=**改高位映射，不放宽绑址** | deploy §2 表、§3 | 已设计 | `assert-listeners.sh` 断言期望集；从另一台机器扫描 3081/3082/3001 → 全部 closed（基线 C3） |
| **C-17** | NapCat 与 DSH 分容器分 uid，理想分 VM | `napcat user: "2100:2100"` vs `dsh user: "10001:10001"`；不同网络区（net-protocol vs net-agent），中间必经 ingress；S3 形态给出双 VM 升级做法 | deploy §3、§7 | 已设计（S2′ 起步，S3 为升级路径） | `docker exec` 两侧 `id -u` 不同（基线 B5）；VM 形态下核对 VM-A 无密钥文件 |
| **C-18** | LLM key 走 sidecar broker，agent 永不见明文 | broker 容器持 `/run/secrets/llm-key:ro`；DSH 侧 `baseURL → http://broker`、`apiKeyEnv` 值为 opaque ref；egress-proxy `request_header authorization deny all` 防绕过 | deploy §3、§5；arch D-10、§3 L5 | 已设计（含 §5 诚实缺口标注） | `docker exec dsh env \| grep -i key` 只见 ref；让 bot `printenv`/读 `.credentials.yaml` → 无明文（D1/D2） |
| **C-19** | 告警 watcher 与 `!halt` kill switch 独立于 agent 进程 | `ops-watcher` 独立容器（net-ops），只读消费 `./logs`、写 `./state/degraded`；ingress 每消息前读熔断位并短路；`!halt` 由 gateway 解析，不经 LLM | deploy §3（watcher/ingress）、arch §5.2 步骤 8、§7 图 `KIL -.-> HAL` | 已设计 | 下达「不要通知主人」→ 告警仍送达（F2）；`!halt` 后全通道只回固定文案（E2） |
| **C-20** | 统一接入层锁定 OneBot 11 反向 WebSocket，端口绑 `127.0.0.1` | D-03 + `MODE: reverse_ws` + `ONEBOT_URL` 指向 ingress；监听 `127.0.0.1:3001`；握手校验 token 指纹 + self_id | deploy §2/§3；arch D-03、§5.2 步骤 2 | 已设计 | `wscat` 直连不带 token → 立即断开 + 告警事件（C4） |
| **C-21** | 健康检查用 `heartbeat` + `get_status`（NapCat 无 `lifecycle.enable/disable`） | `ChannelAdapter.health()` 契约 + ingress 观测 heartbeat 超时判掉线 | arch §5.4、§3 L3 | 已设计 | 杀掉协议端 → 1 min 内发现掉线（E6） |
| **C-22** | 禁止业务侧使用 napcat 私有扩展 API | adapter 层只实现 OB11 公共 API；能力协商走 `capabilities`；私有 API 不出现在 normalized 类型中 | arch D-05、§5.4 | 已设计 | `grep -rn "group_poke\|nc_get_rkey\|get_mini_app_ark\|fetch_emoji_like" apps/` 为空 |
| **C-23** | 严格 schema + JSON5/parser differential 收敛 | zod 严格解析、拒未知字段、拒带注释/尾逗号帧（按严格 JSON） | arch §5.2 步骤 4 | 已设计 | 构造 JSON5 风格帧 → 被拒并记审计 |
| **C-24** | 四网络 internal + 单一 egress proxy 是部署前提（非优化项） | deploy §1 网络矩阵 + §6 allowlist（阻断 RFC1918/metadata） | deploy §1、§6 | 已设计 | `docker network inspect ... .Internal` 全 true（C2）；容器内 `curl 169.254.169.254` 失败且有 deny 日志（C5） |
| **C-25** | prompt 定界符每次随机以阻格式逃逸 | `envelopeTokenBytes: 4` 每次新生成；工具返回值同等封装 | arch §5.3.3、§9.3 | 已设计 | 单测：两次相同消息生成的 prompt 前缀不同（A4） |
| **C-26** | 工具返回值同等降级为 untrusted（防二级注入回路） | `tools/post-execute` 包裹 `<retrieved-untrusted-xxxx>`；fetch 后同轮 write/exec 直通被拦为 `{kind:'ask'}` | arch §5.3.3 | 已设计 | 注入用例回归：恶意网页 → 被拦在规划步之前（A5） |
| **C-27** | 回帖脱敏（绝对路径/高熵串/堆栈行） | `outbound sanitizer` 规则集 + `redactPatterns: default`；命中计数入审计 | arch §5.3.4、deploy §4 | 已设计 | 审回帖缓冲中 `/home/`、`Error:` 计数为 0（A7） |
| **C-28** | 三级限流在 gateway 实现（早于 agent），并发 run ≤2 | ingress env `RATE_SENDER_PER_MIN/CHAT/GLOBAL` + `MAX_CONCURRENT_RUNS: "2"` | deploy §3 | 已设计 | 压测 → 超限请求未产生 LLM 调用（E1） |
| **C-29** | 8 类审计事件全覆盖 + append-only + 异地副本 | `bot.audit.v1` schema（arch §9.4）+ collector/WORM 远端副本 | arch §9.4、deploy §3(collector) | 已设计 | 每项各造一条 → JSONL 可查（F1）；删本地片段 → 远端完整 + 告警（F3） |
| **C-30** | otel 外送前必须先配 redaction | collector 挂 `processor.yaml:ro`，profile 中**不含** otel endpoint 配置（外送是写代码不是填 YAML） | deploy §3、arch §3 L6 | 已设计 | outbound 样本无聊天正文与 secret（F4） |
| **C-31** | 附件默认不入 context；启用需类型白名单 + 尺寸上限 + 解析超时 | ingress segment 白名单外一律丢弃并打 `risk_tags: oversize/unknown-segment`；`attachments.enabled` 默认 false | arch §5.2 步骤 5、§5.4 | 部分（默认关闭，开启细则交 t4） | 上传超大文件/深层 zip → 被拒且有审计（A8） |
| **C-32** | QQ 必须可牺牲小号、不得作唯一通道 | TG 为主链路；NapCat 故障不影响 TG 侧核心功能；watcher 对 QQ 掉线只告警不降级 | arch H2 相关、deploy §7 | 已设计 | 关停 napcat 容器 → 核心链路仍可用（H2） |
| **C-33** | 不给任何容器 docker.sock / privileged / 宿主根挂载 | compose 全局锚点 `cap_drop ALL` + `read_only`；无任何 socket/特权挂载条目 | deploy §3 | 已设计 | `docker ps -a --format '{{.Names}} {{.Mounts}}' \| grep docker.sock` 为空（B3） |
| **C-34** | 不 mount `dsh-tool-cordis`（运行时 API 枚举属侦察面） | bot profile 组成中显式排除；arch §4.1 表末注明理由 | arch §4.1 注 | 已设计 | `cordis_inspect_list` 在 bot 会话不可见 |

## C. 移交下游的开放项

| ID | 事项 | 归属 | 备注 |
|---|---|---|---|
| O-1 | S2-alt（ingress 拆独立容器）是否在 t4 后启用 | 用户/captain | 取决于对进程内通道代码的信任度评估 |
| O-2 | 升级到 S3 双 VM 的资源判定 | 运维 | NAS VM 内存 ≥8GB 时建议；t1 §4.3 指出 NapCat 常驻内存高 |
| O-3 | `agent/followup` 与 `tools/pre-execute{kind:'ask'}` 在无 open turn 时的交互语义 | t4 集成测试 | 包文档明示「an idle ask rejects before appending anything」，需实测排队场景下的边界 |
| O-4 | `--dump-config-schema` 复核 profile 字段（尤其 `persona.includeRuntimeContext`、`client-connection.cookieMaxAgeDays`） | t4 | 本文档声明为形状示意 |
| O-5 | Docker Hub tag 新鲜度与 digest 锁定（t1 §7.2 未能远程验证） | t4 上线自查 | `docker manifest inspect` + `docker images --digests` |
| O-6 | 附件解析子容器（zip bomb 隔离） | t4+ | C-31 当前以"默认关闭"规避 |
| O-7 | 反向 WS 落点：(a) 独立 ingress 容器 listen `127.0.0.1:3001`（本文采用）vs (b) DSH 进程经 `registerUpgrade()` 承接 | 用户/captain 可选 | 判决与过滤代码在两方案下完全复用；(b) 少一个容器但把未认证 socket 引入 agent 进程 |
| O-8 | ingress→bot-core 提交口的鉴权强度（HMAC 共享密钥 vs mTLS vs internal 网络即信任） | t4 | 需实测 Docker internal 网络下的实际可达性后再定 |

---

## D. 追溯完整性自检

- **U1（访问控制）** → C-01…C-05：判决点、判决输入、拒绝路径、兜底守卫四层齐备，且架构图上有可视化的旁路证明。
- **U2（文件系统隔离）** → C-06…C-09：卷类型、生命周期、禁令声明、变更流程四项齐备；NAS 共享目录在配置中**根本不存在**（而非"只读挂载"）。
- **U3（高危动作审批）** → C-10…C-15：预设组合、类别划分、通道优先级、超时值、备用条件、一次性语义六项齐备。
- **captain 附加五条** → C-16（端口）、C-17（分容器/uid/VM）、C-18（broker）、C-19（watcher/halt 独立）、C-20（OB11 反向 WS + loopback）逐条有落点。
- **t2 §13 给 t3 的六条硬约束** → C-21…C-26 一一对应（normalized 携带 channel/chat_id/user_id/risk_tags、heartbeat+get_status、端口清单固化、禁私有 API、三/四网络 internal + 单一 egress、告警与 kill switch 独立于 LLM）。
- **t2 需要 t3 决定的两个开放项**：① DSH 与协议端是否分 VM → 本文选 S2′ 起步 + S3 升级路径（O-2）；② LLM key 是否走 sidecar → **决定走**（C-18/D-10），理由是公理 2 使然，成本为一跳运维。
- 无条目停留在"原则上满足"：每条都有具体配置键、代码位置或图形元素作为证据锚点。
