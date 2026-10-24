# t2 · 安全基线清单（Security Baseline Checklist）

> DSH 大肥鱼机器伴侣 · NAS 虚拟机部署
> 配套：威胁模型 `t2-threat-model.md`、防御架构 `t2-defense-architecture.md`
> 用法：P0 全部通过才允许接外部消息；P1 在公开使用前完成；P2 为运营期持续项。
> 每条附 **验证命令**——不可验证的条目不算完成。

---

## A. 输入与授权（对应 TM-001 / TM-002 / TM-006 / TM-011）

| # | 级别 | 基线条目 | 验证方式 |
|---|---|---|---|
| A1 | **P0** | 默认拒绝：非白名单 `(channel, chat_id, user_id)` 的消息**不进入 agent 进程**，只回固定文案 | 用非白名单小号发消息，确认无 LLM 调用记录、无工具日志 |
| A2 | **P0** | 授权判定只读结构化字段，代码中不存在对 `nickname/card/sender_name` 的比较 | `grep -rn "nickname\|card" apps/gateway/authz.ts` 为空 |
| A3 | **P0** | QQ 侧管理类动作需跨通道确认（TG 私聊批准后才执行） | 手工演练：QQ 发"改配置"→ 无 TG 确认则不执行 |
| A4 | **P0** | 外部消息体外层使用**每次随机定界符**包裹，并在系统提示中声明为不可信数据 | 单测：两次相同消息生成的 prompt 前缀不同 |
| A5 | **P0** | 工具返回值同样按 untrusted 封装；fetch 结果不得同轮直通写/执行类工具 | 注入用例回归：`web_fetch` 恶意页 → 观察是否被拦在规划步之前 |
| A6 | P1 | 注入启发式规则集覆盖中英 + base64/hex + 零宽字符；命中**打标不静默丢弃** | 语料集 ≥50 条已知 payload，召回率报告 |
| A7 | P1 | 回帖输出脱敏：绝对路径、高熵串、堆栈行一律替换为人话 | `grep` 回帖缓冲中的 `/home/`、`Error:` 计数为 0 |
| A8 | P1 | 附件默认不入 context；启用需类型白名单 + ≤N MB + 解析超时 | 上传超大文件/深层 zip → 被拒且有审计记录 |
| A9 | P2 | 规则更新走版本化配置，变更进审计 | diff 记录存在 |

## B. 执行隔离与容器加固（TM-003 / TM-009 / TM-010）

| # | 级别 | 基线条目 | 验证方式 |
|---|---|---|---|
| B1 | **P0** | 机器人会话 DSH 组成 = `sandbox-policy.mode: read-only` + `approval: never` + permission-presets 不提供 `danger-full-access` | 让 bot 尝试写文件 → 失败且审计有 denied |
| B2 | **P0** | 协议端容器 `cap_drop: [ALL]`、`security_opt: [no-new-privileges:true]`、`read_only: true` + tmpfs | `docker inspect --format '{{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.HostConfig.ReadonlyRootfs}}'` |
| B3 | **P0** | 不给任何容器挂 `docker.sock`；不使用 `--privileged`；不做宿主根目录挂载 | `docker ps -a --format '{{.Names}} {{.Mounts}}' \| grep docker.sock` 为空 |
| B4 | **P0** | bind mount 除明确需要外均带 `:ro`；`napcat/plugins` 卷对 agent 侧不可写 | `mount \| grep <path>` 检查 ro 标志 |
| B5 | P1 | DSH 与 QQ 协议端**分容器且分 uid**运行（理想为分 VM） | `docker exec` 两侧 `id -u` 不同 |
| B6 | P1 | seccomp 定制 profile（禁 `ptrace`、`unshare`、`bpf`、`keyctl`、`socket(AF_NETLINK)` 非必要项） | `docker inspect ... .HostConfig.SeccompProfile` 或 `seccomp-profile` 生效 |
| B7 | P1 | 每周重建容器镜像层（抗持久化后门） | cron/compose 定时任务存在 + 上次执行时间 |
| B8 | P1 | 插件与配置文件基线哈希监控（inotify + sha256 清单） | 手工写入一个假插件 → 触发告警 |
| B9 | P2 | NAS 内核与 DSM 补丁节奏 ≤30 天；VM 独立内核、最小设备直通 | 版本记录 + `lspci`/直通清单比对 |

## C. 网络隔离与端口纪律（TM-007 / TM-008 / TM-013）

| # | 级别 | 基线条目 | 验证方式 |
|---|---|---|---|
| C1 | **P0** | 所有对外服务仅绑 `127.0.0.1`；compose 端口写法必须带 `127.0.0.1:` 前缀 | `ss -ltnp` 输出与期望清单逐行比对（脚本断言，不符即启动失败） |
| C2 | **P0** | 四个网络 `net-protocol/net-ingress/net-agent/net-ops` 全部 `internal: true` | `docker network ls` + `docker network inspect ... .Internal` 均为 true |
| C3 | **P0** | NapCat WebUI(6099)、LLBot WebUI(3080)、OB11 HTTP(3001) 不对 LAN 暴露；LLBot 3080 与 DSH GUI 3080 **冲突已解决**（改高位随机端口，而非放宽绑址） | 从另一台机器扫描这些端口 → 全部 closed |
| C4 | **P0** | 反向 WS 接入握手校验 `access_token` 指纹 + `self_id` 匹配预期；未知来源断开并告警 | 用 curl/wscat 直连监听口 → 立即断开 + 告警事件 |
| C5 | **P0** | 出站统一经 egress proxy allowlist；禁止访问 RFC1918 网段与云 metadata IP | 容器内 `curl http://192.168.x.x` / `169.254.169.254` → 失败；proxy 日志有 deny |
| C6 | P1 | Telegram 采用 **getUpdates 长轮询**而非 webhook（避免对外开 HTTPS 端点） | 无入站监听口对应 TG；配置项核对 |
| C7 | P1 | DSH GUI 仅 SSH 隧道访问；若必须 LAN 则 `webserver.tls` 必配（缺证书时该包拒绝启动，不回退 http） | `curl http://<nas>:3080` 从 LAN → 失败/仅 https |
| C8 | P1 | `cookieMaxAgeDays` 调低（建议 ≤7）；吊销流程文档化 = 删 `client-connection/browser-session` grant + 重启 dsh | 演练一次全量吊销并验证旧 cookie 失效 |
| C9 | P2 | 每日自动 diff 监听口快照并推送变化 | 连续两天日志对比记录存在 |

## D. 凭据存储与轮换（TM-004）

| # | 级别 | 基线条目 | 验证方式 |
|---|---|---|---|
| D1 | **P0** | LLM API key **不在 DSH 进程可读范围**：由 sidecar proxy 持有，DSH 侧仅 opaque reference；agent 无法通过 `printenv`/读文件拿到明文 | 让 bot 执行 `env`/读 `.credentials.yaml` → 无明文 key |
| D2 | **P0** | 关闭 `.env` 回落链：机器人 profile 环境中不含 provider key（`dsh-credentials-local` 会依次回落 launch env → project `.env` → harness-home `.env`） | `docker exec <dsh> env \| grep -i key` 为空 |
| D3 | **P0** | `.credentials.yaml` 权限 0600 且属主非 agent 运行用户（若做不到 D1，至少换 uid） | `stat -c %a ~/.dsh/.credentials.yaml` == 600 |
| D4 | **P0** | `WEBUI_TOKEN` / OB11 `access_token` ≥32 字节随机，不落 git；仓库只有 `.env.example` | `git grep -E "TOKEN=.+"` 无真实值；pre-commit 高熵扫描开启 |
| D5 | **P0** | secret 不进聊天回帖、不进日志、不进错误信息 | 审 100 条最近日志无高熵串 |
| D6 | P1 | 轮换周期：LLM key 30 天双 key 重叠；TG token 立即可 `/revoke`；WebUI/OB11 token 90 天 | 轮换记录表存在 |
| D7 | P1 | 每季度做一次"假设 LLM key 已泄露"演练（吊销→换→重启→验证） | 演练报告（含耗时）归档 |
| D8 | P2 | 凭据分级台账（爆炸半径排序），新增 token 必须先登记再上线 | 台账文件与实际 env 数量一致 |

## E. 速率限制与异常行为检测（TM-012 / TM-014 / TM-016）

| # | 级别 | 基线条目 | 验证方式 |
|---|---|---|---|
| E1 | **P0** | 三级令牌桶在 gateway 实现（早于 agent）：per-sender 10/min、per-chat 30/min、global 60/min 且并发 run ≤2 | 压测脚本 → 超限请求未产生 LLM 调用 |
| E2 | **P0** | owner kill switch `!halt` 立即停全部通道，且实现**不经 LLM** | 发 `!halt` → 后续消息全部只回固定文案 |
| E3 | **P0** | 自动熔断：出现凭据路径访问尝试 / 非白名单出站点 / 连续 N 次审批拒绝 → 降级为只读固定文案 | 构造触发样本 → 状态变为 degraded 并有告警 |
| E4 | P1 | 每 sender 每日 LLM token 预算；超预算回"今日额度已用完" | 灌量测试 |
| E5 | P1 | 检测信号落地：未授权尝试突增、payload 形态突变、`web_fetch→exec` 序列、首次出现的出站目的、花费 z-score、非 loopback 监听、镜像 digest 漂移 | 每条信号有一个可运行的查询/脚本 |
| E6 | P1 | 健康检查用 `heartbeat` + `get_status`（NapCat 不支持 `lifecycle.enable/disable`） | 杀掉协议端 → 1 min 内发现掉线 |
| E7 | P2 | watcher 自身心跳告警（沉默即告警） | 停 watcher → 收到 alive-missing |

## F. 日志审计与告警（TM-014）

| # | 级别 | 基线条目 | 验证方式 |
|---|---|---|---|
| F1 | **P0** | 8 类事件全覆盖：外部消息（含被拒）、授权判定、工具调用、approval 结论、sandbox denial、凭据解析、出站连接、配置/插件/镜像变更 | 每项各造一条 → JSONL 中可查到 |
| F2 | **P0** | 告警由旁路 watcher 发出（订阅事件/tail 日志），**不经 agent、不经 LLM** | 在 agent 里下达"不要通知主人" → 告警仍送达 |
| F3 | **P0** | 审计 sink append-only + 异地副本；本地删除远端仍在 | 删本地片段 → 远端完整 + 触发告警 |
| F4 | **P0** | 启用 `dsh-otel`/`dsh-session-telemetry` 前**先配 redaction 规则**（否则「captured data leaves the process unchanged」，聊天原文会外送） | outbound 样本无聊天正文与 secret |
| F5 | P1 | 保留期热 7 天 / 冷 ≥90 天；日志自身限流防灌爆 | 配置核对 + 压测 |
| F6 | P1 | 沙箱 deny 判定不作为唯一依据（`dsh-bash-sandbox` 明示 deny 由 stderr 推断，可能漏报/误报） | 判决逻辑改用白名单前置，deny 仅作辅助信号 |
| F7 | P1 | NAS 校时（NTP），保证跨源关联可用 | `timedatectl` 偏移 < 1s |
| F8 | P2 | 月度审计报告：Top 拒绝原因、异常趋势、轮换到期提醒 | 报告产出记录 |

## G. 供应链与发布（TM-015）

| # | 级别 | 基线条目 | 验证方式 |
|---|---|---|---|
| G1 | **P0** | 镜像固定版本标签 + digest 锁定，不用 `latest` | `docker images --digests` 与 compose 中 tag 一致 |
| G2 | P1 | 上线自查纳入 checklist：`docker manifest inspect mlikiowa/napcat-docker:<tag>`（t1 §7.2 未能远程验证 Hub tag 新鲜度） | 自查输出归档 |
| G3 | P1 | LLBot 启动期从 GitHub Release 拉 zip 的行为视为运行时取码风险：优先锁 digest/自建镜像 | Dockerfile diff 记录 |
| G4 | P2 | 上游活跃度季度复核（NapCat/LLBot release 节奏、go-cqhttp 类僵尸项目不复现） | 复查记录 |

## H. 账号与平台风险（TM-016 · 可用性约束，非可消除项）

| # | 级别 | 基线条目 | 验证方式 |
|---|---|---|---|
| H1 | **P0** | QQ 使用**可牺牲专用小号**，不加任何管理权限群 | 账号清单 |
| H2 | **P0** | QQ 不作唯一通道：TG 为主，QQ 掉线不影响核心功能 | 关停 NapCat 容器 → 核心链路仍可用 |
| H3 | P1 | 自动化发言频率上限（低于人工水平），夜间静默 | 配置核对 |
| H4 | P2 | 被封后的切换 SOP（备用小号 + 平移 LLBot，因 OB11 接口一致） | 演练一次 |

---

## 上线门禁（Go / No-Go）

```
No-Go 条件（任一成立即不得接入外部消息）：
  ✗ A1/A2/A4/A5 未通过          —— 注入主防线缺失
  ✗ B1/B2/B3 未通过             —— agent 具备自由 shell 或未做容器围栏
  ✗ C1/C2/C4/C5 未通过          —— 攻击者可直接连入或任意外传
  ✗ D1/D2/D5 未通过             —— 注入后可直接拿到明文密钥
  ✗ E1/E2/E3 未通过             —— 无节流、无止损手段
  ✗ F1/F2/F3/F4 未通过          —— 攻击隐形，且检测通道可被关闭
  ✗ G1/H1/H2 未通过             —— 供应链与封号止损缺失
```

**残留风险声明（诚实列出，不假装已解决）**
1. DSH sandbox 只管文件效果，**网络/进程/系统调用/凭据不在其词汇表**（官方文档原文）→ 出站控制必须由容器/proxy 层承担，这一层的正确性是本设计的命门。
2. 同 OS 用户下的凭据隔离只能靠 proxy broker（D1）；若运维图省事把 key 放回环境，D1 立刻退化。
3. NapCat 容器内含被注入的官方 QQ Electron，属**不可审计的高权限第三方代码**；我们对它只做"隔离 + 最小暴露"，无法做可信性证明。
4. Prompt injection 没有可靠的可判定过滤器；本设计依赖"授权前置 + 能力最小化 + 独立止损"，而非依赖过滤器的召回率。
5. QQ 风控/封号无公开量化数据，只能降低影响面（小号 + 双通道），不能预防。
