# t2 [t5-core-impl] 进度检查点（暂停时快照）

任务：`t2 [t5-core-impl]` · attempt `8837f507-65b1-4f29-8ef5-c1ab1c4a1abe` · 状态 **in_progress**
分支：`feature/core-impl`（未合并，未推 main）· 记录时间：2026-10-24 20:10 (+08:00)

这份文件是**暂停检查点**，不是最终验证记录。最终记录按验收条目重写为
`docs/validation/core-impl.md`（恢复后完成）。

## 1. 已完成并可运行的部分

| 模块 | 位置 | 状态 |
|---|---|---|
| 编排与网络 | `deploy/compose.yaml`（profiles: `qq`/`llbot`/`egress`/`agent`/`ops`） | ✅ `config --quiet` 通过（默认 + 全 profile） |
| 记忆服务（PG 权威 + SQLite L1/投影） | `apps/memory-service/` | ✅ 双写、SQLite 先读 + 回填、中文 trgm 检索、审批删除、墓碑、访问账本 |
| PG 迁移与角色（宿主实例） | `deploy/scripts/host-pg-prepare.sh` + `docs/memory/sql/pg/001..004` | ✅ 建库/角色/pg_hba/迁移 001–004/权限矩阵在线校验，重复执行幂等 |
| Secret Broker（凭据 + LLM 转发） | `apps/secret-broker/` | ✅ 授权矩阵、HMAC 签名、头剥离、字面量拒答 |
| 引用注入（env 只有 opaque ref） | `packages/bot-secrets/` | ✅ 新增 resolve 层，broker 优先、挂载文件兜底 |
| 接入网关（OB11 反向 WS + TG 出站） | `apps/gateway/` | ✅ 白名单在 LLM 之前、限流、去重、结构化 id 判定 |
| DSH 插件 + intake | `apps/bot-core/` | ✅ 4 个记忆工具、guard、审批拦截、签名提交、standalone 模式 |
| 宿主基线/监听断言 | `deploy/scripts/assert-listeners.sh`、`assert-host-baseline.sh` | ✅ 全部 loopback |
| 文档 | `README.md`（快速开始 + 端口表 + 偏差清单 + 安全要点） | ✅ 已写完 |

## 2. 验收条目实测结果

| # | 验收条件 | 证据 | 结果 |
|---|---|---|---|
| 1 | `docker compose up` 起全栈，30 s 内健康 | 冷启动计时：broker 12.8s / memory 13.1s / bot-core 13.3s / ingress **13.5s 全部 healthz 200**；`compose ps` 四个 `(healthy)` | ✅ |
| 2 | 非白名单 user_id 被拒 + 审计 | `scripts/ingress-e2e.mjs` **13/13**（含 W1 错 token→1008、W7 伪 self_id→1008、W2b `not-whitelisted` 审计、W2c 不落昵称、W5 限流审计、W6 审计无凭据） | ✅ |
| 3 | 记忆读/写/检索/删除，删除触发审批 | `scripts/memory-e2e.mjs`（真实栈）**24/24**：无令牌写→`APPROVAL_REQUIRED`、审批后删除→墓碑 + 缓存行消失 + 读 `ACL_DENIED`、trusted 调 forget 被拒、访问账本 delete/read/search/write 齐全 | ✅ |
| 4 | Agent 读不到 LLM key / PG 口令明文 | `scripts/broker-e2e.sh`（在容器内发起）**17/17**：bot-core 拿 `llm-api-key`/`llm-key`/`mem-pg-rw-password`/`mem-kek` 全 403，memory 拿 `llm-key`/别人的 token 全 403，四个容器 env 里只有 `opaque-ref:`，`llm-key` 文件只挂在 broker，直连外网不可达 | ✅ |
| 5 | PG 迁移在**宿主实例**成功、幂等、权限矩阵 | `host-pg-prepare.sh` 跑两遍均 OK；[4/5] 以真实登录角色探测：ro 禁 INSERT/`pgp_sym_decrypt`，rw 禁 DELETE 墓碑/禁 `forget_by_subject`，允许 `purge_expired` | ✅ |
| 6 | README 快速开始 + `docs/validation/` 验证记录 | README ✅；验证记录当前为本检查点，最终版待写 | 🟡 部分 |

单测/集成：**127 通过 / 0 失败**（`npm test`，含新增 `packages/bot-secrets/test` 10、`apps/bot-core/test/plugin.test.mjs` 15、`apps/gateway/test/*` 21、`apps/memory-service/test/unit.test.mjs` 25、broker 14）；
`node scripts/integration-memory.mjs` **35/35**（临时 PG 实例上的迁移 + 角色矩阵 + 读写检索删除）。

## 3. 剩余工作

1. **3 个 Telegram 适配测试断言待修**（实现是对的，断言写死）：重复轮询下 `stats.polls === 1` 应为 `>= 1`；假 API 需按 `offset` 返回空列表；经代理的绝对形式 URL 因百分号编码不能逐字节比较。**这是本次暂停时唯一在跑红的项**。
2. 覆盖率：全仓 `all files` 行覆盖 **78.32 %**（新增 telegram/memory-client 用例后重测中）；`repository.mjs`/`migrate.mjs` 的低数字是**测量口径问题**——它们由 `scripts/integration-memory.mjs`（真 PG）覆盖，不在 `npm test` 的进程内。要么把它们并入覆盖率口径，要么在验证记录里如实标注。
3. 最终验证记录 `docs/validation/core-impl.md`：把上面 6 条的原始输出贴全，并把 7 条设计偏差逐条写清（unix socket、`net-edge` 第五网络、3005 方向、DEK 按敏感度分域、HMAC 绑定 query+approval、审计词表扩两项、`memory_readable` 缺列）。
4. PR：按模块提交后推 `feature/core-impl`，`gh pr create --reviewer captain --reviewer memory-architect --reviewer security-validator`。
5. 可选项：`deploy/seccomp/napcat.json` 占位、`ops/watcher` 最小实现补全。

## 4. 暂停时发现的两个真实缺陷（已修，供 review 关注）

* `apps/memory-service/src/jobs.mjs`：构造器里 `this.status = new Map()` 把原型的 `status()` 方法**遮蔽**，`GET /jobs` 会 500。已改名 `statusByJob`，并加单测锁住。
* `apps/memory-service/src/repository.mjs`：`forget()` 只对 episode/profile 生效，**偏好（preference）删除会返回 `ACL_DENIED`**（即使审批通过）。已补 preference 分支（墓碑→删 embedding→删行，同一事务）。
* 另记：`docker compose cp` 在只读 rootfs 上不可用；宿主 Docker 对纯 internal 网络不发布端口（见偏差 2）。

## 5. 阻塞点

无外部阻塞。模型链路（真实 LLM 调用）不在本任务范围：`BOT_CORE_MODE=echo` 可闭环整条接入链路；
切到 `queue` 需要 `deploy/secrets/llm-key` 配真实 key 并由 broker 转发。
