# DSH 大肥鱼机器伴侣 · 可运行原型

QQ 伴侣机器人的运行骨架：四个容器 + 宿主 PostgreSQL 长期记忆 + SQLite 短期缓存 +
Secret Broker 凭据隔离。设计文档见 [`docs/design/`](docs/design/)、
[`docs/memory/`](docs/memory/)、[`docs/security/`](docs/security/)；本文只讲**怎么把它跑起来**
和**怎么验证它真的按设计工作**。

```
 NapCat / LLBot（协议端，宿主机或 NAS）
        │  reverse WebSocket（127.0.0.1:3001，唯一对外发布的入口端口）
        ▼
 ┌────────────┐   signed /submit    ┌──────────────┐   signed /v1/*    ┌────────────────┐
 │  ingress   │ ──────────────────▶ │  bot-core    │ ────────────────▶ │    memory      │
 │ (gateway)  │   白名单/限流/审计   │  DSH agent   │                   │ 记忆服务(8091) │
 └────────────┘                     └──────┬───────┘                   └───────┬────────┘
        ▲                                 │                              PG rw/ro
        │  /v1/secret/:ref 仅授权客户端     ▼                              (宿主实例)
 ┌──────┴─────────────────────────────────────────┐
 │ secret-broker（LLM 出站转发 + 凭据注入，8080） │
 └────────────────────────────────────────────────┘
```

## 端口

| 端口 | 位置 | 说明 |
|---|---|---|
| `127.0.0.1:3001` | 发布 | OB11 反向 WebSocket 监听（ingress） |
| `127.0.0.1:3080` | 发布 | DSH Web GUI（`--profile agent`） |
| `127.0.0.1:3081` / `3082` | 发布 | NapCat WebUI / LLBot WebUI（`--profile qq` / `llbot`） |
| `8091` | 仅内网 | 记忆服务 REST（net-agent） |
| `8190` | 仅容器内 loopback | 记忆服务管理面（healthz / jobs） |
| `8181` `8185` `8180` | 仅容器内 loopback | ingress / bot-core / broker 健康检查 |
| `3005` | 仅内网 | bot-core intake `/submit` |

任何端口都不绑定 `0.0.0.0`；`bash deploy/scripts/assert-listeners.sh` 会替你确认这一点。

## 快速开始

前置条件：Docker + compose v2、Node ≥ 22（`node:sqlite` 内置）、宿主 PostgreSQL 16。

```bash
# 1) 生成凭据材料（0600/0644，见脚本输出说明）
bash deploy/scripts/gen-secrets.sh

# 2) 配置环境变量
cp deploy/.env.example deploy/.env
#   必填：SELF_ID（机器人 QQ 号）、TOKEN_FP（= sha256(NapCat 的 access_token)）
#   printf '%s' "$TOKEN" | sha256sum  —— token 本身永远不进 env / 不进容器
$EDITOR deploy/.env

# 3) 宿主 PostgreSQL：建库 + 角色 + pg_hba + 迁移 001..004 + 权限矩阵自检
MEM_PG_RW_PASSWORD="$(cat deploy/secrets/mem-pg-rw-password)" \
MEM_PG_RO_PASSWORD="$(cat deploy/secrets/mem-pg-ro-password)" \
  bash deploy/scripts/host-pg-prepare.sh

# 4) 起栈（默认四个服务）
docker compose -f deploy/compose.yaml up -d --wait
docker compose -f deploy/compose.yaml ps        # 全部 (healthy)
bash deploy/scripts/assert-listeners.sh         # 全部 loopback

# 5) 可选：协议端与代理
docker compose -f deploy/compose.yaml --profile qq up -d        # NapCat（需 NAPCAT_WEBUI_TOKEN）
docker compose -f deploy/compose.yaml --profile egress up -d    # squid 出站白名单
docker compose -f deploy/compose.yaml --profile agent up -d     # DSH Web GUI
```

把 NapCat 的 HTTP/WS 上报方式设为 **reverse_ws**，地址 `ws://127.0.0.1:3001/onebot/v11/ws`，
`access_token` 与第 2 步算指纹的那个 token 一致，`self_id` 与 `SELF_ID` 一致。
原型阶段没有真 QQ 号时，可用 `node scripts/ingress-e2e.mjs` 扮演协议端（见下）。

默认 `BOT_CORE_MODE=queue` 需要一个可用的模型 key；把 `deploy/.env` 里改成 `echo`
即可在没有 key 的情况下跑通“接入 → 白名单 → 提交 → 回复”整条链路（回复是一条确认文本）。

## 验证

```bash
npm test                        # 单元 + 契约测试（全部离线，不需要 Docker）
node scripts/integration-memory.mjs   # 35 项：临时 PG 实例上跑迁移、角色矩阵、读写检索删除
node scripts/ingress-e2e.mjs          # 13 项：白名单/握手/限流/审计（需要栈在跑）
bash scripts/broker-e2e.sh            # 17 项：凭据隔离与出站限制（需要栈在跑）
docker compose -f deploy/compose.yaml exec -T memory node --input-type=module < scripts/memory-e2e.mjs
                                    # 24 项：真实栈上的记忆读写/中文检索/删除审批/墓碑
docker compose -f deploy/compose.yaml config --quiet    # 交付门槛
```

完整实测记录（含命令输出）在 [docs/validation/core-impl.md](docs/validation/core-impl.md)。

## 目录

```
apps/gateway/          ingress：OB11 反向 WS、Telegram 长轮询、白名单、限流、去重、提交
apps/bot-core/         DSH 扩展（4 个记忆工具 + guard + 审批拦截）与 intake 服务、standalone 模式
apps/memory-service/   记忆服务：PG 权威存储 + SQLite L1/投影缓存 + 检索 + 保留任务 + 迁移
apps/secret-broker/    凭据解析与 LLM 出站转发（唯一持有 llm-key 的容器）
packages/bot-*         共享包：hmac、audit、normalize、sanitize、crypto、secrets
deploy/compose.yaml    编排（四个 internal 网络 + net-edge，见偏差说明）
deploy/profiles/bot/   DSH profile：沙箱 read-only + workspaceRoot tmpfs + approval ask
deploy/scripts/        gen-secrets / host-pg-prepare / assert-listeners / assert-host-baseline
docs/memory/sql/pg/    迁移 SQL 的规范副本（apps/memory-service/migrations 是执行副本）
scripts/               集成与端到端验证脚本
```

## 与 t3/t4 设计的偏差（实测原因，详见验证记录）

1. **宿主 PostgreSQL 走 unix socket**，不是 t4 §9.3 方案 A 的 TCP。宿主实例只监听
   `127.0.0.1`，而 internal 网络到 host-gateway 的 TCP 实测不通；compose 把
   `/var/run/postgresql` 挂进 memory 容器，`MEM_PG_HOST=socket:/var/run/postgresql`。
2. **新增第五个网络 `net-edge`**（非 internal，但关闭 IP masquerade 且强制
   `host_binding_ipv4=127.0.0.1`）。t3 §4 的四个网络全是 internal，而 Docker 无法为
   只挂在 internal 网络上的容器发布端口（`HostConfig.PortBindings` 有值但
   `NetworkSettings.Ports` 为 null），反向 WS 入口因此必须有一个非 internal 链路。
3. **3005 的方向**在 t3 文本里前后不一致；实现按 “ingress → bot-core:3005” 落地。
4. **DEK 域按敏感度划分**，不是 t4 的按类别划分（类别可以改，密钥域不能改）。
5. **`bot-hmac` 的规范化串包含 query string**，并把 `X-Bot-Approval` 绑定进签名，
   否则审批令牌可以贴到别的请求上。
6. **审计词表增加 `ratelimit.exceeded` / `session.lifecycle`**：`AuditSink.emit()` 会把
   不在词表内的类型改写成 `external.message`，限流事件因此一度在日志里“消失”。
7. **`memory_readable` 视图不含 `created_at`/`attr_key` 列**（迁移里就有这个差异），
   服务层按现有列使用；补齐属于 schema 变更，未在本任务夹带。

## 安全要点（改动前必读）

* 白名单只看结构化 `(channel, chat_id, user_id)`；昵称/备注在任何一层都不参与判定，
  未命中直接拒绝并写审计（默认**不回话**，`REFUSE_REPLY=polite` 才回拒绝文本）。
* 长期记忆写入与删除需要一次性审批令牌；`memory_forget` 仅 owner 角色可调用，
  bot-core 的 guard 与记忆服务端各自拦一道。
* LLM key 只在 broker 容器里；bot-core 只能请求 `POST /v1/llm/*`，转发前剥掉
  `authorization`/`cookie`/`x-broker-token` 等头，上游响应剥掉 `set-cookie`。
* 宿主实例的 `dsh_companion_rw` / `dsh_companion_ro` 权限矩阵由
  `deploy/scripts/host-pg-prepare.sh` 第 [4/5] 步在线验证，不可执行
  `forget_by_subject`（遗忘由服务自己做，墓碑先写、删除后写）。
* 容器 rootfs 只读、`no-new-privileges`、cap drop ALL、tmpfs 512M 工作区；
  agent 平面没有直连外出的路由（`scripts/broker-e2e.sh` 第 [5] 步实测为不可达）。

## 已知限制（原型阶段）

* QQ 主链路已用真实账号跑通（白名单私信 → echo 回执回到 QQ，陌生人私信被 default-deny 拒绝，
  见 [runbook 第 3 节](docs/validation/qq-channel-runbook.md)）；`scripts/ingress-e2e.mjs`
  扮演的假适配器仍在，用途变成回归覆盖而不是唯一证据来源。
* **Telegram 通道整体 deferred（本原型不启用）**：本机到 `api.telegram.org` 网络不可达
  （调研期已证实，也是此前“卡住”的根因）。适配器代码与出站/长轮询实现保留，单测对着本地
  假 API 跑通（`apps/gateway/test/telegram.test.mjs`，11 项，全程不联网），但没有真实 TG
  验收；默认栈不挂 TG 入站，`deploy/.env` 的 `TG_BOT_TOKEN_ALERT` 只服务可选的告警看门狗。
  打通顺序 QQ 优先。
* Telegram 侧只实现了出站 + getUpdates 长轮询，没有入站监听器（C6）。
* NapCat 镜像按 digest 固化：`mlikiowa/napcat-docker:v4.18.41@sha256:b101b896…`（buildx imagetools
  与 Hub tag API 双源一致，见 [runbook 第 1 节](docs/validation/qq-channel-runbook.md)）；
  `deploy/seccomp/napcat.json` 仍是占位，因此 NapCat 目前跑在 Docker 默认 seccomp profile 下，
  需要自定义策略时用绝对路径 `NAPCAT_SECCOMP_PROFILE=/abs/napcat.json`（相对路径对 daemon 无效）。
* **协议容器以 uid 1000 运行，偏离 t3 基线的 2100（现在是主动选择，不是静默错配）**：镜像的
  `entrypoint.sh` 靠 `usermod` 改 `/etc/passwd` 落地 `NAPCAT_UID`，而 `read_only: true` 让
  `/etc` 不可写，`gosu napcat` 只会落到镜像内建 uid 1000；与此同时它每次启动都按 `NAPCAT_UID`
  把挂载目录 chown 回去，所以声明 2100 会让 uid 1000 的 QQ 进程对 `0700` 的 `data/qq` 持续
  Permission denied，登录服务每 40s 重置、二维码活不到被扫。因此 `NAPCAT_UID/GID` 设为 1000
  与宿主目录属主一致。降权仍有效（不是 root），容器只挂 `data/{qq,napcat-app,napcat-config,
  napcat-plugins}` 四个目录，宿主工作区与 `deploy/secrets/*` 不在其中。要真正满足 2100 需要
  自建派生镜像预置 passwd 再重新固化 digest，待 t3 安全定级后另开任务。
* **`net-qq` 是本机唯一给协议容器直连 WAN 的网络（新增偏差，需 t3 正式定级）**：QQ 客户端必须
  直连腾讯 login/msf 服务器（raw TCP/QUIC），squid 白名单代理不了这类流量，所以协议容器无法
  像其他平面一样只走 internal 网。`net-qq` 是 bridge + masquerade 且排在 `networks` 首位以承载
  默认路由；其余服务的网络策略未改动。这是 QQ 协议端的固有属性，不是实现偷懒。
* **WebUI 曾临时发布在 `0.0.0.0:3081`（2026-10-24 约 22:00–22:44 +08）并已回退**：操作者从远程
  设备管理这台 VM，够不到 `127.0.0.1:3081`，只能短暂开到 LAN 完成一次性扫码；登录采纳后立即
  改回 loopback-only（commit `b3994fa`），期间暴露面叠加了上一条「日志明文打 WebUI token」，
  因此那段时间的 `docker compose logs napcat` 与 LAN 上的 3081 都按已泄露处理，
  建议后续轮换 `NAPCAT_WEBUI_TOKEN`。
* **NapCat 会把 WebUI token 明文写进容器日志**（上游行为，不改镜像无法关闭），因此
  `docker compose logs napcat` 属敏感输出；t3 时再评估是否要做日志脱敏。
* `--profile ops` 的 watcher/collector 目前是最小实现，只做降级旗标与心跳读取。
