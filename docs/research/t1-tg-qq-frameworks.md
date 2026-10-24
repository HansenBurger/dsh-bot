# t1 · TG / QQ 机器人接入方案调研

> DSH 大肥鱼机器伴侣 · 协议端选型
> 调研时间：2026-10-24（Asia/Shanghai）· 数据来源见文末「证据与验证」
> 结论速览：**QQ 侧 NapCatQQ（主）+ LLBot/LuckyLilliaBot（备），统一走 OneBot 11 反向 WebSocket；TG 侧 aiogram（Python，主）或 grammY（TS，若 DSH 同栈则优先）；go-cqhttp / Mirai 一律排除。**

---

## 1. 调研范围与方法

目标是为 DSH 找一个能把 Telegram 与 QQ 消息送进同一个入口的成熟开源方案。两类平台的技术性质完全不同，必须分开评估：

| | Telegram | QQ |
|---|---|---|
| 官方态度 | **官方开放 Bot API**，有 token 即合规 | **无官方 Bot API**，全部依赖逆向协议或客户端注入 |
| 封号风险 | 几乎为零（遵守 ToS 即可） | 真实存在，是选型的头号约束 |
| 架构位置 | DSH 直接调用库即可 | 需要一个独立的**协议端网关**进程，DSH 只对接网关 |

因此 QQ 侧的评估对象是「协议端」（protocol-side gateway），Telegram 侧的评估对象是「应用端 SDK」。这两层不能混为一谈，也决定了 DSH 的接入层设计必须是**适配器 + 统一消息模型**。

采集手段：GitHub REST API（stars / push 时间 / release 时间线 / commit 频率 / 仓库文件树 / README）、PyPI 与 npm registry 发布记录、PyPI downloads stats、各框架官方文档站、以及从 sdist 源码中直接读取的 API 版本常量。

---

## 2. QQ 侧候选对比

### 2.1 核心对比表

| 项目 | 最新版本 / 日期 | 近 90 天 commit | Stars | 协议实现 | Docker | 维护判定 |
|---|---|---|---|---|---|---|
| **NapCatQQ** (NapNeko) | v4.18.41 · 2026-10-21 | **69** | 11.4k | OneBot 11 + go-cqhttp 扩展 + napcat 私有扩展 | ✅ 官方镜像 `mlikiowa/napcat-docker`（amd64/arm64）+ compose 模板 | 🟢 **活跃，事实标准** |
| **LLBot / LuckyLilliaBot**（原 LLOneBot）(LLOneBot) | v8.3.2 · 2026-10-12 | **100+** | 3.7k | OneBot 11 **+ Satori + Milky** | ✅ 仓库内 `docker/Dockerfile`、`initialencounter/llonebot` 镜像、`llonebot.nix` | 🟢 **最活跃** |
| Lagrange.Core (LagrangeDev) | nightly · 2025-08-02 | 19 | 3.0k | 纯 NTQQ 协议 + Milky | ⚠️ 仅 `Lagrange.Milky` 有 Dockerfile | 🟡 慢热，**license 缺失** |
| SnowLuma | — | 高频（push 2026-10-23） | 2.2k | 「Next Remote Protocol Framework」 | 未验证 | 🟡 新星，NapCat 官方 README 主动推荐 |
| ~~go-cqhttp~~ (Mrs4s) | v1.2.0 · **2023-10-09** | **0**（末次 commit 2024-05-09） | 10.6k | OneBot 11 + CQ 扩展 | 旧镜像已失效 | 🔴 **官方放弃** |
| ~~Mirai~~ (mamoe) | — | **0**（末次 push 2024-09-23） | 14.8k | 旧协议（非 NTQQ） | 需 JVM | 🔴 **停更** |

### 2.2 关键发现一：go-cqhttp 已被官方宣告死亡

这是本次调研最重要的排除性结论。go-cqhttp README 顶部「重要信息」原文：

> 由于QQ官方针对协议库的围追堵截, 不断更新加密方案, **我们已无力继续维护此项目**.
> 建议Bot开发者尽快迁移至无头NTQQ项目 → https://github.com/Mrs4s/go-cqhttp/issues/2471

佐证数据链完整：最后一次正式 release 是 v1.2.0（2023-10-09），最后一次 commit 2024-05-09（一个 merge PR），此后近一年半零提交，但仍挂着 314 个 open issues——典型的「僵尸仓库高星」形态。仓库 stars 高达 10.6k，容易让只看 star 数的选型误判。

**推论**：任何把 go-cqhttp 当作现役方案的教程/AI 生成代码都不可信。它唯一残留的价值是**接口方言**：社区把它的一堆扩展 API（`get_group_msg_history`、`ocr_image`、`_send_group_notice`、CQ 码等）当成了事实约定，而 NapCat 明确宣称兼容这批扩展 API。

Mirai 同理：末次 push 2024-09-23，且基于旧协议栈（非 NTQQ），在 QQ 9.x 时代已不适配。

### 2.3 关键发现二：NapCat 的 OneBot 11 覆盖度实测

NapCat 官方文档 `/develop/api` 逐条列出兼容性，实测结论：

- **OneBot 11 公共 API：全部 ✅**（`send_private_msg` / `send_group_msg` / `set_group_ban` / `get_group_member_list` / `delete_msg` / `get_file` 等）
- **连接方式全支持**：HTTP API、HTTP POST 事件上报、HTTP POST 快速操作、正向 WS、反向 WS
- **go-cqhttp 扩展 API 大量 ✅**：`set_qq_profile`、`get_online_clients`、`delete_friend`、`mark_msg_as_read`、`send_group_forward_msg`、`get_group_msg_history`、`ocr_image`、群文件系统全套、`_send_group_notice` 等
- **napcat 私有扩展**：`group_poke`、`translate_en2zh`、`fetch_emoji_like`、`get_ai_record`、`create_collection` 等（这些是**不可移植**的部分，接入层不应依赖）

消息段兼容（`/develop/msg`）：`text` `face` `image` `record` `video` `at` `share` `contact` `location` `music` `reply` `forward` `node` `json` `mface` `file` `markdown` `lightapp` 均支持收发，其中 `shake`/`share`/`location` 仅收、`markdown` 仅在双层合并转发内可发——属于 QQ 平台本身的能力边界，不是框架缺陷。注意自 v4.4.14 起 NapCat 用 **JSON5** 解析请求（允许尾随逗号与注释），严格 JSON 序列化器需注意。

事件兼容（`/develop/event`）有一处值得警惕的缺口：
- `meta_event.lifecycle.enable` / `.disable` ❌ 不可用（只有 `.connect` 和 `heartbeat` ✅）
- `message.private.group_self`、`message.group.notice` ❌

**影响**：DSH 无法靠 OneBot 标准的 lifecycle 事件判断协议端就绪，必须改用 `heartbeat` + 主动 `get_status` 轮询做健康检查。这条应写进后续安全/健壮性设计。

### 2.4 关键发现三：LLBot 的多协议能力是差异化优势

LLBot（LLOneBot 改名后的 LuckyLilliaBot）在同一份 config 里可同时开启三套协议出口：

```jsonc
{ "ob11":   { "enable": true, "connect": [{ "type": "ws", "port": 3001 }] },
  "milky":  { "enable": true, "http": { "port": 3010 } },
  "satori": { "enable": true, "port": 5600, "token": "" } }
```

外加 WebUI（默认 **3080** 端口）。它的 Docker 镜像基于 `node:24-alpine` + ffmpeg + `TZ=Asia/Shanghai`，比 NapCat 的镜像轻得多。

**反查到一个部署冲突点**：LLBot WebUI 默认端口 3080，与当前 DSH Web GUI 的 3080 完全相同。同机部署必须改端口，否则容器/进程端口争抢。

另一项对 NAS 很关键：LLBot 文档明确区分**有头模式（HOOK，需 LiteLoaderQQNT 拉起真 QQ 客户端）**与**无头模式（纯协议，不需要 QQ 客户端）**。「无头模式不需要 QQ 客户端」意味着它可以在纯 headless 容器里跑，而 NapCat 的 Docker 方案是把官方 `linuxqq_3.2.34` .deb 装进容器再注入（见 §4）。

### 2.5 反检测 / 风控维度（诚实说明）

这一维**没有可靠的公开量化指标**，任何声称"绝对不封号"的说法都应视为营销。可核实的事实只有：

- go-cqhttp 的死因本身就是腾讯的协议围堵 → 说明该风险是实质性的、能杀死项目的。
- NapCat README 明确限定用途：「本仓库仅用于提高易用性，实现消息推送类功能……使用请遵守当地法律法规，由此造成的问题由使用者和提供违规使用教程者负责。」并采用**混合 license**，且「禁止任何项目未经仓库主作者授权基于 NapCat 代码开发」。
- NapCat 社群入群需要密钥、限制人数、审核编程基础 → 侧面反映风控话题在社区内被谨慎对待，公开资料少。
- LLBot 桌面版安装要求「不要安装第三方 QQ 插件」「64 位官方原版 NTQQ」→ 官方自己也在规避叠加注入带来的检测面。
- 两者都仍在被持续攻击面更新（NapCat 一周内三个 patch 版本），说明适配 QQ 新版本是当前主要工程负担。

**给架构的硬约束**：QQ 账号必须是**可牺牲账号**（专用小号），且接入层要假设随时可能掉线/被封，不能把 QQ 作为唯一通道。这与后续的防注入安全架构是同一条防线：外部消息一律按不可信输入处理。

---

## 3. Telegram 侧候选对比

### 3.1 核心对比表

| 项目 | 最新版本 / 日期 | 支持的 Bot API | 月/周下载量 | Stars | 维护判定 |
|---|---|---|---|---|---|
| **python-telegram-bot** | v22.8 · 2026-06-12 | **10.0**（源码 `_BotAPIVersion(major=10, minor=0)`） | **6.76M/月** | 29.5k | 🟢 活跃，API 跟进略慢半拍 |
| **aiogram** | v3.31.0 · 2026-08-25 | **10.3**（源码 `__api_version__="10.3"`） | **2.76M/月** | 5.9k | 🟢 活跃，**API 最新** |
| **grammY** (TS) | v1.46.0 · 2026-08-26 | 类型包 `@grammyjs/types` 5.0.0，方法数 **185 = aiogram 的 186**（差 1 个为内部 base） | **2.16M/周** | 3.8k | 🟢 活跃，**API 最新** |
| Telethon | PyPI 1.45.0 · 2026-09-10 | MTProto schema **LAYER = 229** | 3.01M/月 | 12.1k（**仓库已 archived**） | 🟡 **迁移至 Codeberg**，仍发版 |
| telegraf (TS) | 4.16.3 · **2024-02-29** | 落后多个版本 | 178k/周 | 9.2k | 🔴 **停滞约 2.5 年** |

### 3.2 关键发现一：Telethon 的 GitHub 仓库已经归档

GitHub `LonamiWebs/Telethon` 状态为 `archived: true`，README 首行：

> Moved to https://codeberg.org/Lonami/Telethon. The GitHub repository may be deleted in the future.

但**不等于项目死了**：PyPI 上 1.45.0 发布于 2026-09-10，1.43→1.45 的节奏是每季度一版，schema LAYER 已到 229，月下载 3.0M。正确表述是「**开发主阵地迁到 Codeberg，GitHub 镜像停更但包发布正常**」。选型时若依赖 GitHub issue 追踪/CI 拉取要注意源已变更。

Telethon 的定位也不同：它是 **MTProto 客户端库**，能以**普通用户账号**登录（userbot），不只是 bot。这带来额外能力（读历史、加入任意群、多账号），也带来额外封号风险——用户账号违反 ToS 会被真封。

### 3.3 关键发现二：Bot API vs MTProto 的取舍

| | Bot API（PTB / aiogram / grammY） | MTProto（Telethon / gram.js / tdlib） |
|---|---|---|
| 合规性 | 官方明文许可 | 用户自账号，灰色但普遍容忍 |
| 能力 | 只能看到发给 bot 的消息；需 `privacy mode` 关闭才能看群消息 | 可见会话全量历史、任意群、可作"潜水观察" |
| 服务器 | Telegram 托管的 Bot API server（可用本地 local server 自建） | 直连 DC，需自备 session 存储 |
| 集成成本 | 低，webhook/getUpdates 两种 pull 模式 | 中高，需 api_id/api_hash、session 持久化、重连逻辑 |
| 封号风险 | 极低 | 中（账号级） |

对 DSH 伴侣场景，如果只需要「用户主动 @ 或私聊 bot → 触发 DSH 任务」，**Bot API 足够且更安全**。只有当需求升级为「读取我所有 TG 私聊/群作为上下文」时才需要 MTProto，此时应显式接受账号风险并考虑自建 local Bot API server 折中。

### 3.4 语言栈决定选择

DSH 本体是 TypeScript（`apps/web`、Vite、Node 生态）。据此：

- **若接入层写在 DSH 进程内** → grammY 是最自然的选择：TS 原生、类型与最新 Bot API 对齐（185 个方法）、每周 2.16M 下载、`@grammyjs/*` 插件生态（menu、router、i18n、webhook 等）。
- **若接入层是独立服务** → aiogram 更好：单文件异步 worker、内置 router/FSM（对话状态机对多步任务很有用）、Bot API 10.3 最新、月下载 2.76M。
- PTB 下载量最大（6.76M/月）但 API 落后到 10.0，且其 API 风格偏重；作为「求稳的大众选择」合格，但不是本项目最优。

---

## 4. Docker / NAS 虚拟机部署可行性

### 4.1 NapCat 官方 Docker 方案（已核实到 compose 级别）

`NapNeko/NapCat-Docker` 提供可直接使用的 compose（README 原文示例）：

```yaml
services:
  napcat:
    image: mlikiowa/napcat-docker:latest
    restart: unless-stopped
    environment:
      MODE: ws                      # 正向 WS；反向用 reverse_ws / reverse_http + ONEBOT_URL
      WEBUI_TOKEN: replace-with-your-own-token
    ports:
      - "127.0.0.1:6099:6099"       # WebUI
      - "127.0.0.1:3001:3001"       # OneBot WS
    volumes:
      - ./data/qq:/app/.config/QQ
      - ./data/config:/app/napcat/config
      - ./data/plugins:/app/napcat/plugins
```

Dockerfile 实测内容（关键）：基座 `mlikiowa/napcat-docker:base`，构建时按 `arch` 自动选 `linuxqq_3.2.34-53644_{amd64|arm64}.deb` 从 `qqdl.gtimg.cn` 下载并 `dpkg -i --force-depends`，然后改写 `/opt/QQ/resources/app/package.json` 的 `main` 指向注入脚本 `loadNapCat.js`。**即：容器内跑的是官方 QQ Electron 客户端 + 注入，不是纯协议。**

NAS 相关要点（均来自官方 README）：
- 支持 **Linux amd64 / arm64**，覆盖绝大多数 x86 NAS 与 ARM 型 NAS。
- **群晖专项**：「`NAPCAT_UID`、`NAPCAT_GID` 指定运行用户，挂载目录需允许该用户读写，**群晖还需设置共享目录 ACL**」——这是踩过坑的人写的，直接照做即可。
- 更新方式 `docker compose pull && docker compose up -d`，保留三个数据目录；生产环境建议把 `latest` 换成固定发布标签。
- 端口只绑 `127.0.0.1`，远程访问走 SSH 转发——这个默认姿态正好符合我们的安全要求。
- 调试用 `NAPCAT_ENABLE_COREDUMP=1`。
- 官方还预置了 AstrBot / Koishi / qq-ai-bot / sealdice / olivos / q2tg 等 compose 模板，说明这套镜像常被用作多框架底座。
- Linux 裸机（非 Docker）也有官方一键脚本 `NapCat-Installer`（apt/dnf，amd64/arm64，`--docker n --cli y`），并在文档里注明「系统仓库未提供 Xvfb 时使用 Docker」——反过来说明 Docker 路径正是为 headless 准备的。

### 4.2 LLBot Docker 方案

两条路：仓库自带 `docker/Dockerfile`（`node:24-alpine` + ffmpeg + tzdata，`TZ=Asia/Shanghai`，启动时从 GitHub Release 拉 `LuckyLillia.zip`，并只保留 musl 版 native 模块）＋ `script/install-llbot-docker.sh`；或社区镜像 `initialencounter/llonebot:latest`，compose 需挂 `./QQ:/root/.config/QQ` 与 `./llonebot:/root/llonebot`，暴露 3000(HTTP)/3001(WS)/5600(Satori)/3080(WebUI)。另有 `LLOneBot/llonebot.nix` 提供 Nix/Docker 部署。

**⚠️ 端口冲突**：LLBot WebUI 默认 **3080**，与本机 DSH Web GUI（`http://127.0.0.1:3080`）撞车。同机部署务必改映射。

### 4.3 资源与体积估算

| | NapCat（容器含 QQ Electron） | LLBot 无头（alpine + Node） |
|---|---|---|
| 镜像量级 | 大（Electron + Qt 依赖，GB 级） | 小（数十~百 MB 级） |
| 内存 | 常驻较高（GUI 运行时开销） | 较低 |
| NAS 适配 | 官方明确支持群晖 ACL，文档针对性强 | 轻量友好，但需自行确认无头模式稳定性 |
| 是否需要显示服务 | 容器内自带 headless 运行时；裸机需 Xvfb | 无头模式不需要 QQ 客户端 |

**判定**：NAS 虚拟机内存 ≥4GB 且以稳定为先 → NapCat；资源紧张或追求极简 → LLBot 无头模式。

---

## 5. 消息格式标准化程度（DSH 统一接入的关键）

三条可选抽象层，实测差异如下：

| 抽象层 | 代表 | 标准化程度 | 评价 |
|---|---|---|---|
| **OneBot 11** | NapCat、LLBot、go-cqhttp(遗产)、Koishi、NoneBot2、AstrBot | ★★★★ 生态最广 | 规范仓库 `botuniverse/onebot-11` 末次 push 2024-04-27，**标准已冻结**——但这恰恰是优点：不会再破坏性变更，且所有现役 QQ 协议端都实现它。消息模型是 array of segments `{type, data}`，同时兼容 CQ 码字符串形式。 |
| **Satori** | LLBot、Chronocat、Entari、Koishi | ★★★ 表达力更强 | 跨平台统一协议（设计上覆盖 TG/Discord 等），语义更现代。但 Chronocat 末次 push 2025-06-25、Entari 仅 38★，**QQ 之外的落地薄**。 |
| **Milky** | Lagrange、LLBot | ★★ 新兴 | 目前主要是 Lagrange 系生态，采用面窄。 |

**推荐决策：DSH 统一接入层锁定 OneBot 11。**

理由：
1. 现役两个候选协议端（NapCat、LLBot）**都完整实现 OB11**，切换协议端时 DSH 侧代码零改动——这是真正的可移植性保险。
2. OB11 的 segment 数组模型与 Telegram 的结构化实体（text + entities + photo/video/document + reply_parameters）**可以无损双向映射**，不需要引入第三种协议来"翻译"。
3. 标准冻结 = 不会某天被 breaking change 打穿；而 Satori 的跨平台愿景虽好，但 QQ 侧只有 LLBot 一家稳定供应该出口，等于用一个新锁定替换旧锁定。
4. 若将来需要 Satori 的表达力，LLBot 已内置 Satori 端口，可在**不改协议端**的前提下灰度迁移——保留退路。

**DSH 适配层的正确姿势**：定义内部规范化消息模型（normalized message），OB11 ↔ TG 各自只做一次映射；**严禁**业务逻辑直接使用 `napcat` 私有扩展 API（`group_poke`、`nc_get_rkey`、`get_mini_app_ark` 等），否则就被绑定到单一协议端。同时预留 OB11 的已知缺口处理（无 `lifecycle.enable/disable`，健康检查须靠 `heartbeat` + `get_status`）。

---

## 6. 最终选型推荐

### 6.1 推荐架构

```
                        ┌───────────────────────── NAS 虚拟机 (Docker) ─────────────────────────┐
  Telegram ──Bot API──▶ │  tg-adapter (grammY 或 aiogram)  ─┐                                   │
                        │                                  ├─▶ DSH 统一消息总线 (normalized)    │
  QQ ──OneBot 11──WS──▶ │  NapCat (reverse_ws → DSH)       ┘        ↕  鉴权 / 限流 / 注入过滤   │
     [备用: LLBot 无头]   │                                            ↕                          │
                        │                                              └──▶ DSH core (agent)     │
                        └───────────────────────────────────────────────────────────────────────┘
```

- **QQ 主选 NapCatQQ**：现役事实标准；OB11 全量兼容 + go-cqhttp 扩展兼容（迁移成本低）；官方 Docker 镜像含 amd64/arm64 与**群晖 ACL 专项说明**；一周三发的响应速度证明其能适应 QQ 客户端更新（这是生存能力的第一指标）；社区体量最大（11.4k★，仅 6 个 open issue，维护质量高）。
- **QQ 备选 LLBot**：commit 频率更高（100+/90d）、镜像轻量、**唯一同时提供 OB11+Satori+Milky 三出口**、有真正无头模式、WebUI 完善。作为「NapCat 被封/失修时的平移目标」价值极高，因为 OB11 接口一致。
- **TG 主选 grammY**（若接入层并入 DSH TS 进程）或 **aiogram**（若独立 Python worker）。两者 Bot API 覆盖度实测相当（185 vs 186 方法，均为最新 10.3 档）。
- **Telethon 仅作特定需求启用**：需要 userbot 级会话可见性时才用，并接受账号级风险；注意其仓库已迁 Codeberg。
- **明确排除**：go-cqhttp（官方放弃）、Mirai（停更+旧协议）、telegraf（2024-02 起停滞）。

### 6.2 分阶段落地建议

1. **P0**：DSH 侧实现 OB11 反向 WebSocket 服务端（DSH 主动监听，协议端外连进来）。选反向而非正向的三点好处：NAS 不必对外开端口、天然过 NAT、连接发起方是可信内网侧。
2. **P0**：NapCat 容器起来，`MODE=reverse_ws` + `ONEBOT_URL` 指向 DSH，端口仅绑 `127.0.0.1`，WebUI 强制设 `WEBUI_TOKEN`。
3. **P1**：grammY/aiogram adapter 接入，两侧消息归一到同一 normalized 模型。
4. **P1**：健康检查用 `heartbeat` + `get_status`（绕开 NapCat 不支持 `lifecycle.enable/disable` 的缺口）。
5. **P2**：把 LLBot 无头模式作为并行演练，验证「协议端可替换」这一假设真的成立。
6. **贯穿**：QQ 用小号；所有外部消息进入 agent 前做注入过滤（交给 t2 安全架构）。

---

## 7. 证据与验证

### 7.1 一手来源

| 来源 | 用途 |
|---|---|
| [NapNeko/NapCatQQ](https://github.com/NapNeko/NapCatQQ) | v4.18.41 (2026-10-21)、11,377★、69 commits/90d、README 用途与 license 限制 |
| [NapNeko/NapCat-Docker](https://github.com/NapNeko/NapCat-Docker) | compose 模板、`mlikiowa/napcat-docker`、群晖 ACL、Dockerfile 注入机制 |
| [NapCat 文档 · 请求接口兼容情况](https://napneko.github.io/develop/api) | OB11 全量 ✅、go-cqhttp 扩展、连接方式 |
| [NapCat 文档 · 消息格式](https://napneko.github.io/develop/msg) / [上报事件](https://napneko.github.io/develop/event) | segment 收发矩阵、JSON5、lifecycle 缺口 |
| [NapCat 文档 · Shell 安装](https://napneko.github.io/guide/boot/Shell) / [Framework](https://napneko.github.io/guide/boot/Framework) | amd64/arm64、Xvfb 与 Docker 关系、代理环境变量 |
| [LLOneBot/LuckyLilliaBot](https://github.com/LLOneBot/LuckyLilliaBot) | v8.3.2 (2026-10-12)、3,686★、100+ commits/90d、GPL-2.0、docker/Dockerfile |
| [LLBot 文档 · 什么是 LLBot](https://luckylillia.com/guide/introduction) / [配置](https://luckylillia.com/guide/config) | 有头 HOOK vs 无头纯协议、OB11/Satori/Milky 三协议、WebUI 3080 |
| [LLOneBot/llonebot.nix](https://github.com/LLOneBot/llonebot.nix) | `initialencounter/llonebot` compose 与端口 |
| [Mrs4s/go-cqhttp](https://github.com/Mrs4s/go-cqhttp) | README「已无力继续维护」、v1.2.0 (2023-10-09)、末次 commit 2024-05-09、314 open issues |
| [mamoe/mirai](https://github.com/mamoe/mirai) | 末次 push 2024-09-23 |
| [LagrangeDev/Lagrange.Core](https://github.com/LagrangeDev/Lagrange.Core) | nightly (2025-08-02)、19 commits/90d、license None |
| [botuniverse/onebot-11](https://github.com/botuniverse/onebot-11) | 规范目录结构、末次 push 2024-04-27 |
| [LonamiWebs/Telethon](https://github.com/LonamiWebs/Telethon) | `archived: true`、README「Moved to codeberg.org/Lonami/Telethon」 |
| PyPI `telethon-1.45.0` sdist | `telethon/tl/alltlobjects.py: LAYER = 229` |
| PyPI `python_telegram_bot-22.8` sdist | `src/telegram/constants.py: _BotAPIVersion(major=10, minor=0)` |
| PyPI `aiogram-3.31.0` sdist | `aiogram/__meta__.py: __api_version__ = "10.3"` |
| npm `grammy@1.46.0` / `@grammyjs/types@5.0.0` | 依赖锁定 types 5.0.0；方法清单 185 个，与 aiogram 186 逐一 diff 后等价 |
| pypistats / npm downloads API | PTB 6.76M/月、aiogram 2.76M/月、Telethon 3.01M/月、grammY 2.16M/周、telegraf 178k/周 |

### 7.2 未能验证（网络受限，不影响选型结论）

- **Docker Hub 镜像 tag 新鲜度**：`hub.docker.com/v2/repositories/{mlikiowa/napcat-docker,llonebot/llonebot}/tags` 返回空响应，无法确认 latest 标签的实际构建时间与多架构 manifest。**缓解**：已从两仓库源码读到 Dockerfile 与 CI workflow（`NapNeko/NapCat-Docker/.github/workflows/docker-publish.yml`、`LLOneBot/LuckyLilliaBot/.github/workflows/docker.yml`）证明流水线存在；上线前请在 NAS 上执行 `docker manifest inspect mlikiowa/napcat-docker:latest` 与 `docker images --digests` 自查，并按 §4.1 建议改用固定版本标签。
- **Telegram 官方 Bot API changelog**：`core.telegram.org`（含 `/bots/api`、`/bots/api-changelog`）在本机连接超时（curl http_code=000），web_fetch 同样失败。**缓解**：Bot API 版本改为从三个库的**源码常量**交叉取证（PTB 10.0 / aiogram 10.3 / grammY types 方法集等价于 aiogram），足以支撑「aiogram 与 grammY 均处于最新档」的结论；具体官方发布日期未核。
- **QQ 风控/封号率**：无任何可靠公开数据，本报告不做定量承诺（详见 §2.5）。
- **SnowLuma**：NapCat README 主动推荐的替代品，2.2k★ 且 push 到 2026-10-23，但其协议兼容面与 Docker 支持未展开调研，列为后续观察项。
- **匿名 GitHub API 限额**：本次曾打满 60 次/小时配额，恢复后已完成全部关键取证；如需追加大规模抓取建议配置 `GITHUB_TOKEN`。
