# 端口审计 · 宿主监听清单与上线门禁可过性（t2 交付物）

> 角色：backend-engineer · 采集时间：2026-10-24 17:1x（Asia/Shanghai）· 主机：`burger`（NAS VM，Ubuntu 24.04）
> 起因：t1 附带发现（F-7）——宿主存在多个非 loopback 监听，与 t3 `deploy §2` 的 `assert-listeners.sh` **期望集**冲突，上线门禁在真实宿主上会红。captain 已将梳理列为本任务的显式子任务。
> 本文只做**事实梳理 + 处置建议**；任何改绑/关停都是宿主级变更，需 owner 单独批准，不在 t2 内执行。

---

## 1. 结论先行

| 问题 | 回答 |
|---|---|
| t3 的门禁脚本能在本机通过吗？ | **不能**。脚本要求"所有监听都在 loopback 且端口 ∈ 期望集"，实测有 **19 个非 loopback 监听**（下表），全部早于本项目存在 |
| 这些监听是本项目造成的吗？ | **不是**。逐条取证到进程/容器，均为既有服务（Docker 应用栈、MySQL、Jellyfin、open-webui、TTS 桥等） |
| 大肥鱼自身引入的新监听是什么？ | 仅 `127.0.0.1:3001`（ingress OB11）、`127.0.0.1:8190`（memory 管理面），协议端 WebUI 3081/3082 默认 profile 不启用 |
| 门禁怎么改才既可用又不自我欺骗？ | **拆两级**：① `assert-project-listeners.sh`（严格，只断言本项目端口集合，可立即通过并纳入 CI）；② `assert-host-baseline.sh`（漂移基线，把既有 19 条冻结为快照，新增即告警）。二者都保留，不放宽绑址原则 |
| 最危险的既有条目 | `0.0.0.0:3306` / `33060`（MySQL 对 LAN 全开）、`0.0.0.0:8090`（open-webui 无 TLS 的管理面）——它们与本项目无关，但**扩大了同一台机器上任何被入侵服务的可达面** |

一句话：**门禁本身没错，错在它假设了一个"干净宿主"**。修正方式是让它区分"我们引入的"和"本来就有的"，而不是把期望集改成一个大白名单来蒙绿。

---

## 2. 实测原始数据（全部为本次执行的命令输出）

```bash
$ ss -ltnH | awk '{print $4}' | sed 's/^*/0.0.0.0/' | sort -u | wc -l
38
$ docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Ports}}'      # 9 个容器，8 个发布端口
$ systemctl list-units --type=service --state=running             # 31 个运行中服务
$ sudo -n ss -ltnp "sport = :3306"                                # pid=553733 → /usr/sbin/mysqld
$ ls /usr/share/postgresql/16/extension/ | grep vector            # 空（pgvector 未安装，与 t1 §1.4 一致）
```

### 2.1 非 loopback 监听（19 条，逐条归属）

| 端口 | 绑址 | 归属 | 证据 | 类别 | 建议 |
|---|---|---|---|---|---|
| 22 | 0.0.0.0 / :: | `ssh.service` | systemd | 必需运维入口 | **保留**（owner 经 SSH，隧道依赖它） |
| 3000 | 0.0.0.0 / :: | Docker `lanraragi`（difegue/lanraragi） | `docker ps` 端口表 | 既有应用 | 建议改绑 `127.0.0.1:3000` |
| 3306 | 0.0.0.0 | `/usr/sbin/mysqld`（`mysql.service`） | pid 553733 cmdline | **数据库对 LAN 全开** | ⚠ 高优先：`bind-address=127.0.0.1` 或防火墙限源 |
| 33060 | 0.0.0.0 | 同上（MySQL X Plugin） | pid 553733 | 数据库管理口 | ⚠ 同上，通常可直接关闭 X Plugin |
| 33135 | 0.0.0.0 | `node`（pid 583809，DSH 相关进程） | `/proc/*/cmdline` | 运行时临时口 | 归入漂移基线监控 |
| 34017 | 0.0.0.0 | `node`（pid 580925） | `/proc/*/cmdline` | 运行时临时口 | 同上 |
| 38583 | 0.0.0.0 | `node …/ollama-mcp`（pid 554040） | `/proc/*/cmdline` | MCP 桥 | 建议改绑 loopback |
| 5000 | 0.0.0.0 / :: | Docker `qwbot-web`（qwbot:latest） | `docker ps` | 既有应用 | 建议改绑 loopback |
| 8000 | 0.0.0.0 / :: | Docker `portainer`（8000→9000 入口） | `docker ps` | **容器管理面板** | ⚠ Portainer 等同 docker.sock 权限，建议限源网段 |
| 8081 | 0.0.0.0 / :: | Docker `metatube-server` | `docker ps` | 既有应用 | 建议改绑 loopback |
| 8085 | 0.0.0.0 / :: | Docker `reader`（hectorqin/reader） | `docker ps` | 既有应用 | 建议改绑 loopback |
| 8090 | 0.0.0.0 | `open-webui serve`（pid 553663） | cmdline `--host 0.0.0.0` 隐含 | **AI 管理面无 TLS** | ⚠ 高优先：改绑 loopback 或加 TLS |
| 8096 | 0.0.0.0 | `jellyfin`（pid 553632） | cmdline | 媒体服务（LAN 用途明确） | 若为家庭流媒体可**保留**，但须进基线 |
| 8188 | 0.0.0.0 / :: | Docker `comfyui` | `docker ps` | 既有应用 | 建议改绑 loopback |
| 9000 | 0.0.0.0 / :: | Docker `portainer`（edge agent） | `docker ps` | 容器管理 | 同 8000 |
| 9966 | 0.0.0.0 | ChatTTS 桥（pid 553703，uvicorn `--host 0.0.0.0`） | cmdline 明示 | TTS | 建议改绑 loopback |
| 9967 | 0.0.0.0 | MeloTTS 桥（pid 553681，uvicorn `--host 0.0.0.0`） | cmdline 明示 | TTS | 建议改绑 loopback |
| 9998 | 0.0.0.0 / :: | Docker `tika` | `docker ps` | 文档解析 | 建议改绑 loopback |
| 9999 | 0.0.0.0 / :: | Docker `stash` | `docker ps` | 既有应用 | 建议改绑 loopback |

### 2.2 loopback 监听（合规，无需处置）

| 端口 | 归属 | 与本项目关系 |
|---|---|---|
| 127.0.0.1:5432 / `[::1]:5432` | `postgres 16/main`（pid 553679） | ✅ 正是 t1 §9.3 方案 A 依赖的现状：**已是 loopback-only，C-1 满足** |
| 127.0.0.1:3080 | `node`（pid 583753，DSH Web GUI） | ✅ 本项目沿用，端口分配表已避让 |
| 127.0.0.1:11434 | `ollama serve`（pid 918） | 二期 embedding 候选（t1 R-7），一期不使用 |
| 127.0.0.1:8100 | `mcpo --host 127.0.0.1`（pid 553692） | 无关，合规 |
| 127.0.0.1:42343 | `codex`（pid 580685） | 无关，合规 |
| 127.0.0.1:8888 | jupyter（pid 553695） | 无关，合规 |
| 127.0.0.53/54:53 | `systemd-resolved` | 系统 DNS stub，合规 |

### 2.3 与 t1/t3 既有断言的一致性核对

| 上游断言 | 本次复核 | 结论 |
|---|---|---|
| t1 §1.4「Host PG = 16.15，监听 127.0.0.1:5432」 | `ss` + `/proc` 双重确认 | ✅ 一致，方案 A 前提成立 |
| t1 §1.4「pgvector 未安装」 | `ls …/extension/ \| grep vector` → 空 | ✅ 一致，一期 byte-trigram GIN 路线不变 |
| t1 §1.4「宿主已有 0.0.0.0:8090，memory-service 避开 8090」 | 8090 = open-webui，确实在用 | ✅ 本实现内部端口取 **8091**，管理面 **8190**（未被占用） |
| t3 deploy §2 期望集 `3001/3080/3081/3082` | 3081/3082 当前未监听（协议端默认 profile 关闭） | ⚠ 期望集需按"启用的 profile"动态化，见 §4 |

---

## 3. 风险分级（为什么不能只是"加白名单让它变绿"）

1. **`0.0.0.0:3306` + `33060`（MySQL）** — 与本项目无关，但它意味着：任何拿到 NAS 网络位置的设备都能尝试认证。一旦大肥鱼的 agent 被注入诱导去探测内网（t2 TM-008 SSRF 类），MySQL 就是现成靶子。**egress-proxy 的 `blocked_net` 规则挡得住容器出网，挡不住宿主自身的服务暴露**。
2. **`0.0.0.0:8000/9000`（Portainer）** — 等价于把 docker.sock 放到 LAN。t2 基线 B3「不给任何容器挂 docker.sock」的强度，会被这个宿主级入口完全绕过。这是**唯一一条能让本项目全部容器隔离努力失效的既有边**。
3. **`0.0.0.0:8090`（open-webui）** — 无 TLS 的管理面，含凭据登录页；同时它是 memory-service 必须避开 8090 的原因。
4. 其余（3000/5000/8081/8085/8188/9998/9999/9966/9967/38583）属"不必要的暴露"，风险等级中低，但同样应改绑 loopback。

**因此**：上线门禁必须继续对**本项目**端口保持严格（C-1 不可谈判），同时把宿主既有暴露作为**独立跟踪项**报告给 owner，而不是混在一个期望集里互相稀释。

---

## 4. 门禁改造方案（本任务已落地）

原脚本单条断言 → 拆成两条互补断言：

### 4.1 `deploy/scripts/assert-project-listeners.sh`（严格，CI 可跑）

只断言"本项目应当存在的监听集合"，且**每一个都必须绑在 127.0.0.1**：

| 场景 | 期望集合 |
|---|---|
| S2′ 起步（协议端未起） | `127.0.0.1:3001`（ingress）、`127.0.0.1:3080`（DSH GUI）、`127.0.0.1:8190`（memory 管理面） |
| + napcat profile | 追加 `127.0.0.1:3081` |
| + llbot profile | 追加 `127.0.0.1:3082` |

额外断言：这三者之外**不得出现任何由本项目容器发布的宿主端口**（用 `docker ps --format '{{.Ports}}'` 与本项目的 compose project 名比对，而非扫全网）。这样既不会被宿主噪声干扰，也不会漏掉我们自己多开的口。

### 4.2 `deploy/scripts/assert-host-baseline.sh`（漂移检测，运维日常）

把 §2.1 的 19 条非 loopback 监听固化为 `deploy/config/host-listener-baseline.txt`，每次上线前 diff：

- 新增条目 → 失败（可能是本项目误开，也可能是第三方软件改了绑址）
- 消失条目 → 警告（服务停了，或被人收紧了，需要更新基线）

这正是 t2 基线 **E5「非 loopback 监听」检测信号**与 **C9「每日 diff 监听口快照」**的具体实现，把原本会"永远红"的门禁变成"变化才红"。

### 4.3 为什么两个都保留

`t3 deploy §2` 的原脚本隐含前提是"这台机器只跑大肥鱼"。现实是一台共享 NAS VM。合并成一个脚本必然要在"严格"和"能过"之间牺牲一个；拆开后各自都能保持自己的强度：项目侧零容忍，宿主侧只管变化。

---

## 5. 交给 owner 的处置建议（按性价比排序，**本任务不执行**）

| 优先级 | 动作 | 影响 | 回滚成本 |
|---|---|---|---|
| P0 | Portainer 改绑 `127.0.0.1:8000/9000`，经 SSH 隧道访问 | 关掉通往 docker.sock 的 LAN 入口 | 一行 compose 改动 |
| P0 | MySQL `bind-address=127.0.0.1`，或 `ufw limit from <LAN>/24 to any port 3306,33060` | 数据库不再对 LAN 认证开放 | 配置文件一行 + restart |
| P1 | open-webui 改 `--host 127.0.0.1` 或前置 TLS 反代 | 管理面不再明文暴露 | 启动参数一处 |
| P1 | 其余 Docker 应用统一 `127.0.0.1:` 前缀（3000/5000/8081/8085/8188/9998/9999） | 减少 8 个 LAN 入口 | 各 compose 一处 |
| P2 | ChatTTS/MeloTTS/ollama-mcp 改绑 loopback | 减少 3 个 LAN 入口 | systemd unit / 启动参数 |
| P2 | Jellyfin 8096 若确为家庭流媒体则保留，写入基线并注明理由 | 有意暴露，需记录 | — |

> 上述任何一项都会改变现有用户体验，必须由 owner 决定；本项目只负责让"没处理"这件事变得可见（§4.2 的漂移门禁 + 本报告）。

---

## 6. 本项目自身的端口纪律（实现期自检结果）

| 检查 | 结果 |
|---|---|
| compose 中所有宿主端口映射带 `127.0.0.1:` 前缀 | ✅ 见 `deploy/compose.yaml`（3001/3080/8190/3081/3082 全部 loopback 前缀） |
| 不与宿主既有监听冲突 | ✅ 8091 内部口不发布；8190 管理面未被占用；3001/3081/3082 空闲 |
| broker / proxy / memory 内部服务不发布宿主端口 | ✅ 仅 internal 网络内可达 |
| PG 仍 loopback-only，未因本项目改配置 | ✅ 本任务**未修改**宿主 `postgresql.conf` / `pg_hba.conf`（改宿主配置属高危，留给 t5 运维窗口，脚本见 `deploy/scripts/init-host-db.sh`） |

---

## 7. 复现命令

```bash
# 全量监听快照
ss -ltnH | awk '{print $4}' | sed 's/^*/0.0.0.0/' | sort -u

# 归属取证（部分需 root）
sudo -n ss -ltnp | sort -u
docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Ports}}'
systemctl list-units --type=service --state=running --no-pager

# 本项目门禁
bash deploy/scripts/assert-project-listeners.sh
bash deploy/scripts/assert-host-baseline.sh

# 端口占用查询（新增服务前必查）
for p in 3001 3081 3082 8091 8190; do printf "%s: " "$p"; ss -ltnH "sport = :$p" | wc -l; done
```
