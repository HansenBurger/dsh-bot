# QQ 通道端到端打通 · 运行手册（t7）

目标链路：**白名单用户在 QQ 发消息 → NapCat（OneBot11 反向 WS）→ ingress 白名单授权 →
bot-core → DSH 生成回复 → 发回 QQ**，并要求同时观测“非白名单被拒 + 审计”。

## 0. 当前状态（本沙箱实测）

| 步骤 | 状态 | 说明 |
|---|---|---|
| 编排/网络/env 契约 | ✅ 与上游文档核对一致 | `MODE=reverse_ws` + `ONEBOT_URL`、`WEBUI_TOKEN`、`NAPCAT_UID/GID`、三个挂载目录（`/app/.config/QQ`、`/app/napcat/config`、`/app/napcat/plugins`）均与 `NapNeko/NapCat-Docker` README 一致；WebUI 容器端口 6099 → 宿主 `127.0.0.1:3081` |
| ingress 反向 WS 监听 | ✅ 已实测 | `127.0.0.1:3001` 已发布；`node scripts/ingress-e2e.mjs` 13/13（假适配器扮 NapCat，含 token 指纹、self_id 钉死、白名单拒绝、限流、审计无凭据） |
| 数据目录权限 | ✅ | `data/{qq,napcat-app,napcat-config,napcat-plugins}` 存在且属主与 `NAPCAT_UID` 一致（现为 1000:1000；上游要求挂载目录对运行用户可读写，属主不一致会让登录服务反复重置） |
| 镜像 digest 核验与固化 | ✅ 已完成（双源一致） | `v4.18.41@sha256:b101b8968cc31ae428ec0f8e117386e4ced7773b2d8226ed9f7ddfcec55f1b7e`，由 `docker buildx imagetools inspect` 与 Hub tag API 交叉核验一致，已写入 `deploy/compose.yaml`（commit `7c80935`）。**t3 G3 的 digest 门禁至此才算满足。** |
| **NapCat 启动 + 扫码登录** | ✅ 已完成 | 小号 `207346792` 一次性人工扫码登录；之后容器重建走 `ACCOUNT` 快速登录，会话保存在 `data/qq` |
| **真实 QQ 端到端** | ✅ 已完成 | 主人私信 → echo 回执回到真实 QQ；陌生号私信被 default-deny 拒绝。逐条证据见第 3.5 节 |
| 记忆链路（真实 QQ 驱动） | ⚠ 不在 echo 口径内 | `BOT_CORE_MODE=echo` 不调模型，也就不会走 `memory_write`；真实消息不产生记忆写入（实测 L1 真号 peer 行数 0）。记忆子系统对真存储 24/24 |

第 1 步失败的真实根因不是网络，而是**任务书里那个 tag 不存在**：`mlikiowa/napcat-docker`
没有 `0.01.11` 这个 tag（此前所有 `not found`/超时都掩盖了这一点），当前真实 tag 是
`v4.18.41`（2026-10-21 推送，amd64+arm64）。路由器级代理开启后 registry 可达，digest
按两条独立来源核验后固化——没有编造任何 hex 串。

## 1. digest 复核（升级或改 compose 后跑一次）

```bash
bash scripts/verify-napcat-digest.sh            # 打印 tag 背后的 digest
bash scripts/verify-napcat-digest.sh --pin      # 打印并写回 deploy/compose.yaml
```

等价手工命令（任选其一，默认 tag 已是 `v4.18.41`）：

```bash
docker buildx imagetools inspect mlikiowa/napcat-docker:v4.18.41   # 看 Digest: sha256:…
crane digest mlikiowa/napcat-docker:v4.18.41
skopeo inspect --format '{{.Digest}}' docker://mlikiowa/napcat-docker:v4.18.41
```

compose 里的形态：`image: mlikiowa/napcat-docker:v4.18.41@sha256:b101b896…`。

## 2. 启动 NapCat 并登录小号

```bash
# 1) WebUI 令牌（>=32 字节，只用于协议侧管理面）
export NAPCAT_WEBUI_TOKEN="$(head -c 32 /dev/urandom | base64 | tr -d '\n=' | cut -c1-43)"
python3 - <<'PY'   # 写入 deploy/.env（compose 会读它）
import pathlib,re
p=pathlib.Path('deploy/.env'); s=p.read_text()
s=re.sub(r'^NAPCAT_WEBUI_TOKEN=.*$', f'NAPCAT_WEBUI_TOKEN={__import__("os").environ["NAPCAT_WEBUI_TOKEN"]}', s, flags=re.M)
p.write_text(s)
PY

# 2) 反向 WS 的目标与令牌指纹必须与 ingress 一致
#    deploy/.env: SELF_ID=<小号 QQ 号>（扫码登录后从 heartbeat/lifecycle 读出来回填）
#    deploy/.env: TOKEN_FP=<sha256(access_token)>，access_token 本身不进 env
#    已就位：deploy/secrets/napcat-ob11-access-token（0600，gitignored）= 新生成的 43 字符
#    强随机 token；deploy/.env 的 TOKEN_FP 已换成它的 sha256（原型占位指纹作废）。
#    取回明文：cat deploy/secrets/napcat-ob11-access-token   （只填进 NapCat 配置）
docker compose -f deploy/compose.yaml up -d --wait          # 先起核心四件
docker compose -f deploy/compose.yaml --profile qq up -d    # 再拉 NapCat
docker compose -f deploy/compose.yaml logs -f napcat        # 看登录二维码/URL
```

登录：打开 `http://127.0.0.1:3081/webui`（口令 = `deploy/.env` 里的 `NAPCAT_WEBUI_TOKEN`），用小号扫码。
**这一步需要人工，agent 会在此停住并报告，不空转重试。**

在 WebUI 里确认 OneBot 网络设置为反向 WebSocket：
`ws://172.28.0.10:3001/onebot/v11/ws`（compose 的 `MODE/ONEBOT_URL` 只初始化缺失配置，
已有配置以 WebUI 为准），`access_token` 填上面那个文件里的明文。改完 token 需要
`docker compose restart ingress`（指纹在启动时读入 env）。

**验收口径（captain 21:12 确认）**：t7 = echo 模式下的真实传输链——真 QQ 消息进出、
白名单判决、审计、`send_private_msg` 到达真实 QQ；回复正文是固定 ack 文本。
**不接 LLM**：`BOT_CORE_MODE` 保持 `echo`，模型链路是后续独立任务。

## 2.5 本次 bring-up 的实测结论（21:37–21:45，容器已就绪等扫码）

起栈踩到的两个坑与修法（详见 commit `ee994c2`）：

1. **不能给 napcat 写 `user: "2100:2100"`**。上游 `entrypoint.sh` 自己降权
   （`usermod` + `chown -R` + `gosu napcat`），且 `/app/NapCat.Shell.zip` 在镜像里是
   `0600 root:root`：以 2100 启动连安装载荷都读不到，直接 crash-loop。
2. **read-only rootfs 挡住解压**：`unzip -d ./NapCat.Shell` 需要可写目录 → 给它挂 tmpfs，
   安装产物落 `data/napcat-app`。
3. `cap_drop: [ALL]` 下的 root **没有 CAP_DAC_OVERRIDE**，也就是照样受普通文件权限约束：
   安装目录必须让 uid 0 可写（`data/napcat-app`、`data/qq` 置 1777，
   `data/napcat-config` 置 `a+rwX`），否则报 `cp: ... Permission denied`。
   安装完 entrypoint 会把它们 chown 给应用用户。
4. **镜像声明了 `VOLUME /app/napcat/config`**：不显式绑宿主目录时，每次重建都会换一个匿名卷，
   反向 WS 的 url/token 就得重填。已显式绑 `data/napcat-config`。

**已核对到的偏差（要如实记录）**：`NAPCAT_UID/NAPCAT_GID=2100` 没有生效。原因是
`/etc` 在 read-only rootfs 下不可写，`usermod` 改不动 passwd 条目，于是
`gosu napcat` 落在镜像内建的 **uid 1000**（容器内 `ps` 实测 `1000 napcat qq`）。
这与 t3 基线里「协议容器以 2100 运行」不完全一致。当前缓解：容器只挂了
`data/{qq,napcat-app,napcat-config,napcat-plugins}` 四个目录，宿主工作区与
`deploy/secrets/*`（0600，uid 1000）**不在挂载里，容器读不到**；降权本身有效（不是 root）。
彻底修法是自建派生镜像（预置 passwd 条目）并重新固定 digest，属后续任务，不在 t7 范围。

反向 WS 已经预配好，不需要在 WebUI 手填：`MODE=reverse_ws` + `ONEBOT_URL` 让上游把
`ws://172.28.0.10:3001/onebot/v11/ws` 写进了 `data/napcat-config/onebot11.json`
（实测文件内容确认），我再把 `deploy/secrets/napcat-ob11-access-token` 的明文写进同一份配置的
`token` 字段——**这是 t7 里唯一一次让明文 token 落到 NapCat 侧配置**，ingress 只持 sha256 指纹。
登录完成后如果 NapCat 生成的是 `onebot11_<QQ号>.json`，需要确认该文件的 url/token 一致
（登录后我实测并记录）。

扫码就绪信号：容器 `Up`、WebUI `http://127.0.0.1:3081/webui?token=<NAPCAT_WEBUI_TOKEN>` 返回 200，
日志停在 `[Core] [Login] 登录服务已断开，将允许重新获取二维码`。
**注意：NapCat 会把 WebUI token 明文打进容器日志**（上游行为，无法在不改镜像的前提下关闭），
所以 `docker compose logs napcat` 属于敏感输出。

## 3. 打通判定（白名单 + 非白名单 + 记忆）

`deploy/whitelist.json` 里先准备好小号与一个陌生人 id：

```bash
# a) 白名单：用小号给“机器人号”发一条私信
#    期望：ingress 审计 authz.decision result=allowed role=owner，机器人回复到达 QQ
# b) 非白名单：用另一个号发一条
#    期望：机器人不回话，审计出现 reason=not-whitelisted（只有结构化 id，无昵称）
tail -n 20 logs/ingress.jsonl | python3 -c "
import sys,json
for l in sys.stdin:
    d=json.loads(l)
    print(d.get('type'), d.get('stage'), d.get('result'), d.get('role'), d.get('reason'), d.get('structuredIds'))"

# c) 记忆链路：连发两条（先“记住我不吃香菜”，再问“我吃香菜吗”）
docker compose -f deploy/compose.yaml exec -T memory node --input-type=module < scripts/memory-e2e.mjs
# L1 在 memory 容器的命名卷里（宿主不直接可见）：
docker compose -f deploy/compose.yaml exec -T memory sqlite3 /var/lib/dshbot/memory/l1.db \
  'select peer_key, slot, updated_at from context_entry order by updated_at desc limit 5;'
```

验收证据格式（贴进 PR 或本文件末尾）：

```
[QQ 实发] 20:xx:xx  小号 100012345 → 机器人：「记住我不吃香菜」
[DSH 回复] 20:xx:xx  机器人 → 小号：「<模型文本>」
[审计] {"type":"authz.decision","stage":"gate","role":"owner","result":"allowed"}
[审计] {"type":"authz.decision","stage":"gate","result":"denied","reason":"not-whitelisted","structuredIds":true}
[记忆] memory-e2e 24/24；memory_access_log: write/read/search 记录齐全
```

## 3.5 已实测的网络半程证据（容器内扮演适配器）

从 `bot-net-protocol` 内的容器（NapCat 将来所在的网络位置）拨 ingress 的真实地址，
而不是宿主 loopback：

```bash
timeout 240 docker run --rm --network bot-net-protocol -v $PWD:/host:ro -w /host \
  -e E2E_OB11_URL=ws://172.28.0.10:3001 docker.m.daocloud.io/library/node:22-slim \
  node --no-warnings scripts/ingress-e2e.mjs
```

实测 **13/13 通过**（20:48 左右）：错误 access_token → 关闭码 1008 + `token-fingerprint-mismatch`
审计；伪 `self_id` → 1008；非白名单 `user_id=999999999` → 0 次上游调用 +
`reason=not-whitelisted` 审计 + 不落昵称；owner 私信 → `send_private_msg` 回程帧；
文本里自称主人不改变判决；连发 14 条触发 `ratelimit.exceeded`；审计文件无凭据。

**这条证据的边界要诚实说明**：扮演 NapCat 的仍是脚本，不是真 QQ 账号。它证明
“反向 WS 通路 + 白名单判决 + 回程动作”在真实网络位置上可用，不证明腾讯侧的
登录/风控/消息格式细节——那需要第 2 节的人工扫码。

## 3.5 真实 QQ 端到端证据（2026-10-24，小号 207346792）

**NapCat 自己的收发日志（腾讯侧真实账号，非脚本扮演）**：

```text
10-24 22:15:54 [info] 汉森Burger | 接收 <- 私聊 (1035376945) 你好
10-24 22:15:54 [info] 汉森Burger | 发送 -> 私聊 (1035376945) 收到（prototype intake，未调用模型）：你好
10-24 22:40:36 [info] 汉森Burger | 接收 <- 私聊 (952010048) 请求添加你为好友
```

**同一时刻的 ingress 审计（`logs/ingress.jsonl`）**：

```json
{"ts":1792851354…,"type":"authz.decision","stage":"gate","peerKind":"dm","role":"owner","result":"allowed"}
{"ts":1792851354…,"type":"authz.decision","stage":"submit","result":"allowed","status":200,"ms":23,"role":"owner"}
{"ts":1792852836…,"type":"authz.decision","stage":"gate","peerKind":"dm","role":null,"result":"denied","reason":"not-whitelisted","structuredIds":true}
{"ts":1792852915…,"type":"authz.decision","stage":"gate","peerKind":"dm","role":null,"result":"denied","reason":"not-whitelisted","structuredIds":true}
```

对应关系是逐秒吻合的：`22:15:54` 白名单 owner 放行并以 HTTP 200 提交到 bot-core，回程帧
`send_private_msg` 由 NapCat 落进上一条日志；`22:40:36`/`22:41:55` 是真实陌生号私信，
判决 `denied reason=not-whitelisted`，**其后没有任何 `submit` 审计行**，即零次上游调用；
`structuredIds:true` 说明判决只用 `(channel, chat_id, user_id)`，昵称「请求添加你为好友」
这类展示字段没有参与授权，也没被写进审计。

**用户侧确认**：用户收到回复原文「收到（prototype intake，未调用模型）：你好」。

**登录态跨重建验证**：回退 WebUI 端口后容器重建，日志出现
`正在快速登录 207346792`，审计随后 `connected`（socket `172.28.0.20:n66w1a`）且无
`self-id-mismatch`。注意 `ACCOUNT` 必填（compose 里从 `SELF_ID` 插值）：不传时镜像永远展示
新二维码，`data/qq` 里保存的凭据根本不参与登录。

**记忆链路的诚实边界**：echo 口径下模型不参与，`memory_write` 工具不会被调用，所以两条真
QQ 消息**不会**写入记忆（实测 `context_entry` 中真号 peer 行数 0，仅有一条 19:44 原型 peer
的历史行）。记忆子系统对真存储的读写用 `scripts/memory-e2e.mjs` 在容器内实测 **24/24**
（SQLite L1 + 宿主 PG：写/读/中文检索/审批删除/墓碑/访问账本）。“真实 QQ 消息驱动记忆”
要等接上模型的那条后续任务。

## 4. Telegram：明确 deferred（不在本任务范围）

`api.telegram.org` 从本机不可达（调研期已证实），因此 TG 通道整体标记 deferred：
适配器代码保留，`apps/gateway/test/telegram.test.mjs` 只在本地假 API 上跑（不联网），
`scripts/ingress-e2e.mjs` / `broker-e2e.sh` 不含任何 TG 联网项。README「已知限制」已记录。
