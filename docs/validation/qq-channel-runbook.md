# QQ 通道端到端打通 · 运行手册（t7）

目标链路：**白名单用户在 QQ 发消息 → NapCat（OneBot11 反向 WS）→ ingress 白名单授权 →
bot-core → DSH 生成回复 → 发回 QQ**，并要求同时观测“非白名单被拒 + 审计”。

## 0. 当前状态（本沙箱实测）

| 步骤 | 状态 | 说明 |
|---|---|---|
| 编排/网络/env 契约 | ✅ 与上游文档核对一致 | `MODE=reverse_ws` + `ONEBOT_URL`、`WEBUI_TOKEN`、`NAPCAT_UID/GID`、三个挂载目录（`/app/.config/QQ`、`/app/napcat/config`、`/app/napcat/plugins`）均与 `NapNeko/NapCat-Docker` README 一致；WebUI 容器端口 6099 → 宿主 `127.0.0.1:3081` |
| ingress 反向 WS 监听 | ✅ 已实测 | `127.0.0.1:3001` 已发布；`node scripts/ingress-e2e.mjs` 13/13（假适配器扮 NapCat，含 token 指纹、self_id 钉死、白名单拒绝、限流、审计无凭据） |
| 数据目录权限 | ✅ | `data/{qq,napcat-config,napcat-plugins}` 已建并 `chown 2100:2100`（上游明确要求挂载目录对运行用户可读写） |
| 镜像 digest 核验与固化 | ✅ 已完成（双源一致） | `v4.18.41@sha256:b101b8968cc31ae428ec0f8e117386e4ced7773b2d8226ed9f7ddfcec55f1b7e`，由 `docker buildx imagetools inspect` 与 Hub tag API 交叉核验一致，已写入 `deploy/compose.yaml`（commit `7c80935`）。**t3 G3 的 digest 门禁至此才算满足。** |
| **NapCat 启动 + 扫码登录** | ⏸ 等用户扫码 | 镜像拉取在宿主后台进行中；拉到位后按第 2 节 bring-up，停在扫码处等人工 |

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
#    deploy/.env: SELF_ID=<小号 QQ 号>
#    deploy/.env: TOKEN_FP=<sha256(access_token)>，access_token 本身不进 env
docker compose -f deploy/compose.yaml up -d --wait          # 先起核心四件
docker compose -f deploy/compose.yaml --profile qq up -d    # 再拉 NapCat
docker compose -f deploy/compose.yaml logs -f napcat        # 看登录二维码/URL
```

登录：打开 `http://127.0.0.1:3081/webui`（首次需要 `WEBUI_TOKEN` 里那个令牌），用小号扫码。
**这一步需要人工，agent 会在此停住并报告，不空转重试。**

在 WebUI 里确认 OneBot 网络设置为反向 WebSocket：
`ws://172.28.0.10:3001/onebot/v11/ws`（compose 的 `MODE/ONEBOT_URL` 只初始化缺失配置，
已有配置以 WebUI 为准），并设置 `access_token`（其 sha256 就是 `TOKEN_FP`）。

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

## 4. Telegram：明确 deferred（不在本任务范围）

`api.telegram.org` 从本机不可达（调研期已证实），因此 TG 通道整体标记 deferred：
适配器代码保留，`apps/gateway/test/telegram.test.mjs` 只在本地假 API 上跑（不联网），
`scripts/ingress-e2e.mjs` / `broker-e2e.sh` 不含任何 TG 联网项。README「已知限制」已记录。
