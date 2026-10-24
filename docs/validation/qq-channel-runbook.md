# QQ 通道端到端打通 · 运行手册（t7）

目标链路：**白名单用户在 QQ 发消息 → NapCat（OneBot11 反向 WS）→ ingress 白名单授权 →
bot-core → DSH 生成回复 → 发回 QQ**，并要求同时观测“非白名单被拒 + 审计”。

## 0. 当前状态（本沙箱实测）

| 步骤 | 状态 | 说明 |
|---|---|---|
| 编排/网络/env 契约 | ✅ 与上游文档核对一致 | `MODE=reverse_ws` + `ONEBOT_URL`、`WEBUI_TOKEN`、`NAPCAT_UID/GID`、三个挂载目录（`/app/.config/QQ`、`/app/napcat/config`、`/app/napcat/plugins`）均与 `NapNeko/NapCat-Docker` README 一致；WebUI 容器端口 6099 → 宿主 `127.0.0.1:3081` |
| ingress 反向 WS 监听 | ✅ 已实测 | `127.0.0.1:3001` 已发布；`node scripts/ingress-e2e.mjs` 13/13（假适配器扮 NapCat，含 token 指纹、self_id 钉死、白名单拒绝、限流、审计无凭据） |
| 数据目录权限 | ✅ | `data/{qq,napcat-config,napcat-plugins}` 已建并 `chown 2100:2100`（上游明确要求挂载目录对运行用户可读写） |
| **镜像 digest 核验** | ❌ **本机不可达** | `docker manifest inspect` 连 `registry-1.docker.io` 超时；daocloud 镜像站对该命名空间回 `denied`；USTC 镜像站无响应；直连 `docker pull mlikiowa/napcat-docker:0.01.11` 亦超时 |
| **NapCat 启动 + 扫码登录** | ⏸ 等用户 | 需要 (a) 能拉镜像的网络，(b) 用户用小号扫码 |

未伪造任何 digest：`deploy/compose.yaml` 里 NapCat 仍是 `mlikiowa/napcat-docker:0.01.11`，
并在注释里写明核验命令与原因。**t3 G3 的 digest 门禁在 --pin 之后才算满足。**

## 1. 用户/运维侧一条命令核验并固化 digest

在能访问 Docker Hub 的机器上：

```bash
bash scripts/verify-napcat-digest.sh            # 只打印
bash scripts/verify-napcat-digest.sh --pin      # 打印并写回 deploy/compose.yaml
```

等价的手工命令（任选其一）：

```bash
docker buildx imagetools inspect mlikiowa/napcat-docker:0.01.11   # 看 Digest: sha256:…
crane digest mlikiowa/napcat-docker:0.01.11
skopeo inspect --format '{{.Digest}}' docker://mlikiowa/napcat-docker:0.01.11
```

拿到后 compose 应长成：`image: mlikiowa/napcat-docker:0.01.11@sha256:<64hex>`。

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

## 4. Telegram：明确 deferred（不在本任务范围）

`api.telegram.org` 从本机不可达（调研期已证实），因此 TG 通道整体标记 deferred：
适配器代码保留，`apps/gateway/test/telegram.test.mjs` 只在本地假 API 上跑（不联网），
`scripts/ingress-e2e.mjs` / `broker-e2e.sh` 不含任何 TG 联网项。README「已知限制」已记录。
