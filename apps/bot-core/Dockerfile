# bot-core: the DSH host container plus the companion plugin (t3 §3 "L4 agent 区").
#
# Two commands share this image:
#   * `node apps/bot-core/src/standalone.mjs` — the intake plane only (no model key
#     needed), which is what the default compose stack runs so the boundary can be
#     health-checked on a fresh host;
#   * `dsh --profile bot web ...` — the real agent loop, behind compose profile
#     `agent`, once the owner has mounted a provider credential.
FROM docker.m.daocloud.io/library/node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY apps/gateway/package.json ./apps/gateway/
COPY apps/memory-service/package.json ./apps/memory-service/
COPY apps/secret-broker/package.json ./apps/secret-broker/
COPY apps/bot-core/package.json ./apps/bot-core/
RUN npm ci --omit=dev --workspace=@dsh-bot/bot-core

FROM docker.m.daocloud.io/library/node:22-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
# Pinned harness version: `latest` would let the agent's own runtime move under us (G1).
RUN npm install -g @deepseek-ai/dsh@0.2.1-rc.2 && dsh --version
WORKDIR /app
ENV NODE_ENV=production
# Axiom 2 mitigation: the ephemeral HOME keeps .credentials.yaml out of any persistent mount.
ENV HOME=/run/user/10001 DSH_HOME=/home/bot/.dsh
COPY --from=deps /app/node_modules ./node_modules
COPY packages/bot-audit/package.json ./packages/bot-audit/
COPY packages/bot-audit/src ./packages/bot-audit/src
COPY packages/bot-hmac/package.json ./packages/bot-hmac/
COPY packages/bot-hmac/src ./packages/bot-hmac/src
COPY packages/bot-normalize/package.json ./packages/bot-normalize/
COPY packages/bot-normalize/src ./packages/bot-normalize/src
COPY packages/bot-sanitize/package.json ./packages/bot-sanitize/
COPY packages/bot-sanitize/src ./packages/bot-sanitize/src
COPY packages/bot-secrets/package.json ./packages/bot-secrets/
COPY packages/bot-secrets/src ./packages/bot-secrets/src
COPY apps/bot-core ./apps/bot-core
COPY deploy/profiles /etc/dsh-profile
RUN set -eux; useradd -u 10001 -m -s /bin/bash bot; mkdir -p /run/user/10001 /home/bot/.dsh /rw/work; chown -R 10001:10001 /app /run/user/10001 /home/bot /rw/work
USER 10001:10001
EXPOSE 3005 3080
HEALTHCHECK --interval=15s --timeout=4s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8185/healthz || exit 1
CMD ["node", "apps/bot-core/src/standalone.mjs"]
