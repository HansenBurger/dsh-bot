# ingress gateway (t3 §3 "L2 接入区"). Build context is the repository root because
# @dsh-bot/bot-* are workspace packages this service imports.
FROM docker.m.daocloud.io/library/node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY apps/gateway/package.json ./apps/gateway/
COPY apps/memory-service/package.json ./apps/memory-service/
COPY apps/secret-broker/package.json ./apps/secret-broker/
COPY apps/bot-core/package.json ./apps/bot-core/
RUN npm ci --omit=dev --workspace=@dsh-bot/gateway

FROM docker.m.daocloud.io/library/node:22-slim
# The image carries no credential material and no build tooling (B2).
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production
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
COPY apps/gateway/package.json ./apps/gateway/
COPY apps/memory-service/package.json ./apps/memory-service/
COPY apps/secret-broker/package.json ./apps/secret-broker/
COPY apps/bot-core/package.json ./apps/bot-core/
COPY apps/gateway/src ./apps/gateway/src
# Source checkouts sometimes carry 0600 modes (umask 077), and BuildKit preserves them
# while root-owning the copies — which would make the runtime uid unable to read its own
# app tree. Normalize once here instead of debugging an EACCES at container start.
RUN chmod -R a+rX /app
USER node
EXPOSE 3001
# healthcheck hits the admin endpoint on loopback only (C1).
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8181/healthz || exit 1
CMD ["node", "apps/gateway/src/index.mjs"]
