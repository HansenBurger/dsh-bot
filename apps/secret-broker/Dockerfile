# Secret Broker (t4 §9.4 / D1): the only image whose *runtime mount* holds plaintext.
# Nothing is baked into the layer — secrets arrive as read-only bind mounts.
FROM docker.m.daocloud.io/library/node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY apps/gateway/package.json ./apps/gateway/
COPY apps/memory-service/package.json ./apps/memory-service/
COPY apps/secret-broker/package.json ./apps/secret-broker/
COPY apps/bot-core/package.json ./apps/bot-core/
RUN npm ci --omit=dev --workspace=@dsh-bot/secret-broker

FROM docker.m.daocloud.io/library/node:22-slim
WORKDIR /app
ENV NODE_ENV=production
COPY --from=deps /app/node_modules ./node_modules
COPY packages/bot-audit/package.json ./packages/bot-audit/
COPY packages/bot-audit/src ./packages/bot-audit/src
COPY packages/bot-hmac/package.json ./packages/bot-hmac/
COPY packages/bot-hmac/src ./packages/bot-hmac/src
COPY packages/bot-secrets/package.json ./packages/bot-secrets/
COPY packages/bot-secrets/src ./packages/bot-secrets/src
COPY apps/gateway/package.json ./apps/gateway/
COPY apps/memory-service/package.json ./apps/memory-service/
COPY apps/secret-broker/package.json ./apps/secret-broker/
COPY apps/bot-core/package.json ./apps/bot-core/
COPY apps/secret-broker/src ./apps/secret-broker/src
# Source checkouts sometimes carry 0600 modes (umask 077), and BuildKit preserves them
# while root-owning the copies — which would make the runtime uid unable to read its own
# app tree. Normalize once here instead of debugging an EACCES at container start.
RUN chmod -R a+rX /app
USER node
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8180/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "apps/secret-broker/src/index.mjs"]
