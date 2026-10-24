# Memory service (t4 §9.4). Two DB clients are baked in on purpose:
#   - postgresql-client: the schema migration runs at container start against the host
#     PostgreSQL over a mounted unix socket (see docs/validation/core-impl.md, deviation
#     from t4 §9.3 方案A);
#   - sqlite3: L1 short-term cache + `VACUUM INTO` backups from inside the container.
FROM docker.m.daocloud.io/library/node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages ./packages
COPY apps/gateway/package.json ./apps/gateway/
COPY apps/memory-service/package.json ./apps/memory-service/
COPY apps/secret-broker/package.json ./apps/secret-broker/
COPY apps/bot-core/package.json ./apps/bot-core/
RUN npm ci --omit=dev --workspace=@dsh-bot/memory-service

FROM docker.m.daocloud.io/library/node:22-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client sqlite3 ca-certificates curl \
 && rm -rf /var/lib/apt/lists/* \
 && psql --version && sqlite3 --version
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
COPY apps/memory-service ./apps/memory-service
# uid 10001 = the same principal the agent side runs as (t3 B5 splits NapCat at 2100).
# The L1 directory is created here, not at runtime: compose mounts a *named volume* on
# /var/lib/dshbot/memory, and Docker seeds a fresh volume from the image's directory
# ownership. A pre-created dir owned by the service uid is what makes the volume writable
# for uid 10001; the entrypoint then verifies rather than hopes.
RUN set -eux; useradd -u 10001 -m -s /bin/bash dshbot; mkdir -p /var/lib/dshbot/memory/backup; chown -R 10001:10001 /var/lib/dshbot
RUN chown -R 10001:10001 /app
COPY apps/memory-service/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh
USER 10001:10001
EXPOSE 8091
HEALTHCHECK --interval=15s --timeout=4s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8190/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "apps/memory-service/src/index.mjs"]
