# ops/watcher — the L6 bypass watchdog (t3 §3, arch §5.2 “旁路 watcher”, baseline E3/F2/E7).
#
# stdlib-only on purpose: the watchdog is the one component that must still start when
# the npm registry is unreachable (it is the thing that tells us the stack is broken), so
# it has no `npm ci` step and no node_modules layer at all.
FROM docker.m.daocloud.io/library/node:22-slim
WORKDIR /app
ENV NODE_ENV=production
# Build context is the repository root (same convention as every other service: compose
# resolves a relative `build:` against deploy/, so `./ops/watcher` alone was never found).
COPY ops/watcher/package.json ./ops/watcher/
COPY ops/watcher/src ./ops/watcher/src
# Source checkouts sometimes carry 0600 modes (umask 077) and BuildKit preserves them
# while root-owning the copies — same lesson as the gateway image (EACCES at start).
RUN chmod -R a+rX /app
USER node
# The status endpoint is bound to loopback *inside* this container (C1: no published
# host port anywhere in the stack; assert-listeners stays green).
HEALTHCHECK --interval=30s --timeout=4s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8186/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["node", "ops/watcher/src/index.mjs"]
