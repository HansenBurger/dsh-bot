#!/bin/sh
# Container start sequence (task requirement: "PG schema migration at container start").
#
# The migration is *idempotent* (docs/memory/sql/pg/001..004 are re-runnable), so running
# it on every start is safe; MEM_RUN_MIGRATIONS is opt-in only for the *host* instance so
# a restarted container does not fight over DDL while the owner edits migrations by hand.
set -eu

if [ ! -w "$(dirname "${MEM_L1_PATH:-/var/lib/dshbot/memory/l1.db}")" ]; then
  echo "memory-service: ${MEM_L1_PATH:-/var/lib/dshbot/memory/l1.db} is not writable (the L1 volume must be owned by uid 10001)" >&2
  exit 1
fi

if [ "${MEM_RUN_MIGRATIONS:-0}" = "1" ]; then
  echo "memory-service: applying PG schema migration at container start" >&2
  node apps/memory-service/src/migrate-cli.mjs || exit 1
fi

exec "$@"
