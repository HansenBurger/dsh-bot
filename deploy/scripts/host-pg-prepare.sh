#!/usr/bin/env bash
# host-pg-prepare.sh — make the HOST PostgreSQL instance reachable and usable by the
# memory-service container, then apply the schema migrations.
#
# Why this exists as a script and not as a compose entrypoint:
#   t4 §9.3 方案 A asks for "container → host PG over host.docker.internal with a
#   pg_hba allowlist for container IPs". Measured on this host (docs/validation/
#   core-impl.md), host PG listens on 127.0.0.1 ONLY, so *no* TCP path from a docker
#   network exists — 172.17.0.1:5432 and 172.28.0.1:5432 both answer ECONNREFUSED, and
#   changing `listen_addresses` would put a shared production cluster on a bridge
#   network, which the security baseline forbids (C-1).
#   The remaining host-local path that keeps scram-sha-256 authentication and adds no
#   listener at all is the UNIX SOCKET. So this script:
#     1. appends narrowly-scoped `local` pg_hba rules (DB + role specific, inserted
#        BEFORE the catch-all `local all all peer`), with a timestamped backup and a
#        parse check before any reload — a broken pg_hba must never be applied;
#     2. grants CONNECT on the one database we own;
#     3. runs 001..004 as the postgres superuser.
#   This is t4 §9.3 方案 B *for the container hop only*; the process still speaks to
#   the host's own cluster, so "长期记忆 = Host PostgreSQL" holds. The deviation is
#   documented in README.md and docs/validation/core-impl.md rather than hidden.
#
# Idempotent: safe to re-run. Requires: sudo -n (passwordless) and psql.
set -euo pipefail

DB="${MEM_PG_DATABASE:-dsh_companion}"
SOCKET_DIR="${MEM_PG_SOCKET_DIR:-/var/run/postgresql}"
CONF_DIR="${MEM_PG_CONF_DIR:-/etc/postgresql/16/main}"
MARKER="# dshbot-companion-managed"
export PGPASSWORD="${MEM_PG_RW_PASSWORD:?MEM_PG_RW_PASSWORD required (16+ chars)}"
RO_PWD="${MEM_PG_RO_PASSWORD:?MEM_PG_RO_PASSWORD required (16+ chars)}"
# Optional: a CREATEDB login role so the *container* may apply the schema itself
# (MEM_RUN_MIGRATIONS=1). Without it the migration stays host-side, which is the
# default: fewer credentials on the socket than the operator did not ask for.
PROVISION_ROLE="dsh_companion_provision"
PROVISION_PWD="${MEM_PG_PROVISION_PASSWORD:-}"

# `sudo` resets the environment, so PGOPTIONS (which carries the custom GUCs the
# migrations read through current_setting()) must be re-asserted inside the sudo call;
# `sudo -u postgres PGOPTIONS=...` alone would be swallowed by env_reset.
as_pg() { sudo -n -u postgres env PGOPTIONS="${PGOPTIONS:-}" psql -X -q -v ON_ERROR_STOP=1 "$@"; }

echo "[1/5] pg_hba: scoped local rules for ${DB}"
HBA="${CONF_DIR}/pg_hba.conf"
TMP="$(sudo -n mktemp)"
BACKUP="${HBA}.bak.$(date +%s)"
sudo -n cp -a "$HBA" "$BACKUP"
if sudo -n grep -qF "dshbot-companion-managed" "$HBA"; then
  echo "      already present — skipping"
else
  # Insert before the first `local` catch-all so our rules win (pg_hba is first-match).
  sudo -n awk -v marker="$MARKER" -v db="$DB" -v prov="$PROVISION_PWD" -v provrole="$PROVISION_ROLE" '
    BEGIN { done = 0 }
    !done && /^local[[:space:]]+all[[:space:]]+all[[:space:]]+peer/ {
      print "# dshbot-companion-managed — memory-service container, unix socket, scram"
      printf "local   %s   dsh_companion_rw   scram-sha-256\n", db
      printf "local   %s   dsh_companion_ro   scram-sha-256\n", db
      if (prov != "") {
        # CREATE DATABASE must be issued against a maintenance db, hence the postgres line.
        printf "local   %s   %s   scram-sha-256\n", db, provrole
        printf "local   postgres   %s   scram-sha-256\n", provrole
      }
      done = 1
    }
    { print }
  ' "$HBA" | sudo -n tee "$TMP" >/dev/null
  sudo -n install -o postgres -g postgres -m 640 "$TMP" "$HBA"
fi
# Parse the *file* before reloading: pg_hba_file_rules reports syntax errors without
# applying them, and openwebui is on this same instance.
ERRS="$(as_pg -d postgres -tAc "select count(*) from pg_hba_file_rules where error is not null" || echo 1)"
if [[ "$ERRS" != "0" ]]; then
  sudo -n cp -a "$BACKUP" "$HBA"
  echo "FATAL: pg_hba.conf would not parse — restored $BACKUP, refusing to reload" >&2
  exit 1
fi
as_pg -d postgres -c "select pg_reload_conf()" >/dev/null
echo "      reloaded, 0 parse errors"

if [[ -n "$PROVISION_PWD" ]]; then
  echo "      provisioning role ${PROVISION_ROLE} (LOGIN CREATEDB) for container-side migration"
  as_pg -d postgres -c "DO \$\$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${PROVISION_ROLE}') THEN
        CREATE ROLE ${PROVISION_ROLE} LOGIN CREATEDB NOINHERIT CONNECTION LIMIT 2;
      ELSE
        ALTER ROLE ${PROVISION_ROLE} WITH CONNECTION LIMIT 2;
      END IF;
    END \$\$;
    ALTER ROLE ${PROVISION_ROLE} PASSWORD '$(printf "%s" "$PROVISION_PWD" | sed "s/'/''/g")';"
fi

echo "[2/5] database ${DB} + role defaults"
EXISTS="$(as_pg -d postgres -tAc "select count(*) from pg_database where datname='${DB}'")"
if [[ "$EXISTS" == "0" ]]; then
  as_pg -d postgres -c "CREATE DATABASE ${DB} ENCODING 'UTF8' LC_COLLATE 'C.UTF-8' LC_CTYPE 'C.UTF-8' TEMPLATE template0"
  echo "      created (UTF-8 / C.UTF-8, required by the byte-trigram path)"
else
  echo "      already exists"
fi

echo "[3/5] migrations 001..004 (idempotent)"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MIG_DIR="$(cd "${HERE}/../../apps/memory-service/migrations" && pwd)"

# GUCs the migrations read through current_setting() travel in a 0600 temp file that is
# executed in the SAME psql session as the migration (`-f boot.sql -f migration.sql`).
# Two cheaper transports were measured to be wrong and are recorded in
# apps/memory-service/src/migrate.mjs:
#   - psql `-c name=value` is "run this SQL", not "set a parameter";
#   - PGOPTIONS splits on commas, which silently truncates the baseline spec (it is a
#     comma-joined list), and its quoting rules corrupt values containing a quote.
BOOT_SETS=()   # accumulated `SET x = 'v';` lines for the current migration
boot_file() {
  local boot; boot="$(sudo -n mktemp)"
  printf '%s\n' "${BOOT_SETS[@]}" | sudo -n tee "$boot" >/dev/null
  # Owned by the role that will read it (postgres runs psql), mode 0600: mktemp leaves it
  # root-owned, and postgres would then be refused.
  sudo -n chown postgres:postgres "$boot"
  sudo -n chmod 600 "$boot"
  printf '%s' "$boot"
}
sql_literal() { # single-quote a literal; a quote inside would let SQL text escape
  local v="$1"
  case "$v" in *"'"*) echo "FATAL: value contains a single quote — use migrate-cli.mjs instead" >&2; exit 1 ;; esac
  printf "'%s'" "$v"
}
run_migration() { # run_migration <file>
  local f="$1" boot=""
  if [[ ${#BOOT_SETS[@]} -gt 0 ]]; then boot="$(boot_file)"; fi
  if [[ -n "$boot" ]]; then
    as_pg -d "$DB" -f "$boot" -f "${MIG_DIR}/${f}" >/dev/null
    sudo -n rm -f "$boot"
  else
    as_pg -d "$DB" -f "${MIG_DIR}/${f}" >/dev/null
  fi
  BOOT_SETS=()
  echo "      applied ${f}"
}

# 001 has no GUC inputs at all. The role passwords must reach 002 as a GUC rather than
# as SQL text: a literal in the statement would land in the server log (D5).
run_migration 001_schema.sql
BOOT_SETS=("SET companion.rw_password = $(sql_literal "$PGPASSWORD");" "SET companion.ro_password = $(sql_literal "$RO_PWD");")
run_migration 002_roles.sql

# Artifact baseline: path=sha pairs, hashed from the exact bytes being applied.
BASELINE=""
for f in 001_schema.sql 002_roles.sql 004_retention.sql; do
  [[ -f "${MIG_DIR}/${f}" ]] || continue
  BASELINE="${BASELINE:+${BASELINE},}docs/memory/sql/pg/${f}=$(sha256sum "${MIG_DIR}/${f}" | cut -d' ' -f1)"
done
BOOT_SETS=("SET companion.baseline_sha256 = $(sql_literal "$BASELINE");")
run_migration 003_seed_policy.sql
run_migration 004_retention.sql

echo "[4/5] permission matrix, probed as the login roles (M-02/M-07)"
# `SET ROLE` would prove nothing: the point is what a *connection* as that role can do,
# which is exactly what the memory service's two pools hold. Passwords travel in the
# child environment, never on argv (argv is visible in `ps`).
probe() { # probe <role> <password> <sql>
  PGPASSWORD="$2" psql -h "$SOCKET_DIR" -p "${MEM_PG_PORT:-5432}" -U "$1" -d "$DB" -X -q -tAc "$3" 2>&1 || true
}
RO_INSERT="$(probe dsh_companion_ro "$RO_PWD" "INSERT INTO companion.memory_episode (subject_id, peer_key, class, body_plain, dedupe_key, sensitivity, visibility) VALUES (gen_random_uuid(), 'probe', 'episode', 'x', 'probe', 'internal', 'private')")"
RO_DECRYPT="$(probe dsh_companion_ro "$RO_PWD" "SELECT pgp_sym_decrypt('\\x00'::bytea, 'k')")"
RW_TOMB_DELETE="$(probe dsh_companion_rw "$PGPASSWORD" "DELETE FROM companion.memory_tombstone")"
RW_FORGET_FN="$(probe dsh_companion_rw "$PGPASSWORD" "SELECT companion.forget_by_subject(gen_random_uuid(), 'probe', 'aaaaaaaa', true)")"
RW_PURGE="$(probe dsh_companion_rw "$PGPASSWORD" "SELECT companion.purge_expired(10)")"
PROBE_FAIL=0
expect_denied() { # expect_denied <label> <output>
  if printf '%s' "$2" | grep -q "permission denied"; then
    echo "      OK  $1 is denied"
  else
    echo "      FAIL $1 should be denied, got: $(printf '%s' "$2" | head -1 | cut -c1-90)"
    PROBE_FAIL=1
  fi
}
expect_denied "ro INSERT" "$RO_INSERT"
expect_denied "ro pgp_sym_decrypt" "$RO_DECRYPT"
expect_denied "rw DELETE on tombstones (append-only)" "$RW_TOMB_DELETE"
expect_denied "rw EXECUTE forget_by_subject (M-07)" "$RW_FORGET_FN"
if printf '%s' "$RW_PURGE" | grep -qiE "^[0-9]+$|purge_expired"; then
  echo "      OK  rw EXECUTE purge_expired is granted"
else
  echo "      FAIL rw purge_expired should be granted, got: $(printf '%s' "$RW_PURGE" | head -1 | cut -c1-90)"
  PROBE_FAIL=1
fi
[[ "$PROBE_FAIL" == 0 ]] || { echo "FATAL: permission matrix does not match the design" >&2; exit 1; }

echo "[5/5] socket reachability from the container network (informational)"
echo "      compose mounts ${SOCKET_DIR}; memory-service uses MEM_PG_HOST=socket:${SOCKET_DIR}"
echo "      connectivity check as dsh_companion_ro: $(printf '%s' "$(probe dsh_companion_ro "$RO_PWD" "select 1")")"
echo "OK: host PG prepared for dsh_companion"
