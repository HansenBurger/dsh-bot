#!/usr/bin/env bash
# Generate the credential material the stack mounts read-only into /run/secrets.
#
# Rules this keeps:
#   - every value is >=32 random bytes of entropy, url-safe, no whitespace (D4);
#   - files are 0600 and the directory 0700, owned by the invoking user; the containers
#     read them through a :ro bind mount, so ownership by root is not required;
#   - an existing file is NEVER overwritten: rotating a KEK or a DB password silently
#     would make existing memories unreadable (t4 §5.2) and lock everyone out.
set -euo pipefail

DIR="${1:-$(dirname "$0")/../secrets}"
umask 077
mkdir -p "$DIR"
chmod 700 "$DIR"

rand() { # 43 base64url chars = 32 bytes
  openssl rand -base64 32 | tr '+/' '-_' | tr -d '=[:space:]'
}

# Containers read these through :ro bind mounts as their own uid (10001 for memory and
# bot-core, 1000 — the operator's own uid — for broker and ingress). The file *mode* may
# never carry a group or other bit, not even for the containers (t3 review R7): a 0644
# secret is world-readable on this shared host, and mount scoping is not a substitute for
# file permissions. When a container uid that is not the file owner must read a file,
# grant it by named ACL instead:
#     sudo setfacl -m u:10001:r deploy/secrets/<file>
# (uid 10001 reads: enrollment tokens for bot-core/memory, mem-hmac-secret, mem-kek,
#  mem-pg-*-password; everything uid 1000 consumes is owned by uid 1000 and plain 0600
#  already covers it). `bash deploy/scripts/assert-secret-modes.sh` checks the result.
TARGET_UID="${SECRETS_UID:-10001}"
mode_for() { [[ "$(id -u)" == "0" ]] && echo 0400 || echo 0600; }

put() { # put <name> <value>
  local name="$1" value="$2" path="$DIR/$1"
  if [[ -e "$path" ]]; then
    echo "  skip $name (exists; rotate deliberately, never by re-running this script)"
    return
  fi
  printf '%s\n' "$value" > "$path"
  chmod "$(mode_for)" "$path"
  if [[ "$(id -u)" == "0" ]]; then chown "$TARGET_UID":"$TARGET_UID" "$path"; fi
  echo "  wrote $name ($(stat -c '%a %U' "$path"))"
}

if [[ "$(id -u)" != "0" ]]; then
  echo "  NOTE: unprivileged run — files are 0600 owned by $(id -un); container uids below get named ACLs." >&2
  echo "        On the NAS: sudo SECRETS_UID=10001 bash deploy/scripts/gen-secrets.sh" >&2
fi
put mem-pg-rw-password "$(rand)"
put mem-pg-ro-password "$(rand)"
put mem-kek "$(rand)"
put mem-hmac-secret "$(rand)"
# Enrollment tokens identify a *client* to the broker; they are not secrets the client
# can spend beyond its own allowlist (apps/secret-broker/src/policy.mjs).
put enroll-memory-service "$(rand)"
put enroll-bot-core "$(rand)"
put enroll-ingress "$(rand)"
put ingress-tg-token "$(rand)"
# The LLM key is the one file an operator must place by hand; a generated placeholder
# makes the broker's refusal obvious instead of silently calling upstream with garbage.
if [[ ! -e "$DIR/llm-key" ]]; then
  printf '%s\n' "REPLACE-WITH-REAL-PROVIDER-KEY" > "$DIR/llm-key"
  chmod "$(mode_for)" "$DIR/llm-key"
  echo "  wrote llm-key (PLACEHOLDER — replace it)"
fi
# Unprivileged posture: hand the 0600 files to the only container uids that must read
# them (10001 = memory + bot-core). The broker/ingress containers run as uid 1000 — the
# owner here — so plain 0600 already covers them.
if [[ "$(id -u)" != "0" ]] && command -v setfacl >/dev/null; then
  for f in mem-pg-rw-password mem-pg-ro-password mem-kek mem-hmac-secret enroll-memory-service enroll-bot-core; do
    setfacl -m u:10001:r "$DIR/$f" 2>/dev/null || echo "  WARN: setfacl u:10001:r $f failed — that container will not read it" >&2
  done
  echo "  ACL: uid 10001 granted read on the six files it mounts (group/other bits stay empty)"
fi
echo
echo "Next:"
echo "  1. host schema:  MEM_PG_RW_PASSWORD=\$(cat $DIR/mem-pg-rw-password) MEM_PG_RO_PASSWORD=\$(cat $DIR/mem-pg-ro-password) bash deploy/scripts/host-pg-prepare.sh"
echo "  2. fill deploy/.env from deploy/.env.example (SELF_ID, TOKEN_FP)"
echo "  3. edit deploy/whitelist.json to your real chat/user ids"
echo "  4. docker compose -f deploy/compose.yaml up -d"
