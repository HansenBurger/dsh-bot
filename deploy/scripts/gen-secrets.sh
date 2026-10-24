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
# bot-core). Ownership is the only thing that keeps a *different* container from reading
# a *sibling's* file when an operator mounts ./secrets wholesale (the broker does), so:
#   - running this script with sudo + SECRETS_UID (default 10001) yields 0400 files owned
#     by that uid, which is the intended NAS posture;
#   - running it unprivileged leaves 0644 files and says so, because mount scoping is then
#     the only thing doing the work — the operator must know which mode they are in.
TARGET_UID="${SECRETS_UID:-10001}"
mode_for() { [[ "$(id -u)" == "0" ]] && echo 0400 || echo 0644; }

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
  echo "  NOTE: unprivileged run — files are 0644; mount scoping is then the only isolation." >&2
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
echo
echo "Next:"
echo "  1. host schema:  MEM_PG_RW_PASSWORD=\$(cat $DIR/mem-pg-rw-password) MEM_PG_RO_PASSWORD=\$(cat $DIR/mem-pg-ro-password) bash deploy/scripts/host-pg-prepare.sh"
echo "  2. fill deploy/.env from deploy/.env.example (SELF_ID, TOKEN_FP)"
echo "  3. edit deploy/whitelist.json to your real chat/user ids"
echo "  4. docker compose -f deploy/compose.yaml up -d"
