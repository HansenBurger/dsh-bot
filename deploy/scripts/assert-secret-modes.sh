#!/usr/bin/env bash
# assert-secret-modes — R7: host credential material must never carry group or other
# access. deploy/secrets/* and deploy/.env are read by the daemon at bind time and by
# exactly the container uids the compose file mounts them into; nothing else on this
# shared host has any business reading them.
#
# The check is ACL-aware on purpose: the *only* legitimate way to widen a secret past
# its owner is a named `user:<uid>:r--` entry (gen-secrets.sh documents it), never a
# group or other bit - those silently include every account on the machine.
#
#   bash deploy/scripts/assert-secret-modes.sh [--containers]
#
# With --containers (and docker available) it also proves the running containers can
# still read each file they mount, so tightening never leaves a healthy-looking stack
# that cannot boot again.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 1
SECRETS_DIR=deploy/secrets
[ -d "$SECRETS_DIR" ] || { echo "FAIL $SECRETS_DIR absent (wrong repo root?)" >&2; exit 1; }
fail=0

perm_lines() { # normalise getfacl output to "class::perms" lines for the three base classes
  local out
  out=$(getfacl -p "$1" 2>/dev/null | grep -E '^(user|group|other)::')
  printf '%s' "$out"
}

check_file() { # check_file <path> <label>
  local p="$1" label="$2" lines bad
  if [ ! -e "$p" ]; then echo "  skip $label (absent: $p)"; return; fi
  lines=$(perm_lines "$p")
  if [ -z "$lines" ]; then echo "  FAIL cannot read permissions of $p"; fail=1; return; fi
  bad=$(printf '%s\n' "$lines" | awk -F:: '$1=="group" && $2!="---" {print "group=" $2} $1=="other" && $2!="---" {print "other=" $2}')
  if [ -n "$bad" ]; then
    echo "  FAIL $label carries non-owner access: $(printf '%s' "$bad" | tr '\n' ' ')"
    fail=1
  else
    echo "  OK   $label is owner-only at base perms ($(printf '%s\n' "$lines" | tr '\n' ' '))"
  fi
}

echo "== deploy/secrets mode gate =="
dir_lines=$(perm_lines "$SECRETS_DIR")
if [ -z "$dir_lines" ]; then
  echo "  FAIL cannot read permissions of $SECRETS_DIR"; fail=1
elif printf '%s\n' "$dir_lines" | grep -E '^(group|other)::[^-]' >/dev/null; then
  echo "  FAIL $SECRETS_DIR grants group/other traversal or read: $(printf '%s' "$dir_lines" | tr '\n' ' ')"
  fail=1
else
  echo "  OK   $SECRETS_DIR is 0700-shaped ($(printf '%s' "$dir_lines" | tr '\n' ' '))"
fi
for f in "$SECRETS_DIR"/* deploy/.env; do
  [ -e "$f" ] || continue
  check_file "$f" "${f##*/}"
done

if [ "${1:-}" = "--containers" ] && command -v docker >/dev/null; then
  echo "== running containers can still read their mounts =="
  for c in broker memory bot-core ingress; do
    name=dsh-big-fish-bot-$c-1
    docker inspect "$name" >/dev/null 2>&1 || { echo "  skip $c (not present)"; continue; }
    out=$(docker exec "$name" sh -c 'for f in /run/secrets/*; do head -c1 "$f" >/dev/null 2>&1 || echo "UNREADABLE $f"; done' 2>/dev/null)
    if [ -n "$out" ]; then echo "  FAIL $c: $out"; fail=1; else echo "  OK   $c reads every mounted secret"; fi
  done
fi

if [ "$fail" -eq 0 ]; then
  echo "OK secret modes satisfy R7 (0600 owner + named ACL only)"
else
  echo "NO-GO: world/group-readable credentials on the host (t3 review R7)"
fi
exit "$fail"
