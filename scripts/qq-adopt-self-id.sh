#!/usr/bin/env bash
# qq-adopt-self-id — after the small account has scanned the QR, teach the gateway who it is.
#
# NapCat dials the reverse WS once it is logged in. While deploy/.env still carries the
# prototype SELF_ID, the gateway rejects that socket with close 1008 and audits the number it
# saw. This script finds the account NapCat actually logged in as, and (with --apply) writes
# SELF_ID + the owner whitelist entry and restarts the two containers that read them.
#
# It reads two independent sources and refuses to guess:
#   1. data/napcat-config/onebot11_<qq>.json — the per-account file NapCat creates on login
#   2. the newest self-id-mismatch audit line whose socket is the NapCat container itself
# The e2e harness also produces mismatch lines (a foreign self_id 555555555 is one of its
# tests) from the published host port, so unfiltered audit parsing will happily "discover" a
# fake account. That happened on the first draft of this script, which rewrote deploy/.env
# with 555555555; the source filter and the dry-run default are the reason they exist.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

OWNER_QQ="${OWNER_QQ:-1035376945}"        # the owner's real QQ, as given by the captain
NAPCAT_IP="${NAPCAT_IP:-172.28.0.20}"     # the container's address on net-protocol
APPLY=0
[[ "${1:-}" == "--apply" ]] && APPLY=1

declare -a found=()

# Source 1: per-account OneBot config written after a successful login.
for f in data/napcat-config/onebot11_*.json; do
  [[ -e "$f" ]] || continue
  id="${f##*onebot11_}"; id="${id%.json}"
  [[ "$id" =~ ^[0-9]{5,20}$ ]] && found+=("$id (from $f)")
done

# Source 2: mismatch audit lines, but only those from the NapCat container itself.
if [[ -f logs/ingress.jsonl ]]; then
  AUDIT_ID=$(grep '"reason":"self-id-mismatch"' logs/ingress.jsonl 2>/dev/null \
    | grep -F "\"socketId\":\"${NAPCAT_IP}:" | tail -1 \
    | grep -o '"observed":"[0-9]\{5,20\}"' | grep -o '[0-9]\+' || true)
  [[ -n "${AUDIT_ID:-}" ]] && found+=("$AUDIT_ID (from audit, socket ${NAPCAT_IP})")
fi

if [[ ${#found[@]} -eq 0 ]]; then
  cat >&2 <<EOF
No logged-in QQ account found yet.
  - no data/napcat-config/onebot11_<qq>.json   (NapCat writes it after a successful login)
  - no self-id-mismatch audit line from ${NAPCAT_IP}
Has the small account scanned the QR? Nothing was modified.
EOF
  exit 1
fi

printf 'candidate self_id: %s\n' "${found[@]}"
SELF_ID=$(printf '%s\n' "${found[@]}" | awk '{print $1}' | sort -u | head -1)
if [[ $(printf '%s\n' "${found[@]}" | awk '{print $1}' | sort -u | wc -l) -gt 1 ]]; then
  echo "sources disagree; pass the id explicitly: SELF_ID=<qq> $0 --apply" >&2
  exit 1
fi
echo "resolved self_id: $SELF_ID   owner to whitelist: $OWNER_QQ"
echo "the owner's QQ is the only onebot entry; an unlisted probe id is denied by default-deny."

if [[ $APPLY -eq 0 ]]; then
  echo "dry run (nothing written). Re-run with --apply."
  exit 0
fi

python3 - "$SELF_ID" "$OWNER_QQ" <<'PY'
import json, pathlib, re, sys
self_id, owner = sys.argv[1:3]

env_path = pathlib.Path('deploy/.env')
text = env_path.read_text()
if re.search(r'^SELF_ID=', text, re.M):
    text = re.sub(r'^SELF_ID=.*$', f'SELF_ID={self_id}', text, flags=re.M)
else:
    text += f'SELF_ID={self_id}\n'
env_path.write_text(text)
print(f'deploy/.env SELF_ID -> {self_id}')

wl_path = pathlib.Path('deploy/whitelist.json')
wl = json.loads(wl_path.read_text())
# Drop every prototype onebot principal: a second owner entry on one channel is a boot-time
# POLICY_INVALID, and a stale whitelisted id is a door nobody remembers opening.
wl['entries'] = [e for e in wl['entries'] if e['channel'] != 'onebot']
wl['entries'].insert(0, {
    'channel': 'onebot',
    'chatId': owner,
    'userId': owner,
    'role': 'owner',
    'note': f'主人 {owner} 的 QQ 私聊（DM 的 chat_id 等于其 QQ 号）；机器人自身号 {self_id}',
})
wl_path.write_text(json.dumps(wl, ensure_ascii=False, indent=2) + '\n')
print(f'deploy/whitelist.json: onebot owner = {owner}, prototype onebot entries removed')
PY

echo
echo "Restarting the containers that read SELF_ID ..."
timeout 180 docker compose -f deploy/compose.yaml restart ingress bot-core
echo "Now confirm the socket is accepted: the newest audit line should be event=connected with no self-id-mismatch."
