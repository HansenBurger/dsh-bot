#!/usr/bin/env bash
# broker-e2e — prove acceptance #4 on the running stack: an agent container cannot obtain
# the LLM key or the database password, while the memory service can obtain exactly the
# refs it needs. Every check is executed *inside* the container that is supposed to be
# limited, so the result cannot be argued away as a host-side artifact.
#
#   bash scripts/broker-e2e.sh
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
COMPOSE=(docker compose -f deploy/compose.yaml)
BROKER=http://172.28.2.30:8080
pass=0; fail=0
step_empty() { # step_empty <label> <actual> — pass when there is nothing to report
  if [ -z "$(printf '%s' "$2" | tr -d '[:space:]')" ]; then pass=$((pass+1)); printf 'PASS %s — nothing leaked\n' "$1";
  else fail=$((fail+1)); printf 'FAIL %s — %s\n' "$1" "$(printf '%s' "$2" | head -3 | tr '\n' ' ' | cut -c1-160)"; fi
}

step() { # step <label> <expected-substring> <actual>
  if printf '%s' "$3" | grep -q "$2"; then pass=$((pass+1)); printf 'PASS %s — %s\n' "$1" "$(printf '%s' "$3" | head -1 | cut -c1-120)";
  else fail=$((fail+1)); printf 'FAIL %s — expected %s, got: %s\n' "$1" "$2" "$(printf '%s' "$3" | head -3 | tr '\n' ' ' | cut -c1-160)"; fi
}

# Only the HTTP status is printed, plus the error body on a *denial*. Echoing a 200 body
# would paste a real credential into the verification record — the whole point of this
# script is that nobody can read those values from an agent container.
status_of() { # status_of <service> <ref>
  "${COMPOSE[@]}" exec -T "$1" sh -c "token=\$(cat /run/secrets/enrollment-token 2>/dev/null); code=\$(curl -sS -o /tmp/b -w '%{http_code}' -H \"x-broker-token: \$token\" '$BROKER/v1/secret/$2'); if [ \"\$code\" != 200 ]; then printf '%s %s' \"\$code\" \"\$(head -c 60 /tmp/b)\"; else printf '%s body-suppressed' \"\$code\"; fi; rm -f /tmp/b" 2>&1 | tail -1
}

echo "[1] the agent plane cannot read credentials it does not own"
# bot-core mounts only its own enrollment token; both probes are made from inside it.
step "B1 bot-core is denied the LLM key (never-resolvable)" "403" "$(status_of bot-core llm-api-key)"
step "B1b bot-core is denied the broker's own llm key ref" "403" "$(status_of bot-core llm-key)"
step "B2 bot-core is denied the PG rw password" "403" "$(status_of bot-core mem-pg-rw-password)"
step "B3 bot-core is denied the memory KEK" "403" "$(status_of bot-core mem-kek)"
step "B4 bot-core may resolve its own HMAC secret" "200" "$(status_of bot-core mem-hmac-secret)"

echo "[2] the memory service gets its four refs and nothing more"
step "M1 memory resolves the rw password" "200" "$(status_of memory mem-pg-rw-password)"
step "M2 memory resolves the KEK" "200" "$(status_of memory mem-kek)"
step "M3 memory is denied the LLM key" "403" "$(status_of memory llm-key)"
step "M4 memory is denied another client's token" "403" "$(status_of memory ingress-tg-token)"
# A `..` segment is normalised away by the HTTP stack before routing, so the broker
# answers 404 rather than reading outside the tree; either way nothing is echoed.
step "M5 a traversal-shaped ref is refused, not echoed" "40[134]" "$(status_of memory ../etc/passwd)"

echo "[3] no secret-shaped literal is present in any container environment"
for svc in ingress bot-core memory broker; do
  # Anything secret-shaped must be an opaque ref (or a ref *name*, or a non-credential).
  # SECRETS_DIR is a path, LLM_KEY_REF is a name the broker resolves, and
  # OB11_ACCESS_TOKEN_FINGERPRINT is a sha256 comparison value (D1) — none of them is key
  # material, so they are excluded by intent, not by accident.
  leak="$("${COMPOSE[@]}" exec -T "$svc" sh -c 'env' 2>/dev/null | grep -iE "password|secret|token|_key|apikey" | grep -vE "=(opaque-ref:|[A-Za-z0-9_-]*REF$|.*_REF=)" | grep -vE "MEM_PG_PROVISIONING_USER|NO_PROXY|http_proxy|https_proxy|NODE_ENV|PATH=|SECRETS_DIR=|_KEY_REF=|FINGERPRINT=" || true)"
  step_empty "E1 ${svc} environment carries only opaque refs" "$leak"
done

echo "[4] the key material itself lives in exactly one container"
for svc in ingress bot-core memory broker; do
  found="$("${COMPOSE[@]}" exec -T "$svc" sh -c 'ls /run/secrets 2>/dev/null | tr "\n" " "' 2>&1 | tail -1)"
  printf '      %-9s /run/secrets: %s\n' "$svc" "${found:0:120}"
done
step "S1 the LLM key is not mounted into the agent container" "No such file" "$("${COMPOSE[@]}" exec -T bot-core sh -c 'cat /run/secrets/llm-key 2>&1' 2>&1 | tail -1)"
step "S2 the broker holds it" "present" "$("${COMPOSE[@]}" exec -T broker sh -c 'test -s /run/secrets/llm-key && echo present || echo missing' 2>&1 | tail -1)"

echo "[5] the agent plane has no direct route to the internet (egress needs the proxy)"
DIRECT="$("${COMPOSE[@]}" exec -T bot-core sh -c 'curl -sS -m 6 -o /dev/null -w "%{http_code}" https://api.deepseek.com/v1/models 2>&1 || echo "unreachable"' 2>&1 | tail -1)"
step "G1 a direct HTTPS call from bot-core fails" "unreachable\|000\|Couldn\|failed\|refused\|timed" "$DIRECT"

echo
echo "== broker e2e: $pass/$((pass+fail)) checks passed =="
[[ $fail -eq 0 ]] || exit 1
