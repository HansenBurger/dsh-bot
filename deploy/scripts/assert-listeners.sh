#!/usr/bin/env bash
# F-7 / C1 — the stack's published ports must be bound to loopback and nothing else.
#
# Run on the NAS host (not inside a container): a container cannot observe that its own
# published port reached 0.0.0.0, so this property has to be asserted from outside.
#
#   bash deploy/scripts/assert-listeners.sh              # check this stack's ports
#   STRICT=1 bash deploy/scripts/assert-listeners.sh     # also flag any other non-loopback listener
set -euo pipefail

STACK_PORTS="${STACK_PORTS:-3001 3080 3081 3082}"
# Only relevant with STRICT=1: things a NAS legitimately listens on.
ALLOW_NONLOOPBACK="${ALLOW_NONLOOPBACK:-}"
FAIL=0

listeners() {
  if command -v ss >/dev/null 2>&1; then
    # One header line, then rows: $5 is always the local address, and a real listener
    # ends with a numeric port (the peer column ends with ":*").
    ss -lntu 2>/dev/null | awk 'NR>1 && NF>=5 {print $5}' | grep -E ':[0-9]+$' || true
  elif command -v netstat >/dev/null 2>&1; then
    netstat -lntu 2>/dev/null | awk 'NR>2 {print $4}' | grep -E ':[0-9]+$' || true
  else
    echo "FATAL: neither ss nor netstat is available — refusing to report success" >&2
    exit 2
  fi
}

ADDRESSES="$(listeners | sort -u)"
if [[ -z "$ADDRESSES" ]]; then
  echo "FATAL: no listener data — this script cannot prove anything" >&2
  exit 2
fi

loopback() {
  case "$1" in
    127.* | \[::1\] | ::1) return 0 ;;
    *) return 1 ;;
  esac
}

for port in $STACK_PORTS; do
  matches="$(printf '%s\n' "$ADDRESSES" | awk -v p=":$port\$" '$0 ~ p' || true)"
  if [[ -z "$matches" ]]; then
    echo "  not listening: $port (stack down?)"
    continue
  fi
  while read -r addr; do
    [[ -z "$addr" ]] && continue
    ip="${addr%:*}"
    if loopback "$ip"; then
      echo "OK   $addr"
    else
      echo "FAIL $addr is not loopback-bound"
      FAIL=1
    fi
  done <<< "$matches"
done

if [[ "${STRICT:-0}" == "1" ]]; then
  while read -r addr; do
    [[ -z "$addr" ]] && continue
    ip="${addr%:*}"; port="${addr##*:}"
    loopback "$ip" && continue
    case " $ALLOW_NONLOOPBACK " in *" :$port "*) continue ;; esac
    case " $ALLOW_NONLOOPBACK " in *" $ip "*) continue ;; esac
    echo "FAIL STRICT: unexpected non-loopback listener $addr"
    FAIL=1
  done <<< "$ADDRESSES"
fi

if [[ "$FAIL" == 0 ]]; then
  echo "OK every stack port is loopback-only"
fi
exit "$FAIL"
