#!/usr/bin/env bash
# assert-egress-allowlist — C5 counter-check: prove the squid allowlist is *enforced*,
# not merely configured.
#
# Why this script exists (t3 review R6): the allowlist only works because of a fragile
# accident. Ubuntu's squid image pulls `conf.d/*.conf` in *filename order*, and the
# distro's `debian.conf` ends in `http_access allow localnet` covering 172.16.0.0/12 -
# i.e. this whole stack. Our rules file is mounted as `a01-dshbot-rules.conf` purely so
# its terminal `http_access deny all` is matched first. Rename the file, re-order the
# image, or let an upgrade ship a later-loading conf.d entry, and the allowlist silently
# degrades to decoration again. A config diff would not catch that; a live probe does.
#
# What it asserts, in order:
#   S1 structural  a01-dshbot-rules.conf sorts before debian.conf in /etc/squid/conf.d
#   P1 behaviour   CONNECT api.deepseek.com:443  via proxy -> 200 (allowlist works)
#   P2 behaviour   CONNECT example.com:443       via proxy -> 403 (deny is terminal)
#   P3 behaviour   CONNECT 10.0.0.1:443          via proxy -> 403 (no RFC1918 side-hole)
# The probes run *inside the broker container*: it is the one workload with a legitimate
# route to the proxy, so the result cannot be argued away as a host-side artifact.
# api.deepseek.com is probed with CONNECT only - the tunnel is dropped before a single
# byte crosses it, so nothing reaches the model and no tokens are produced.
#
# Exit 0 only when every assert passes; any failure exits non-zero.
#
#   bash scripts/assert-egress-allowlist.sh
set -uo pipefail
PROXY_CONTAINER=${PROXY_CONTAINER:-dsh-big-fish-bot-proxy-1}
BROKER_CONTAINER=${BROKER_CONTAINER:-dsh-big-fish-bot-broker-1}
PROXY_URL=${PROXY_URL:-172.28.3.40:3128}
pass=0 fail=0

ok()  { pass=$((pass+1)); printf 'PASS %s\n' "$1"; }
bad() { fail=$((fail+1)); printf 'FAIL %s\n' "$1" >&2; }
check() { # check <label> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1 (=$3)"; else bad "$1 expected $2, got $3"; fi
}

command -v docker >/dev/null || { echo "FAIL docker is required" >&2; exit 2; }
docker inspect "$PROXY_CONTAINER" >/dev/null 2>&1 || { echo "FAIL proxy container $PROXY_CONTAINER not found" >&2; exit 2; }
docker inspect "$BROKER_CONTAINER" >/dev/null 2>&1 || { echo "FAIL broker container $BROKER_CONTAINER not found" >&2; exit 2; }

# ---- S1: the filename-order premise itself ------------------------------------------
order=$(docker exec "$PROXY_CONTAINER" ls -1 /etc/squid/conf.d 2>/dev/null | grep -v '^$')
a01_at=$(printf '%s\n' "$order" | grep -n '^a01-dshbot-rules.conf$' | cut -d: -f1)
deb_at=$(printf '%s\n' "$order" | grep -n '^debian.conf$' | cut -d: -f1)
if [ -n "$a01_at" ] && [ -n "$deb_at" ] && [ "$a01_at" -lt "$deb_at" ]; then
  ok "S1 a01-dshbot-rules.conf loads before debian.conf (positions $a01_at < $deb_at)"
else
  bad "S1 conf.d order: a01=${a01_at:-absent} debian=${deb_at:-absent} — the deny-all is NOT terminal, the allowlist is decorative"
fi

# ---- P1..P3: live CONNECT probes from inside the broker ------------------------------
probe=$(docker exec -i -e PROXY_URL="$PROXY_URL" "$BROKER_CONTAINER" node -e '
const net = require("net");
const [ph, pp] = process.env.PROXY_URL.split(":");
const targets = ["api.deepseek.com:443", "example.com:443", "10.0.0.1:443"];
(async () => {
  for (const t of targets) {
    await new Promise((resolve) => {
      const s = net.connect({ host: ph, port: Number(pp) });
      let settled = false;
      const finish = (out) => { if (settled) return; settled = true; console.log(`${t} ${out}`); s.destroy(); resolve(); };
      const timer = setTimeout(() => finish("TIMEOUT"), 8000);
      s.on("connect", () => s.write(`CONNECT ${t} HTTP/1.1\r\nHost: ${t}\r\n\r\n`));
      s.on("data", (b) => {
        clearTimeout(timer);
        const m = b.toString("latin1").split("\r\n")[0].match(/^HTTP\/1\.[01] (\d{3})/);
        // a 200 tunnel must be dropped immediately: zero bytes forwarded, zero tokens
        finish(m ? m[1] : "MALFORMED");
      });
      s.on("error", (e) => { clearTimeout(timer); finish(`ERR-${e.code}`); });
      s.on("close", () => { clearTimeout(timer); finish("CLOSED"); });
    });
  }
})();') || { echo "FAIL probe runner died inside $BROKER_CONTAINER" >&2; exit 2; }

status_of() { printf '%s\n' "$probe" | awk -v t="$1" '$1==t {print $2}'; }
check "P1 CONNECT api.deepseek.com:443 (allowlisted)" 200 "$(status_of api.deepseek.com:443)"
check "P2 CONNECT example.com:443 (off-allowlist)"    403 "$(status_of example.com:443)"
check "P3 CONNECT 10.0.0.1:443 (RFC1918 side-hole)"   403 "$(status_of 10.0.0.1:443)"

printf '%s\n' "--- $pass pass, $fail fail"
[ "$fail" -eq 0 ] || exit 1
printf 'egress allowlist is enforced, structurally and behaviourally (but see the two compensations documented in runbook 3.6: filename order, and broker exact-host vs dstdomain suffix semantics)\n'
