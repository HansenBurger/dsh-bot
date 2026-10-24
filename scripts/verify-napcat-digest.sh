#!/usr/bin/env bash
# verify-napcat-digest — resolve the immutable digest behind mlikiowa/napcat-docker:<tag>
# and (with --pin) write it into deploy/compose.yaml.
#
# The pin in use today is v4.18.41@sha256:b101b8968cc31ae428ec0f8e117386e4ced7773b2d8226ed9f7ddfcec55f1b7e,
# cross-verified against two sources (buildx imagetools + the Hub tag API). Use this
# script when upgrading the tag, or to re-confirm the digest after a compose change.
#
# Run this on a machine that can reach Docker Hub. This project pins third-party
# protocol images by digest (t3 G3) because NapCat is unauditable code that holds the QQ
# session (axiom 3): a tag can be moved under us, a digest cannot.
#
#   bash scripts/verify-napcat-digest.sh                 # print the digest
#   bash scripts/verify-napcat-digest.sh --pin            # rewrite compose.yaml
#   NAPCAT_IMAGE=mlikiowa/napcat-docker:v4.18.41 bash scripts/verify-napcat-digest.sh
#
# If you use crane or skopeo instead of the docker CLI:
#   crane digest mlikiowa/napcat-docker:v4.18.41
#   skopeo inspect --format '{{.Digest}}' docker://mlikiowa/napcat-docker:v4.18.41
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

IMAGE="${NAPCAT_IMAGE:-mlikiowa/napcat-docker:v4.18.41}"
PIN=0
[[ "${1:-}" == "--pin" ]] && PIN=1

command -v docker >/dev/null || { echo "need the docker CLI (or run crane/skopeo, see header)" >&2; exit 2; }

echo "resolving $IMAGE ..."
# buildx imagetools inspects the *manifest list* in the registry without downloading a
# single layer, so this works even on a machine without the platform of the image.
if command -v docker-buildx >/dev/null 2>&1 || docker buildx version >/dev/null 2>&1; then
  DIGEST=$(docker buildx imagetools inspect "$IMAGE" 2>/dev/null | awk '/^Digest:/{print $2; exit}')
else
  DIGEST=""
fi
if [ -z "${DIGEST:-}" ]; then
  # Fall back to a pull + inspect: heavier, but available on plain docker installs that
  # have no buildx. RepoDigests is what the registry actually served, not the local ID.
  docker pull "$IMAGE" >/dev/null
  DIGEST=$(docker inspect --format '{{join .RepoDigests "\n"}}' "$IMAGE" 2>/dev/null | grep -m1 -o 'sha256:[0-9a-f]\{64\}')
fi

if [ -z "${DIGEST:-}" ]; then
  echo "could not resolve a digest for $IMAGE" >&2
  echo "  - is this machine able to reach registry-1.docker.io (docker login / proxy)?" >&2
  echo "  - does the tag still exist?  https://hub.docker.com/r/mlikiowa/napcat-docker/tags" >&2
  exit 1
fi

echo "digest: $DIGEST"
echo "pinned image ref: ${IMAGE}@${DIGEST}"

if [ "$PIN" = "1" ]; then
  TARGET="${IMAGE}@${DIGEST}"
  python3 - "$TARGET" <<'PY'
import re, sys
target = sys.argv[1]
p = 'deploy/compose.yaml'
s = open(p).read()
new, n = re.subn(r'image: mlikiowa/napcat-docker:[^#\n]*', f'image: {target}', s)
if n == 0:
    sys.exit('no napcat image line found in deploy/compose.yaml')
open(p, 'w').write(new)
print(f'pinned {n} line(s) to {target}')
PY
  docker compose -f deploy/compose.yaml --profile qq config --quiet && echo "compose config still green"
fi
