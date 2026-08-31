#!/usr/bin/env bash
#
# Runs the Linux-only private-routing gates in a privileged Linux container.
#
# The eleven-role scenarios bind the 127.64.x.1 role tuples (KI-2) and the
# namespace gates need CAP_NET_ADMIN plus tcpdump (KI-3). Neither holds on macOS
# or Windows, so without this runner both only ever run in CI. Container results
# are local evidence, not a replacement for the fork-native CI job.
#
# Usage: scripts/linux-gates.sh [gate ...]
#   aggregate:node   deterministic aggregate under Node
#   aggregate:bare   deterministic aggregate under Bare
#   process:node     eleven-role live scenario, Node roles
#   process:bare     eleven-role live scenario, Bare roles
#   namespace        namespace projection enforcement
#   namespace:live   namespace live route with capture oracles
#   all              every gate above, in that order (default)

set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_digest="$(
  cat "$repo/package.json" "$repo/docker/linux-gates.Dockerfile" | shasum -a 256 | cut -c1-12
)"
image_tag="hyperdht-private-routing/linux-gates:$image_digest"

# A stale credsStore in the host docker config (for example "desktop" left behind
# after Docker Desktop is removed) fails every pull with a missing credential
# helper. Build against a copy with the helpers stripped rather than editing the
# developer's config, and pin the endpoint so the copy cannot lose the context.
docker_endpoint="$(docker context inspect -f '{{.Endpoints.docker.Host}}' 2>/dev/null || true)"
docker_config_dir="${TMPDIR:-/tmp}/hyperdht-private-routing-linux-gates-docker"
mkdir -p "$docker_config_dir"
HOST_DOCKER_CONFIG="${DOCKER_CONFIG:-$HOME/.docker}" node -e '
const fs = require("fs")
const path = require("path")
const source = path.join(process.env.HOST_DOCKER_CONFIG, "config.json")
let config = {}
try {
  config = JSON.parse(fs.readFileSync(source, "utf8"))
} catch {}
delete config.credsStore
delete config.credHelpers
fs.writeFileSync(path.join(process.argv[1], "config.json"), JSON.stringify(config, null, 1))
' "$docker_config_dir"
host_docker_config="${DOCKER_CONFIG:-$HOME/.docker}"
# CLI plugins live beside the config, and buildx is one of them, so the copy has
# to point back at the host set or the build has no builder.
if [ -d "$host_docker_config/cli-plugins" ]; then
  ln -sfn "$host_docker_config/cli-plugins" "$docker_config_dir/cli-plugins"
fi
export DOCKER_CONFIG="$docker_config_dir"
if [ -n "$docker_endpoint" ]; then export DOCKER_HOST="$docker_endpoint"; fi

if [ "$#" -eq 0 ]; then
  gates=(all)
else
  gates=("$@")
fi

expanded=()
for gate in "${gates[@]}"; do
  case "$gate" in
    all)
      expanded+=(aggregate:node aggregate:bare process:node process:bare namespace namespace:live)
      ;;
    aggregate:node | aggregate:bare | process:node | process:bare | namespace | namespace:live)
      expanded+=("$gate")
      ;;
    *)
      echo "unknown gate: $gate" >&2
      exit 64
      ;;
  esac
done

command_for() {
  case "$1" in
    aggregate:node) echo 'brittle-node test/private-routing.js' ;;
    aggregate:bare) echo '"$(node -p "require(\"bare-runtime\")(\"bare\")")" test/private-routing.js' ;;
    process:node) echo 'npm run --silent test:private:process:node' ;;
    process:bare) echo 'npm run --silent test:private:process:bare' ;;
    namespace) echo 'npm run --silent test:private:namespace' ;;
    namespace:live) echo 'npm run --silent test:private:namespace:live' ;;
  esac
}

if ! docker image inspect "$image_tag" >/dev/null 2>&1; then
  echo "==> building $image_tag"
  docker build -f "$repo/docker/linux-gates.Dockerfile" -t "$image_tag" "$repo"
fi

status=0
for gate in "${expanded[@]}"; do
  echo "==> gate $gate"
  # --privileged: namespace provisioning creates netns, veth pairs and iptables
  # rules. tmpfs over /app/node_modules hides the host build from Linux Node.
  if docker run --rm \
    --privileged \
    --mount "type=bind,source=$repo,target=/app" \
    --mount type=tmpfs,destination=/app/node_modules \
    --mount type=tmpfs,destination=/tmp \
    -e PR_ROLE_FATAL_LOG=/tmp/role-fatal.log \
    -e PR_CANDIDATE_ORDER="${PR_CANDIDATE_ORDER:-normal}" \
    -w /app \
    "$image_tag" \
    bash -c "set -o pipefail; $(command_for "$gate"); code=\$?; if [ \$code -ne 0 ] && [ -s /tmp/role-fatal.log ]; then echo '--- role stacks ---'; cat /tmp/role-fatal.log; fi; exit \$code"; then
    echo "==> gate $gate: pass"
  else
    status=1
    echo "==> gate $gate: FAIL"
  fi
done

exit "$status"
