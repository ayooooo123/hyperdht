#!/usr/bin/env bash
#
# The two local secrets every remote-peer entry point needs, and the one public
# key it may publish. Sourced, never run:
#
#   . "$(dirname "${BASH_SOURCE[0]}")/remote-peer-credentials.sh"
#
# Two secrets, because they protect different things.
#
# The shared run secret lives in $XDG_CONFIG_HOME/hyperdht-remote-peer/secret and
# in the REMOTE_PEER_SECRET repository secret. Every peer and every role derives
# its own server key from it, which is how a coordinator finds them with no
# directory. It is never a workflow input: inputs are readable by anyone who can
# read the repository, and this secret is what stops a stranger connecting.
#
# The coordinator secret lives in .../coordinator-secret and nowhere else. It is
# not pushed to Actions and not derived from the shared secret, because every role
# host holds the shared secret and could otherwise mint the coordinator's key and
# drive its siblings. A run carries only the matching public key, as the
# coordinator_key dispatch input, which is safe to publish because it is public.
#
# That split is also why the coordinator always runs on this machine and never as
# a job: a coordinator job would need this secret inside Actions, and a secret
# uploaded to Actions is not one that stays here.
#
# Callers cd to the repository root first, because derive_coordinator_key runs a
# path-relative node script. An already-set node_bin is honoured.

secret_dir="${XDG_CONFIG_HOME:-$HOME/.config}/hyperdht-remote-peer"
secret_file="$secret_dir/secret"
coordinator_secret_file="$secret_dir/coordinator-secret"
node_bin="${node_bin:-${NODE:-node}}"

read_secret() {
  if [ ! -s "$secret_file" ]; then
    echo "no local secret; run: scripts/remote-peer.sh secret" >&2
    echo "add --push to also set the REMOTE_PEER_SECRET repository secret a dispatch needs" >&2
    exit 69
  fi
  tr -d '[:space:]' <"$secret_file"
}

read_coordinator_secret() {
  # The environment wins so a container or a one-off shell can supply it without a
  # file. There is deliberately no fall back to the shared secret: that is the
  # scheme this split exists to replace.
  if [ -n "${REMOTE_PEER_COORDINATOR_SECRET:-}" ]; then
    printf '%s' "$REMOTE_PEER_COORDINATOR_SECRET" | tr -d '[:space:]'
    return 0
  fi
  if [ ! -s "$coordinator_secret_file" ]; then
    echo "no coordinator secret; run: scripts/remote-peer.sh secret" >&2
    exit 69
  fi
  tr -d '[:space:]' <"$coordinator_secret_file"
}

# The pin every role and peer is given. Deriving it here keeps key handling in
# test/remote-peer/identity.js, which is the only file that should have any.
derive_coordinator_key() {
  REMOTE_PEER_COORDINATOR_SECRET="$1" "$node_bin" test/remote-peer/identity.js
}
