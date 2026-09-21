#!/usr/bin/env bash
set -euo pipefail

SOURCE="/etc/pve/dhblacklist-update.sh"
LOCK="/run/lock/dh-blacklist.lock"

# Prevent cron/manual runs from overlapping on this node.
exec 9>"$LOCK"
flock -n 9 || exit 0

[[ -r "$SOURCE" ]] || {
    echo "Shared blacklist updater not found: $SOURCE" >&2
    exit 1
}

# Snapshot the current cluster-replicated script.
TMP="$(mktemp /run/pve-blacklist.XXXXXX)"

cleanup() {
    rm -f "$TMP"
}
trap cleanup EXIT INT TERM

cp "$SOURCE" "$TMP"
chmod 0600 "$TMP"

# /run may be noexec; execute through Bash.
# Do not use exec here, so the EXIT trap removes the snapshot.
/bin/bash "$TMP"
