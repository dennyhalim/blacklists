#!/usr/bin/env bash
set -euo pipefail

SOURCE="/etc/pve/dhblacklist-update.sh"
TMP="$(mktemp /run/dh-blacklist.XXXXXX)"

cleanup() {
    rm -f "$TMP"
}
trap cleanup EXIT

[[ -r "$SOURCE" ]] || {
    echo "Shared blacklist updater not found: $SOURCE" >&2
    exit 1
}

# Take a local snapshot so pmxcfs changes cannot affect a running update.
cp "$SOURCE" "$TMP"
chmod 0600 "$TMP"

exec /bin/bash "$TMP"
