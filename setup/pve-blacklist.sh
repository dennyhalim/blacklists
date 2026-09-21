#!/usr/bin/env bash
set -euo pipefail

SOURCE="/etc/pve/dhblacklist-update.sh"

[[ -r "$SOURCE" ]] || {
    echo "Shared blacklist updater not found: $SOURCE" >&2
    exit 1
}

TMP="$(mktemp /run/dh-blacklist.XXXXXX)"
trap 'rm -f "$TMP"' EXIT

cp "$SOURCE" "$TMP"
chmod 0700 "$TMP"

exec "$TMP"
