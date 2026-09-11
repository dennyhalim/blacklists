#!/usr/bin/env bash
set -euo pipefail

TABLE_FAMILY='inet'
TABLE_NAME='filter'
SET_NAME='blocklist_combined4'
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

if ! nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
    nft add table "$TABLE_FAMILY" "$TABLE_NAME"
fi

if nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" >/dev/null 2>&1; then
    nft delete set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME"
fi

nft -f "$SCRIPT_DIR/combined4.nft"
