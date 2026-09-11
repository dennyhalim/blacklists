#!/usr/bin/env sh
set -eu

TABLE='blocklist-hijack'
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Replace the table contents in one operation so removed source IPs disappear.
pfctl -t "$TABLE" -T replace -f "$SCRIPT_DIR/hijack.txt"
