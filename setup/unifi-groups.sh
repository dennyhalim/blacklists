#!/bin/bash
# bl.dennyhalim.com
set -euo pipefail

UNIFI_URL="${UNIFI_URL:-https://127.0.0.1}"
UNIFI_SITE="${UNIFI_SITE:-default}"
UNIFI_USER="${UNIFI_USER:-}"
UNIFI_PASS="${UNIFI_PASS:-}"
MAX_ENTRIES=10000

DEFAULT_GROUPS=(
    "dennyhalim-base3|https://blacklists.pages.dev/dist/plain/base3.txt"
    "dennyhalim-compact|https://blacklists.pages.dev/dist/plain/compact.txt"
)

usage() {
    echo "Usage: $0 <blocklist-url> <group-name>"
    echo "Required: UNIFI_USER and UNIFI_PASS"
    echo "Optional: UNIFI_URL (default https://127.0.0.1), UNIFI_SITE (default default)"
    exit 2
}

[[ $# -eq 0 || $# -eq 2 ]] || usage
[[ -n "$UNIFI_USER" && -n "$UNIFI_PASS" ]] || { echo "ERROR: UNIFI_USER and UNIFI_PASS are required." >&2; exit 2; }
command -v curl >/dev/null || { echo "ERROR: curl is required." >&2; exit 1; }
command -v jq >/dev/null || { echo "ERROR: jq is required." >&2; exit 1; }

BLOCKLIST_URL="${1:-}"
GROUP_NAME="${2:-}"
API="$UNIFI_URL/proxy/network/api/s/$UNIFI_SITE/rest/firewallgroup"

if (( $# == 0 )); then
    failed=0
    for item in "${DEFAULT_GROUPS[@]}"; do
        group_name="${item%%|*}"
        blocklist_url="${item#*|}"
        "$0" "$blocklist_url" "$group_name" || failed=1
    done
    exit "$failed"
fi

TMP_DIR="$(mktemp -d)"
RAW="$TMP_DIR/raw.txt"
LIST="$TMP_DIR/list.txt"
COOKIE="$TMP_DIR/cookies.txt"
HEADERS="$TMP_DIR/headers.txt"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading blocklist..."
curl -fsSL "$BLOCKLIST_URL" -o "$RAW"
grep -Ev '^[[:space:]]*(#|$)' "$RAW" > "$LIST" || true

COUNT="$(grep -cve '^[[:space:]]*$' "$LIST" || true)"
(( COUNT > 0 )) || { echo "ERROR: downloaded blocklist is empty." >&2; exit 1; }
if (( COUNT > MAX_ENTRIES )); then
    echo "ERROR: blocklist contains $COUNT entries; maximum is $MAX_ENTRIES." >&2
    echo "No UniFi changes were made." >&2
    exit 1
fi

echo "Entries: $COUNT"

LOGIN_JSON="$(jq -nc --arg username "$UNIFI_USER" --arg password "$UNIFI_PASS" '{username:$username,password:$password,remember:true}')"
HTTP_CODE="$(curl -skS -o /dev/null -D "$HEADERS" -c "$COOKIE" -w '%{http_code}' -H 'Content-Type: application/json' -X POST --data "$LOGIN_JSON" "$UNIFI_URL/api/auth/login")"
[[ "$HTTP_CODE" == "200" ]] || { echo "ERROR: UniFi login failed (HTTP $HTTP_CODE)." >&2; exit 1; }

CSRF="$(awk 'BEGIN{IGNORECASE=1} /^x-updated-csrf-token:/ || /^x-csrf-token:/ {sub(/\r$/, "", $2); token=$2} END {print token}' "$HEADERS")"
if [[ -z "$CSRF" ]]; then
    TOKEN="$(awk '$6 == "TOKEN" {print $7}' "$COOKIE" | tail -n1)"
    if [[ -n "$TOKEN" ]]; then
        PAYLOAD="$(cut -d. -f2 <<<"$TOKEN" | tr '_-' '/+')"
        case $((${#PAYLOAD} % 4)) in 2) PAYLOAD="${PAYLOAD}==" ;; 3) PAYLOAD="${PAYLOAD}=" ;; esac
        CSRF="$(printf '%s' "$PAYLOAD" | base64 -d 2>/dev/null | jq -r '.csrfToken // empty' || true)"
    fi
fi
[[ -n "$CSRF" ]] || { echo "ERROR: could not obtain UniFi CSRF token." >&2; exit 1; }

api() {
    curl -skS -b "$COOKIE" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' "$@"
}

echo "Looking up IP group..."
GROUPS="$(api "$API")"
GROUP_ID="$(jq -r --arg name "$GROUP_NAME" '.data[]? | select(.name == $name and .group_type == "address-group") | ._id' <<<"$GROUPS" | head -n1)"
MEMBERS="$(jq -Rsc 'split("\n") | map(gsub("^[[:space:]]+|[[:space:]]+$"; "")) | map(select(length > 0))' < "$LIST")"

if [[ -n "$GROUP_ID" ]]; then
    SITE_ID="$(jq -r --arg id "$GROUP_ID" '.data[]? | select(._id == $id) | .site_id // empty' <<<"$GROUPS")"
    PAYLOAD="$(jq -nc --arg name "$GROUP_NAME" --arg id "$GROUP_ID" --arg site_id "$SITE_ID" --argjson members "$MEMBERS" '{name:$name,group_type:"address-group",group_members:$members,_id:$id} + (if $site_id != "" then {site_id:$site_id} else {} end)')"
    echo "Updating '$GROUP_NAME'..."
    RESPONSE="$(api -X PUT --data "$PAYLOAD" "$API/$GROUP_ID")"
else
    PAYLOAD="$(jq -nc --arg name "$GROUP_NAME" --argjson members "$MEMBERS" '{name:$name,group_type:"address-group",group_members:$members}')"
    echo "Creating '$GROUP_NAME'..."
    RESPONSE="$(api -X POST --data "$PAYLOAD" "$API")"
fi

if ! jq -e '.meta.rc == "ok"' >/dev/null 2>&1 <<<"$RESPONSE"; then
    echo "ERROR: UniFi rejected the change:" >&2
    jq . <<<"$RESPONSE" >&2 || printf '%s\n' "$RESPONSE" >&2
    exit 1
fi

echo "OK: '$GROUP_NAME' now contains $COUNT entries."
