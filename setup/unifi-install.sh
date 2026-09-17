#!/usr/bin/env bash
# UBIQUITI UNIFI UDR UCG installer
# ipbl.dennyhalim.com
set -euo pipefail

INSTALL_DIR="/data/dhblocklist"
CONFIG_FILE="$INSTALL_DIR/config"
UPDATE_SCRIPT="$INSTALL_DIR/update.sh"
SERVICE_NAME="dhblocklist.service"
TIMER_NAME="dhblocklist.timer"
SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME"
TIMER_FILE="/etc/systemd/system/$TIMER_NAME"
TABLE_NAME="dhblocklists"
SET_NAME="blocked_ipv4"
UPDATE_MINUTES=30
DEFAULT_BLOCKLIST_URL="https://blacklists.pages.dev/dist/plain/complete.txt"

usage() {
    cat <<'EOF'
UBIQUITI UNIFI UDR UCG installer ipbl.dennyhalim.com

Usage:
  sudo ./ui-install.sh [URL...]

Without URLs, the default blocklist is used.

Examples:
  sudo ./ui-install.sh

  sudo ./ui-install.sh \
    https://blacklists.pages.dev/dist/plain/combined2.txt \
    https://blacklists.pages.dev/dist/plain/level2.txt

The URLs are stored in /data/blocklist/config.
EOF
}

if [[ "$(id -u)" -ne 0 ]]; then
    echo "error: run as root" >&2
    exit 1
fi

if (( $# == 0 )); then
    set -- "$DEFAULT_BLOCKLIST_URL"
    echo "No blocklist URL supplied; using default:"
    echo "  $DEFAULT_BLOCKLIST_URL"
fi

for cmd in nft curl ip awk sort grep mktemp systemctl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "error: required command not found: $cmd" >&2
        exit 1
    fi
done

mkdir -p "$INSTALL_DIR"

{
    echo '# Managed by ipbl.dennyhalim.com install.sh'
    echo 'BLOCKLIST_URLS=('
    for url in "$@"; do
        printf '    %q\n' "$url"
    done
    echo ')'
} > "$CONFIG_FILE"
chmod 0600 "$CONFIG_FILE"

cat > "$UPDATE_SCRIPT" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/data/ipblocklist"
CONFIG_FILE="$INSTALL_DIR/config"
TABLE_NAME="ipblocklists"
SET_NAME="blocked_ipv4"

log() {
    logger -t blocklist -- "$*" 2>/dev/null || true
    printf '%s\n' "$*"
}

if [[ ! -r "$CONFIG_FILE" ]]; then
    log "config missing: $CONFIG_FILE"
    exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

if ! declare -p BLOCKLIST_URLS >/dev/null 2>&1 || (( ${#BLOCKLIST_URLS[@]} == 0 )); then
    log "no blocklist URLs configured"
    exit 1
fi

for cmd in nft curl ip awk sort grep mktemp; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        log "required command not found: $cmd"
        exit 1
    fi
done

TMP_DIR="$(mktemp -d)"
RAW_FILE="$TMP_DIR/raw.txt"
LIST_FILE="$TMP_DIR/list.txt"
NFT_FILE="$TMP_DIR/blocklist.nft"

cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

: > "$RAW_FILE"

for url in "${BLOCKLIST_URLS[@]}"; do
    log "downloading: $url"
    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout 15 \
        --max-time 120 \
        --retry 2 \
        "$url" >> "$RAW_FILE"
    printf '\n' >> "$RAW_FILE"
done

awk '
{
    sub(/\r$/, "")
    sub(/[[:space:]]*#.*/, "")
    gsub(/^[[:space:]]+|[[:space:]]+$/, "")
    if ($0 == "") next

    if ($0 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}(\/[0-9]{1,2})?$/) {
        print
        next
    }

    printf "warning: ignored non-IPv4 entry: %s\n", $0 > "/dev/stderr"
}
' "$RAW_FILE" | sort -u > "$LIST_FILE"

if [[ ! -s "$LIST_FILE" ]]; then
    log "download produced no valid IPv4 entries"
    exit 1
fi

WAN_IF="$(
    ip -4 route show default 2>/dev/null |
    awk 'NR == 1 {
        for (i = 1; i <= NF; i++) {
            if ($i == "dev") {
                print $(i + 1)
                exit
            }
        }
    }'
)"

if [[ -z "$WAN_IF" ]]; then
    log "unable to detect WAN interface"
    exit 1
fi

{
    cat <<EOF_NFT
table inet $TABLE_NAME {
    set $SET_NAME {
        type ipv4_addr
        flags interval
        elements = {
EOF_NFT

    sed 's/^/            /; s/$/,/' "$LIST_FILE"

    cat <<EOF_NFT
        }
    }

    chain wan_ingress {
        type filter hook ingress device "$WAN_IF" priority -300; policy accept;
        ip saddr @$SET_NAME drop
    }
}
EOF_NFT
} > "$NFT_FILE"

# Validate using a temporary table name so repeated updates do not collide
# with the currently active table during nft --check.
CHECK_TABLE="${TABLE_NAME}_check_$$"
CHECK_FILE="$TMP_DIR/blocklist-check.nft"
sed "s/table inet $TABLE_NAME/table inet $CHECK_TABLE/" "$NFT_FILE" > "$CHECK_FILE"

if ! nft --check --file "$CHECK_FILE"; then
    log "generated nftables rules failed validation"
    exit 1
fi

# Our table is intentionally isolated from UniFi-managed tables.
# Rebuild it only after the new ruleset has passed validation.
nft delete table inet "$TABLE_NAME" >/dev/null 2>&1 || true

if ! nft --file "$NFT_FILE"; then
    log "failed to load nftables rules"
    exit 1
fi

COUNT="$(wc -l < "$LIST_FILE" | tr -d ' ')"
log "loaded $COUNT entries on WAN interface $WAN_IF"
EOF

chmod 0755 "$UPDATE_SCRIPT"

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Refresh UniFi ipbl.dennyhalim.com blocklist
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$UPDATE_SCRIPT
EOF

cat > "$TIMER_FILE" <<EOF
[Unit]
Description=Refresh UniFi ipbl.dennyhalim.com blocklist periodically

[Timer]
OnBootSec=2min
OnUnitActiveSec=${UPDATE_MINUTES}min
Persistent=true
Unit=$SERVICE_NAME

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable "$TIMER_NAME"
systemctl restart "$TIMER_NAME"
systemctl start "$SERVICE_NAME"

echo
echo "Installed."
echo "Config:  $CONFIG_FILE"
echo "Updater: $UPDATE_SCRIPT"
echo "Timer:   every ${UPDATE_MINUTES} minutes"
echo
echo "Useful commands:"
echo "  systemctl status $SERVICE_NAME"
echo "  systemctl status $TIMER_NAME"
echo "  $UPDATE_SCRIPT"
echo "  nft list table inet $TABLE_NAME"
