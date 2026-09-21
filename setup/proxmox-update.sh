#!/usr/bin/env bash
set -euo pipefail

# Shared through pmxcfs. Large downloaded lists remain node-local.
URLS=(
    "https://blacklists.pages.dev/dist/plain/complete.txt"
)

TABLE="dh_blacklist"
SET4="dhblocked_ipv4"
SET6="dhblocked_ipv6"

WORKDIR="$(mktemp -d /var/tmp/dh-blacklist.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

RAW="$WORKDIR/raw"
NFT="$WORKDIR/rules.nft"

log() {
    logger -t dh-blacklist "$*"
    printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

die() {
    log "ERROR: $*"
    exit 1
}

command -v curl >/dev/null || die "curl not installed"
command -v nft >/dev/null || die "nftables not installed"

: > "$RAW"

# All feeds must succeed. Keep the existing firewall on any failure.
for url in "${URLS[@]}"; do
    log "Downloading $url"

    tmp="$WORKDIR/download"

    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout 15 \
        --max-time 180 \
        --output "$tmp" \
        "$url" ||
        die "Download failed: $url"

    [[ -s "$tmp" ]] || die "Empty download: $url"

    cat "$tmp" >> "$RAW"
    printf '\n' >> "$RAW"
done

# Parse, validate, deduplicate and collapse IPv4/IPv6 networks.
python3 - "$RAW" "$WORKDIR/v4" "$WORKDIR/v6" <<'PY'
import ipaddress
import re
import sys

source, out4, out6 = sys.argv[1:]

v4 = set()
v6 = set()

# Finds IP or CIDR even in simple CSV/pipe/space-separated feeds.
token = re.compile(
    r'(?<![0-9A-Fa-f:.])'
    r'([0-9A-Fa-f:.]+(?:/\d{1,3})?)'
    r'(?![0-9A-Fa-f:.])'
)

with open(source, encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.split("#", 1)[0]

        for match in token.findall(line):
            try:
                net = ipaddress.ip_network(match, strict=False)
            except ValueError:
                continue

            (v4 if net.version == 4 else v6).add(net)

v4 = list(ipaddress.collapse_addresses(v4))
v6 = list(ipaddress.collapse_addresses(v6))

with open(out4, "w") as f:
    for net in v4:
        f.write(f"{net}\n")

with open(out6, "w") as f:
    for net in v6:
        f.write(f"{net}\n")
PY

COUNT4="$(wc -l < "$WORKDIR/v4")"
COUNT6="$(wc -l < "$WORKDIR/v6")"
TOTAL=$((COUNT4 + COUNT6))

(( TOTAL > 0 )) || die "No valid IP/CIDR entries found"

log "Parsed $COUNT4 IPv4 and $COUNT6 IPv6 networks"

# Generate complete nftables table.
{
    echo "table inet $TABLE {"

    echo "    set $SET4 {"
    echo "        type ipv4_addr"
    echo "        flags interval"
    echo "        auto-merge"

    if (( COUNT4 > 0 )); then
        echo "        elements = {"
        sed 's/^/            /; s/$/,/' "$WORKDIR/v4"
        echo "        }"
    fi

    echo "    }"

    echo "    set $SET6 {"
    echo "        type ipv6_addr"
    echo "        flags interval"
    echo "        auto-merge"

    if (( COUNT6 > 0 )); then
        echo "        elements = {"
        sed 's/^/            /; s/$/,/' "$WORKDIR/v6"
        echo "        }"
    fi

    echo "    }"

    # Protect the Proxmox host itself.
    echo "    chain input {"
    echo "        type filter hook input priority -20; policy accept;"
    echo "        ip saddr @$SET4 drop"
    echo "        ip6 saddr @$SET6 drop"
    echo "    }"

    # Protect routed VM/CT traffic.
    echo "    chain forward {"
    echo "        type filter hook forward priority -20; policy accept;"
    echo "        ip saddr @$SET4 drop"
    echo "        ip6 saddr @$SET6 drop"
    echo "    }"

    echo "}"
} > "$NFT"

# Syntax-check before touching the active firewall.
nft -c -f "$NFT" ||
    die "Generated nftables configuration is invalid"

# Replace only our own table.
# Existing Proxmox nftables configuration is untouched.
nft list table inet "$TABLE" >/dev/null 2>&1 &&
    nft delete table inet "$TABLE"

if ! nft -f "$NFT"; then
    log "ERROR: Failed to load new blacklist table"
    exit 1
fi

log "dhBlacklist updated successfully: $TOTAL networks"
