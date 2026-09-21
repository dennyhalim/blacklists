#!/usr/bin/env bash
set -euo pipefail

# Cluster-shared configuration.
URLS=(
    "https://blacklists.pages.dev/dist/plain/complete.txt"
)

IPSET="dh-blacklist"
TMPSET="${IPSET}-new"
CHAIN="DH-BLACKLIST"

WORKDIR="$(mktemp -d /var/tmp/pve-blacklist.XXXXXX)"
trap 'rm -rf "$WORKDIR"' EXIT

RAW="$WORKDIR/raw"
LIST="$WORKDIR/networks"

log() {
    logger -t dh-blacklist "$*"
    printf '[%s] %s\n' "$(date '+%F %T')" "$*"
}

die() {
    log "ERROR: $*"
    exit 1
}

for cmd in curl python3 ipset iptables; do
    command -v "$cmd" >/dev/null ||
        die "Required command not found: $cmd"
done

: > "$RAW"

# Download all sources. Do not alter the active firewall if any source fails.
for url in "${URLS[@]}"; do
    file="$WORKDIR/download"

    log "Downloading $url"

    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout 15 \
        --max-time 180 \
        --output "$file" \
        "$url" ||
        die "Download failed: $url"

    [[ -s "$file" ]] ||
        die "Downloaded empty list: $url"

    cat "$file" >> "$RAW"
    printf '\n' >> "$RAW"
done

# Extract, validate, deduplicate and collapse IPv4/CIDR networks.
python3 - "$RAW" "$LIST" <<'PY'
import ipaddress
import re
import sys

source, output = sys.argv[1:]

networks = set()

# IPv4 or IPv4/CIDR embedded in whitespace/CSV/pipe-separated feeds.
pattern = re.compile(
    r'(?<![\d.])'
    r'(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)'
    r'(?![\d.])'
)

with open(source, encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.split("#", 1)[0]

        for value in pattern.findall(line):
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError:
                continue

            if network.version == 4:
                networks.add(network)

collapsed = list(ipaddress.collapse_addresses(networks))

with open(output, "w", encoding="utf-8") as f:
    for network in collapsed:
        f.write(f"{network}\n")
PY

COUNT="$(wc -l < "$LIST")"

(( COUNT > 0 )) ||
    die "No valid IPv4 networks found"

log "Prepared $COUNT IPv4 networks"

# Remove stale temporary set from an interrupted previous update.
ipset destroy "$TMPSET" 2>/dev/null || true

# hash:net handles both individual IPv4 addresses and CIDRs.
ipset create "$TMPSET" \
    hash:net \
    family inet \
    hashsize 65536 \
    maxelem 1000000

# Populate the temporary set.
while IFS= read -r network; do
    ipset add "$TMPSET" "$network"
done < "$LIST"

# Sanity check.
LOADED="$(ipset list "$TMPSET" | awk '/Number of entries:/ {print $4}')"

[[ "$LOADED" =~ ^[0-9]+$ ]] ||
    die "Unable to verify temporary IPSet"

(( LOADED > 0 )) ||
    die "Temporary IPSet is empty"

log "Loaded $LOADED networks into temporary IPSet"

# Create active set on first run.
if ! ipset list "$IPSET" >/dev/null 2>&1; then
    ipset create "$IPSET" \
        hash:net \
        family inet \
        hashsize 65536 \
        maxelem 1000000
fi

# Atomic set replacement.
ipset swap "$TMPSET" "$IPSET"
ipset destroy "$TMPSET"

# Create our own chain if necessary.
iptables -w -N "$CHAIN" 2>/dev/null || true

# Ensure exactly one blacklist rule exists inside it.
if ! iptables -w -C "$CHAIN" \
    -m set --match-set "$IPSET" src \
    -j DROP 2>/dev/null; then

    iptables -w -A "$CHAIN" \
        -m set --match-set "$IPSET" src \
        -j DROP
fi

# Protect traffic destined for the Proxmox host.
if ! iptables -w -C INPUT \
    -j "$CHAIN" 2>/dev/null; then

    iptables -w -I INPUT 1 \
        -j "$CHAIN"
fi

# Protect traffic forwarded to/from VMs and CTs.
if ! iptables -w -C FORWARD \
    -j "$CHAIN" 2>/dev/null; then

    iptables -w -I FORWARD 1 \
        -j "$CHAIN"
fi

log "Blacklist updated successfully: $LOADED networks"
