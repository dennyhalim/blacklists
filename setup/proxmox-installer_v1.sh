#!/usr/bin/env bash
# bl.dennyhalim.com
# use updated proxmox-blacklist.sh

set -euo pipefail

IPSET="dhblacklist"
CLUSTER_FW="/etc/pve/firewall/cluster.fw"

URLS=(
    "https://blacklists.pages.dev/dist/plain/complete.txt"
#    "https://blacklists.pages.dev/dist/plain/combined4server.txt" #may include a large number of false positives
)

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

RAW="$WORKDIR/raw.txt"
LIST="$WORKDIR/dhblacklist.txt"
SECTION="$WORKDIR/ipset.txt"

log() {
    logger -t dh-blacklist "$*"
    echo "[$(date '+%F %T')] $*"
}

# Download and merge all sources.
: > "$RAW"

SUCCESS=0

for url in "${URLS[@]}"; do
    log "Downloading: $url"

    if curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout 15 \
        --max-time 120 \
        "$url" >> "$RAW"; then

        echo >> "$RAW"
        ((SUCCESS += 1))
    else
        log "WARNING: failed to download: $url"
    fi
done

if (( SUCCESS == 0 )); then
    log "ERROR: all blacklist downloads failed"
    exit 1
fi

log "Downloaded $SUCCESS/${#URLS[@]} sources"

# Validate, normalize and deduplicate IPv4/CIDR entries.
python3 - "$RAW" "$LIST" <<'PY'
import ipaddress
import sys

source, output = sys.argv[1:]
networks = set()

with open(source, encoding="utf-8") as f:
    for raw in f:
        line = raw.split("#", 1)[0].strip()

        if not line:
            continue

        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue

        if network.version == 4:
            networks.add(network)

if not networks:
    raise SystemExit("No valid IPv4 networks found")

networks = sorted(
    networks,
    key=lambda n: (int(n.network_address), n.prefixlen),
)

with open(output, "w", encoding="utf-8") as f:
    for network in networks:
        f.write(f"{network}\n")
PY

COUNT="$(wc -l < "$LIST")"

log "Merged blacklist contains $COUNT unique networks"

# Generate Proxmox IPSet section.
{
    echo "[IPSET $IPSET]"
    cat "$LIST"
    echo
} > "$SECTION"

# Replace only our managed IPSet section.
python3 - "$CLUSTER_FW" "$IPSET" "$SECTION" <<'PY'
import os
import sys
import tempfile

config, ipset, replacement = sys.argv[1:]

try:
    with open(config, encoding="utf-8") as f:
        lines = f.readlines()
except FileNotFoundError:
    lines = []

header = f"[IPSET {ipset}]"
result = []
skip = False

for line in lines:
    stripped = line.strip()

    if stripped == header:
        skip = True
        continue

    if skip and stripped.startswith("[") and stripped.endswith("]"):
        skip = False

    if not skip:
        result.append(line)

with open(replacement, encoding="utf-8") as f:
    new_section = f.read()

if result and result[-1].strip():
    result.append("\n")

result.append(new_section)

directory = os.path.dirname(config)
fd, tmp = tempfile.mkstemp(
    dir=directory,
    prefix=".blacklist-",
)

try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.writelines(result)

    os.replace(tmp, config)

except:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    raise
PY

log "Updated Proxmox IPSet '$IPSET' with $COUNT networks"
