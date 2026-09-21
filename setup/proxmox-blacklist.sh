#!/usr/bin/env bash
set -euo pipefail

# Proxmox VE blacklist updater
# Run on ONE node in the cluster.
#
# Format:
#   "name|url|group1,group2,..."
#
# No group:
#   merged into Proxmox's special "blacklist" IPSet (global block)
#
# With group(s):
#   creates [IPSET name] and adds a DROP rule to those security groups.

LISTS=(
    "list1|https://example.com/list1.txt|"
    "list2|https://example.com/list2.txt|webservers"
    "list3|https://example.com/list3.txt|mailservers,databases"
)

CLUSTER_FW="/etc/pve/firewall/cluster.fw"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

log() {
    logger -t proxmox-blacklist "$*"
    echo "[$(date '+%F %T')] $*"
}

die() {
    log "ERROR: $*"
    exit 1
}

[[ -f "$CLUSTER_FW" ]] || die "$CLUSTER_FW not found"

# ---------------------------------------------------------------------------
# Download and normalize lists
# ---------------------------------------------------------------------------

GLOBAL_RAW="$WORKDIR/global.raw"
: > "$GLOBAL_RAW"

declare -a SCOPED_NAMES=()
declare -A SCOPED_GROUPS=()

SUCCESS=0

for entry in "${LISTS[@]}"; do
    IFS='|' read -r name url groups <<< "$entry"

    [[ -n "$name" ]] || die "List name is empty"
    [[ -n "$url" ]] || die "URL is empty for '$name'"

    # Keep generated Proxmox identifiers simple and predictable.
    [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] ||
        die "Invalid list name: $name"

    raw="$WORKDIR/$name.raw"

    log "Downloading '$name': $url"

    if ! curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --connect-timeout 15 \
        --max-time 120 \
        --output "$raw" \
        "$url"; then
        log "WARNING: failed to download '$name'"
        continue
    fi

    ((SUCCESS += 1))

    if [[ -z "$groups" ]]; then
        cat "$raw" >> "$GLOBAL_RAW"
        echo >> "$GLOBAL_RAW"
    else
        SCOPED_NAMES+=("$name")
        SCOPED_GROUPS["$name"]="$groups"
    fi
done

(( SUCCESS > 0 )) || die "All blacklist downloads failed"

# ---------------------------------------------------------------------------
# Normalize IPv4/CIDR lists
# ---------------------------------------------------------------------------

normalize() {
    local source="$1"
    local output="$2"

    python3 - "$source" "$output" <<'PY'
import ipaddress
import sys

source, output = sys.argv[1:]
networks = set()

with open(source, encoding="utf-8", errors="ignore") as f:
    for raw in f:
        # Supports:
        #   1.2.3.4
        #   1.2.3.0/24
        # and comments after '#'.
        line = raw.split("#", 1)[0].strip()

        if not line:
            continue

        try:
            network = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue

        if network.version == 4:
            networks.add(network)

networks = sorted(
    networks,
    key=lambda n: (int(n.network_address), n.prefixlen),
)

with open(output, "w", encoding="utf-8") as f:
    for network in networks:
        f.write(f"{network}\n")
PY
}

# ---------------------------------------------------------------------------
# Generate managed configuration
# ---------------------------------------------------------------------------

MANAGED="$WORKDIR/managed.conf"
: > "$MANAGED"

# Global blacklist
if [[ -s "$GLOBAL_RAW" ]]; then
    GLOBAL_LIST="$WORKDIR/global.list"
    normalize "$GLOBAL_RAW" "$GLOBAL_LIST"

    count="$(wc -l < "$GLOBAL_LIST")"

    if (( count > 0 )); then
        {
            echo "[IPSET blacklist]"
            cat "$GLOBAL_LIST"
            echo
        } >> "$MANAGED"

        log "Global blacklist: $count networks"
    fi
fi

# Scoped blacklists
for name in "${SCOPED_NAMES[@]}"; do
    raw="$WORKDIR/$name.raw"
    list="$WORKDIR/$name.list"

    normalize "$raw" "$list"

    count="$(wc -l < "$list")"

    if (( count == 0 )); then
        log "WARNING: '$name' contains no valid networks"
        continue
    fi

    {
        echo "[IPSET $name]"
        cat "$list"
        echo
    } >> "$MANAGED"

    log "'$name': $count networks"
done

# ---------------------------------------------------------------------------
# Add blacklist rules to security groups
# ---------------------------------------------------------------------------

for name in "${SCOPED_NAMES[@]}"; do
    [[ -s "$WORKDIR/$name.list" ]] || continue

    IFS=',' read -ra groups <<< "${SCOPED_GROUPS[$name]}"

    for group in "${groups[@]}"; do
        group="${group//[[:space:]]/}"

        [[ -n "$group" ]] || continue

        printf 'GROUP_RULE|%s|%s\n' "$group" "$name" \
            >> "$WORKDIR/group-rules"
    done
done

# ---------------------------------------------------------------------------
# Safely update cluster.fw
#
# Managed objects:
#   [IPSET blacklist]
#   [IPSET <configured scoped list>]
#   generated DROP rules inside configured security groups
#
# Existing unrelated configuration is preserved.
# ---------------------------------------------------------------------------

python3 - \
    "$CLUSTER_FW" \
    "$MANAGED" \
    "$WORKDIR/group-rules" \
    "${LISTS[@]}" <<'PY'
import os
import re
import sys
import tempfile

config = sys.argv[1]
managed_file = sys.argv[2]
rules_file = sys.argv[3]
entries = sys.argv[4:]

managed_ipsets = {"blacklist"}
configured_rules = {}

for entry in entries:
    name, url, groups = entry.split("|", 2)

    if groups:
        managed_ipsets.add(name)

        for group in groups.split(","):
            group = group.strip()
            if group:
                configured_rules.setdefault(group, set()).add(name)

with open(config, encoding="utf-8") as f:
    lines = f.readlines()

with open(managed_file, encoding="utf-8") as f:
    managed = f.read()

# ------------------------------------------------------------
# Remove IPSET sections managed by this script.
# ------------------------------------------------------------

result = []
skip = False

for line in lines:
    stripped = line.strip()

    match = re.fullmatch(r"\[IPSET ([^\]]+)\]", stripped)

    if match:
        skip = match.group(1) in managed_ipsets

        if skip:
            continue

    elif stripped.startswith("[") and stripped.endswith("]"):
        skip = False

    if not skip:
        result.append(line)

# ------------------------------------------------------------
# Remove our generated DROP rules.
# They are deterministic:
#
#   IN DROP -source +<ipset>
# ------------------------------------------------------------

cleaned = []
current_group = None

for line in result:
    stripped = line.strip()

    match = re.fullmatch(r"\[group ([^\]]+)\]", stripped)

    if match:
        current_group = match.group(1)

    elif stripped.startswith("[") and stripped.endswith("]"):
        current_group = None

    remove = False

    if current_group in configured_rules:
        for ipset in configured_rules[current_group]:
            if stripped == f"IN DROP -source +{ipset}":
                remove = True
                break

    if not remove:
        cleaned.append(line)

result = cleaned

# ------------------------------------------------------------
# Add scoped rules into existing groups.
# ------------------------------------------------------------

output = []
inserted = set()

for line in result:
    stripped = line.strip()

    match = re.fullmatch(r"\[group ([^\]]+)\]", stripped)

    if match:
        group = match.group(1)

        output.append(line)

        if group in configured_rules:
            for ipset in sorted(configured_rules[group]):
                output.append(
                    f"IN DROP -source +{ipset}\n"
                )

            inserted.add(group)

        continue

    output.append(line)

# Refuse to silently create missing security groups.
missing = set(configured_rules) - inserted

if missing:
    raise SystemExit(
        "Security group(s) not found: "
        + ", ".join(sorted(missing))
    )

# ------------------------------------------------------------
# Append generated IPSet sections.
# ------------------------------------------------------------

if output and output[-1].strip():
    output.append("\n")

output.append(managed)

# ------------------------------------------------------------
# Atomic replacement.
# ------------------------------------------------------------

directory = os.path.dirname(config)

fd, tmp = tempfile.mkstemp(
    dir=directory,
    prefix=".blacklist-",
)

try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.writelines(output)

    os.replace(tmp, config)

except Exception:
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    raise
PY

log "Blacklist update completed"
