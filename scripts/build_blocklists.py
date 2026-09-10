#!/usr/bin/env python3
"""Build MikroTik RouterOS address-list imports from selected FireHOL feeds."""

from __future__ import annotations

import ipaddress
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

API_BASE = "https://iplists.firehol.org/api/v1/sets"
OUTPUT_DIR = Path("dist")
README_PATH = Path("README.md")
TIMEOUT_SECONDS = 60
USER_AGENT = "firehol-mikrotik-builder/1.0"
ROUTEROS_LIST_PREFIX = "firehol"

README_TABLE_START = "<!-- BLOCKLIST_COUNTS_START -->"
README_TABLE_END = "<!-- BLOCKLIST_COUNTS_END -->"

# Define exactly which output files/lists to generate.
#
# Key:
#   Output filename and MikroTik address-list suffix.
#
# Value:
#   One or more FireHOL feed names to merge.
LISTS: dict[str, tuple[str, ...]] = {
    "level1": (
        "firehol_level1",
    ),
    "level2": (
        "firehol_level2",
    ),
    "level3": (
        "firehol_level3",
    ),
    "webserver": (
        "firehol_webserver",
    ),
    "etblock": (
        "et_block",
    ),
    "dshield": (
        "dshield_7d",
    ),
    "botscout": (
        "botscout_7d",
    ),
    "blocklistde": (
        "blocklist_de",
    ),
    "combined1": (
        "firehol_level1",
        "firehol_level2",
    ),
    "combined2": (
        "firehol_level2",
        "firehol_level3",
    ),
    "combined3": (
        "firehol_level1",
        "firehol_webserver",
    ),
    "combined4": (
        "firehol_level1",
        "firehol_level2",
        "firehol_level3",
    ),
}

SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def safe_name(value: str) -> str:
    """Return a RouterOS/file-safe name."""
    return SAFE_NAME_RE.sub("-", value).strip("-").lower()


def required_feeds() -> tuple[str, ...]:
    """Return unique FireHOL feeds in deterministic order."""
    seen: set[str] = set()
    feeds: list[str] = []

    for sources in LISTS.values():
        for feed in sources:
            if feed not in seen:
                seen.add(feed)
                feeds.append(feed)

    return tuple(feeds)


def validate_config() -> None:
    """Validate output names and feed definitions."""
    if not LISTS:
        raise RuntimeError("LISTS must contain at least one output definition")

    normalized_names: set[str] = set()

    for output_name, feeds in LISTS.items():
        normalized = safe_name(output_name)

        if not normalized:
            raise RuntimeError(f"invalid output name: {output_name!r}")

        if normalized in normalized_names:
            raise RuntimeError(
                f"duplicate normalized output name: {normalized!r}"
            )

        normalized_names.add(normalized)

        if not feeds:
            raise RuntimeError(
                f"{output_name}: at least one FireHOL feed is required"
            )

        if len(feeds) != len(set(feeds)):
            raise RuntimeError(
                f"{output_name}: duplicate FireHOL feeds are not allowed"
            )


def fetch_feed(name: str) -> set[ipaddress.IPv4Network]:
    """Download and validate one FireHOL IPv4 feed."""
    url = f"{API_BASE}/{name}/data"

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=TIMEOUT_SECONDS,
        ) as response:
            if response.status != 200:
                raise RuntimeError(f"{name}: HTTP {response.status}")

            body = response.read().decode("utf-8")
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(
            f"{name}: download failed: {exc}"
        ) from exc

    networks: set[ipaddress.IPv4Network] = set()

    for line_number, raw_line in enumerate(body.splitlines(), 1):
        value = raw_line.strip()

        if not value or value.startswith("#"):
            continue

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuntimeError(
                f"{name}: invalid address at line "
                f"{line_number}: {value!r}"
            ) from exc

        if network.version == 4:
            networks.add(network)

    if not networks:
        raise RuntimeError(f"{name}: feed is empty")

    return networks


def collapse(
    networks: set[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    """Collapse overlapping and adjacent IPv4 networks."""
    return list(ipaddress.collapse_addresses(networks))


def routeros_quote(value: str) -> str:
    """Quote a RouterOS string safely."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def write_rsc(
    path: Path,
    list_name: str,
    feeds: tuple[str, ...],
    networks: list[ipaddress.IPv4Network],
) -> None:
    """Write one MikroTik RouterOS import file."""
    comment = f"FireHOL: {' + '.join(feeds)}"

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        handle.write(f"# Generated from: {', '.join(feeds)}\n")
        handle.write(f"# Entries: {len(networks)}\n")
        handle.write("/ip firewall address-list\n")

        for network in networks:
            address = (
                str(network.network_address)
                if network.prefixlen == 32
                else str(network)
            )

            handle.write(
                "add "
                f"list={routeros_quote(list_name)} "
                f"address={routeros_quote(address)} "
                f"comment={routeros_quote(comment)}\n"
            )


def build_lists(
    downloaded: dict[str, set[ipaddress.IPv4Network]],
) -> dict[str, int]:
    """Build every configured MikroTik list and return generated counts."""
    counts: dict[str, int] = {}

    for output_name, feeds in LISTS.items():
        merged: set[ipaddress.IPv4Network] = set()

        for feed in feeds:
            merged.update(downloaded[feed])

        networks = collapse(merged)

        safe_output_name = safe_name(output_name)
        list_name = f"{ROUTEROS_LIST_PREFIX}-{safe_output_name}"
        output = OUTPUT_DIR / f"{safe_output_name}.rsc"

        write_rsc(
            output,
            list_name,
            feeds,
            networks,
        )

        counts[output_name] = len(networks)

        print(
            f"built   {output}: "
            f"{len(networks):,} entries "
            f"from {len(feeds)} feed(s)"
        )

    return counts


def build_readme_table(counts: dict[str, int]) -> str:
    """Build the generated Markdown blocklist-count table."""
    lines = [
        README_TABLE_START,
        "| List | FireHOL Sources | IP/CIDR Count |",
        "|---|---|---:|",
    ]

    for output_name, feeds in LISTS.items():
        sources = " + ".join(f"`{feed}`" for feed in feeds)
        count = counts[output_name]

        lines.append(
            f"| `{safe_name(output_name)}` | {sources} | {count:,} |"
        )

    lines.append(README_TABLE_END)
    return "\n".join(lines)


def update_readme(counts: dict[str, int]) -> None:
    """Replace only the generated blocklist-count section in README.md."""
    if not README_PATH.exists():
        raise RuntimeError(
            f"{README_PATH} not found; "
            "create it with the blocklist marker section first"
        )

    content = README_PATH.read_text(encoding="utf-8")

    start = content.find(README_TABLE_START)
    end = content.find(README_TABLE_END)

    if start == -1 or end == -1:
        raise RuntimeError(
            f"{README_PATH} must contain both "
            f"{README_TABLE_START} and {README_TABLE_END}"
        )

    if end < start:
        raise RuntimeError(
            f"{README_PATH}: blocklist count markers are in the wrong order"
        )

    end += len(README_TABLE_END)

    generated_table = build_readme_table(counts)

    updated = (
        content[:start]
        + generated_table
        + content[end:]
    )

    if updated != content:
        README_PATH.write_text(
            updated,
            encoding="utf-8",
            newline="\n",
        )
        print(f"updated {README_PATH}")
    else:
        print(f"unchanged {README_PATH}")


def main() -> int:
    try:
        validate_config()

        OUTPUT_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        # Remove stale generated files from previous configurations.
        for old_file in OUTPUT_DIR.glob("*.rsc"):
            old_file.unlink()

        downloaded: dict[str, set[ipaddress.IPv4Network]] = {}

        for feed in required_feeds():
            networks = fetch_feed(feed)
            downloaded[feed] = networks

            print(
                f"fetched {feed}: "
                f"{len(networks):,} entries"
            )

        counts = build_lists(downloaded)
        update_readme(counts)

        print(
            f"done: {len(counts)} RSC file(s) "
            f"in {OUTPUT_DIR}/"
        )

        return 0

    except RuntimeError as exc:
        print(
            f"error: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
