#!/usr/bin/env python3
"""Build MikroTik RouterOS address-list imports from generic IPv4 blocklist URLs."""

from __future__ import annotations

import ipaddress
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

OUTPUT_DIR = Path("dist")
README_PATH = Path("README.md")
TIMEOUT_SECONDS = 60
USER_AGENT = "mikrotik-blocklist-builder/1.0"
ROUTEROS_LIST_PREFIX = "blocklist"

README_TABLE_START = "<!-- BLOCKLIST_COUNTS_START -->"
README_TABLE_END = "<!-- BLOCKLIST_COUNTS_END -->"

# Generic source definitions.
#
# Each URL should return plain text containing IPv4 addresses/CIDRs,
# one entry per line. Blank lines and lines starting with "#" are ignored.
SOURCES: dict[str, str] = {
    "level1": (
        "https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/firehol_level1.netset"
    ),
    "level2": (
        "https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/firehol_level2.netset"
    ),
    "level3": (
        "https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/firehol_level3.netset"
    ),
    "webserver": (
        "https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/firehol_webserver.netset"
    ),
}

# Define exactly which output files/lists to generate.
#
# Key:
#   Output filename and MikroTik address-list suffix.
#
# Value:
#   One or more source names from SOURCES to merge.
LISTS: dict[str, tuple[str, ...]] = {
    "level1": (
        "level1",
    ),
    "level2": (
        "level2",
    ),
    "level3": (
        "level3",
    ),
    "webserver": (
        "webserver",
    ),
    "combined1": (
        "level1",
        "level2",
    ),
    "combined2": (
        "level2",
        "level3",
    ),
    "combined3": (
        "level1",
        "webserver",
    ),
    "combined4": (
        "level1",
        "level2",
        "level3",
    ),
}

SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def safe_name(value: str) -> str:
    """Return a RouterOS/file-safe name."""
    return SAFE_NAME_RE.sub("-", value).strip("-").lower()


def required_sources() -> tuple[str, ...]:
    """Return unique source names in deterministic order."""
    seen: set[str] = set()
    sources: list[str] = []

    for source_names in LISTS.values():
        for source_name in source_names:
            if source_name not in seen:
                seen.add(source_name)
                sources.append(source_name)

    return tuple(sources)


def validate_config() -> None:
    """Validate source and output definitions."""
    if not SOURCES:
        raise RuntimeError("SOURCES must contain at least one source")

    if not LISTS:
        raise RuntimeError("LISTS must contain at least one output definition")

    normalized_names: set[str] = set()

    for source_name, url in SOURCES.items():
        if not safe_name(source_name):
            raise RuntimeError(f"invalid source name: {source_name!r}")

        if not url.startswith(("https://", "http://")):
            raise RuntimeError(
                f"{source_name}: URL must start with http:// or https://"
            )

    for output_name, source_names in LISTS.items():
        normalized = safe_name(output_name)

        if not normalized:
            raise RuntimeError(f"invalid output name: {output_name!r}")

        if normalized in normalized_names:
            raise RuntimeError(
                f"duplicate normalized output name: {normalized!r}"
            )

        normalized_names.add(normalized)

        if not source_names:
            raise RuntimeError(
                f"{output_name}: at least one source is required"
            )

        if len(source_names) != len(set(source_names)):
            raise RuntimeError(
                f"{output_name}: duplicate sources are not allowed"
            )

        missing = [
            source_name
            for source_name in source_names
            if source_name not in SOURCES
        ]

        if missing:
            raise RuntimeError(
                f"{output_name}: undefined source(s): {', '.join(missing)}"
            )


def fetch_source(name: str) -> set[ipaddress.IPv4Network]:
    """Download and validate one generic IPv4 blocklist source."""
    url = SOURCES[name]

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain,*/*;q=0.8",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=TIMEOUT_SECONDS,
        ) as response:
            body = response.read().decode("utf-8-sig")
    except (urllib.error.URLError, TimeoutError, UnicodeDecodeError) as exc:
        raise RuntimeError(
            f"{name}: download failed from {url}: {exc}"
        ) from exc

    networks: set[ipaddress.IPv4Network] = set()

    for line_number, raw_line in enumerate(body.splitlines(), 1):
        value = raw_line.strip()

        if not value or value.startswith("#"):
            continue

        # Allow simple inline comments after whitespace + "#".
        if " #" in value:
            value = value.split(" #", 1)[0].strip()

        try:
            network = ipaddress.ip_network(
                value,
                strict=False,
            )
        except ValueError as exc:
            raise RuntimeError(
                f"{name}: invalid IPv4/CIDR at line "
                f"{line_number}: {value!r}"
            ) from exc

        if network.version == 4:
            networks.add(network)

    if not networks:
        raise RuntimeError(f"{name}: source is empty")

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
    source_names: tuple[str, ...],
    networks: list[ipaddress.IPv4Network],
) -> None:
    """Write one MikroTik RouterOS import file."""
    comment = f"Sources: {' + '.join(source_names)}"

    with path.open(
        "w",
        encoding="utf-8",
        newline="\n",
    ) as handle:
        handle.write(f"# Generated from: {', '.join(source_names)}\n")
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

    for output_name, source_names in LISTS.items():
        merged: set[ipaddress.IPv4Network] = set()

        for source_name in source_names:
            merged.update(downloaded[source_name])

        networks = collapse(merged)

        safe_output_name = safe_name(output_name)
        list_name = f"{ROUTEROS_LIST_PREFIX}-{safe_output_name}"
        output = OUTPUT_DIR / f"{safe_output_name}.rsc"

        write_rsc(
            output,
            list_name,
            source_names,
            networks,
        )

        counts[output_name] = len(networks)

        print(
            f"built   {output}: "
            f"{len(networks):,} entries "
            f"from {len(source_names)} source(s)"
        )

    return counts


def build_readme_table(counts: dict[str, int]) -> str:
    """Build the generated Markdown blocklist-count table."""
    lines = [
        README_TABLE_START,
        "| List | Sources | IP/CIDR Count |",
        "|---|---|---:|",
    ]

    for output_name, source_names in LISTS.items():
        sources = " + ".join(f"`{name}`" for name in source_names)
        count = counts[output_name]

        lines.append(
            f"| `{safe_name(output_name)}` | {sources} | {count:,} |"
        )

    lines.append(README_TABLE_END)
    return "\n".join(lines)


def update_readme(counts: dict[str, int]) -> None:
    """Update or append the generated blocklist-count section in README.md."""
    generated_table = build_readme_table(counts)

    if not README_PATH.exists():
        content = (
            "# MikroTik Blocklists\n\n"
            "## Generated Lists\n\n"
            f"{generated_table}\n"
        )
        README_PATH.write_text(
            content,
            encoding="utf-8",
            newline="\n",
        )
        print(f"created {README_PATH}")
        return

    content = README_PATH.read_text(encoding="utf-8")

    start = content.find(README_TABLE_START)
    end = content.find(README_TABLE_END)

    if start == -1 and end == -1:
        separator = "" if not content or content.endswith("\n\n") else "\n\n"
        updated = (
            content.rstrip()
            + separator
            + "## Generated Lists\n\n"
            + generated_table
            + "\n"
        )
    elif start == -1 or end == -1 or end < start:
        raise RuntimeError(
            f"{README_PATH}: malformed blocklist count markers; "
            "either remove both markers or fix their order"
        )
    else:
        end += len(README_TABLE_END)
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

        for source_name in required_sources():
            networks = fetch_source(source_name)
            downloaded[source_name] = networks

            print(
                f"fetched {source_name}: "
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
