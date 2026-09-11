#!/usr/bin/env python3
"""Build multiple firewall/blocklist export formats from generic IPv4 sources."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable

DIST_DIR = Path("dist")
README_PATH = Path("README.md")
MANIFEST_PATH = DIST_DIR / "manifest.json"
CHECKSUM_PATH = DIST_DIR / "SHA256SUMS"

TIMEOUT_SECONDS = 60
USER_AGENT = "blocklist-builder/2.0"

README_TABLE_START = "<!-- BLOCKLIST_COUNTS_START -->"
README_TABLE_END = "<!-- BLOCKLIST_COUNTS_END -->"

SOURCES: dict[str, str] = {
    "et_block": (
        "https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/et_block.netset"
    ),
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

LISTS: dict[str, tuple[str, ...]] = {
    "level1": ("level1",),
    "level2": ("level2",),
    "level3": ("level3",),
    "webserver": ("webserver",),
    "combined1": ("level1", "level2"),
    "combined2": ("level2", "level3"),
    "combined3": ("level1", "webserver"),
    "combined4": ("level1", "level2", "level3"),
}

EXPORTS: dict[str, bool] = {
    "plain": True,
    "mikrotik": True,
    "nftables": True,
    "ipset": True,
    "powershell": True,
    "bat": True,
    "pf": True,
}

ROUTEROS_LIST_PREFIX = "blocklist"
NFT_TABLE_FAMILY = "inet"
NFT_TABLE_NAME = "filter"
IPSET_PREFIX = "blocklist"
WINDOWS_RULE_GROUP = "Generated Blocklists"
WINDOWS_RULE_CHUNK_SIZE = 500

SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def safe_name(value: str) -> str:
    return SAFE_NAME_RE.sub("-", value).strip("-").lower()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def required_sources() -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for names in LISTS.values():
        for name in names:
            if name not in seen:
                seen.add(name)
                ordered.append(name)
    return tuple(ordered)


def validate_config() -> None:
    if not SOURCES:
        raise RuntimeError("SOURCES must contain at least one source")
    if not LISTS:
        raise RuntimeError("LISTS must contain at least one output")

    normalized_outputs: set[str] = set()
    for source_name, url in SOURCES.items():
        if not safe_name(source_name):
            raise RuntimeError(f"invalid source name: {source_name!r}")
        if not url.startswith(("https://", "http://")):
            raise RuntimeError(f"{source_name}: URL must start with http:// or https://")

    for output_name, source_names in LISTS.items():
        normalized = safe_name(output_name)
        if not normalized:
            raise RuntimeError(f"invalid output name: {output_name!r}")
        if normalized in normalized_outputs:
            raise RuntimeError(f"duplicate normalized output name: {normalized!r}")
        normalized_outputs.add(normalized)
        if not source_names:
            raise RuntimeError(f"{output_name}: at least one source is required")
        if len(source_names) != len(set(source_names)):
            raise RuntimeError(f"{output_name}: duplicate sources are not allowed")
        missing = [name for name in source_names if name not in SOURCES]
        if missing:
            raise RuntimeError(f"{output_name}: undefined source(s): {', '.join(missing)}")

    if WINDOWS_RULE_CHUNK_SIZE < 1:
        raise RuntimeError("WINDOWS_RULE_CHUNK_SIZE must be >= 1")


def fetch_source(name: str) -> set[ipaddress.IPv4Network]:
    url = SOURCES[name]
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain,*/*;q=0.8"},
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8-sig")
    except (urllib.error.URLError, TimeoutError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"{name}: download failed from {url}: {exc}") from exc

    networks: set[ipaddress.IPv4Network] = set()
    for line_number, raw_line in enumerate(body.splitlines(), 1):
        value = raw_line.strip()
        if not value or value.startswith("#"):
            continue
        if " #" in value:
            value = value.split(" #", 1)[0].strip()

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuntimeError(
                f"{name}: invalid IPv4/CIDR at line {line_number}: {value!r}"
            ) from exc

        if network.version == 4:
            networks.add(network)

    if not networks:
        raise RuntimeError(f"{name}: source is empty")
    return networks


def collapse_networks(
    networks: Iterable[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    collapsed = list(ipaddress.collapse_addresses(networks))
    return sorted(collapsed, key=lambda n: (int(n.network_address), n.prefixlen))


def address_text(network: ipaddress.IPv4Network) -> str:
    return str(network.network_address) if network.prefixlen == 32 else str(network)


def quote_routeros(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def quote_bat(value: str) -> str:
    return (
        value.replace("^", "^^")
        .replace("&", "^&")
        .replace("|", "^|")
        .replace("<", "^<")
        .replace(">", "^>")
    )


def write_text(path: Path, content: str) -> None:
    ensure_dir(path.parent)
    path.write_text(content, encoding="utf-8", newline="\n")


def export_plain(name: str, networks: list[ipaddress.IPv4Network]) -> Path:
    path = DIST_DIR / "plain" / f"{name}.txt"
    write_text(path, "\n".join(address_text(n) for n in networks) + "\n")
    return path


def export_mikrotik(
    name: str,
    source_names: tuple[str, ...],
    networks: list[ipaddress.IPv4Network],
) -> Path:
    path = DIST_DIR / "mikrotik" / f"{name}.rsc"
    list_name = f"{ROUTEROS_LIST_PREFIX}-{name}"
    comment = f"Sources: {' + '.join(source_names)}"
    lines = [
        f"# Generated from: {', '.join(source_names)}",
        f"# Entries: {len(networks)}",
        "/ip firewall address-list",
    ]
    for network in networks:
        lines.append(
            "add "
            f"list={quote_routeros(list_name)} "
            f"address={quote_routeros(address_text(network))} "
            f"comment={quote_routeros(comment)}"
        )
    write_text(path, "\n".join(lines) + "\n")
    return path


def export_nftables(name: str, networks: list[ipaddress.IPv4Network]) -> list[Path]:
    nft_path = DIST_DIR / "nftables" / f"{name}.nft"
    sh_path = DIST_DIR / "nftables" / f"{name}.sh"
    set_name = safe_name(f"blocklist-{name}").replace("-", "_")
    elements = ",\n        ".join(address_text(n) for n in networks)

    nft_content = f"""table {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {{
    set {set_name} {{
        type ipv4_addr
        flags interval
        elements = {{
        {elements}
        }}
    }}
}}
"""

    sh_content = f"""#!/usr/bin/env bash
set -euo pipefail

TABLE_FAMILY={NFT_TABLE_FAMILY!r}
TABLE_NAME={NFT_TABLE_NAME!r}
SET_NAME={set_name!r}
SCRIPT_DIR="$(cd -- "$(dirname -- "${{BASH_SOURCE[0]}}")" && pwd)"

if ! nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
    nft add table "$TABLE_FAMILY" "$TABLE_NAME"
fi

if nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" >/dev/null 2>&1; then
    nft delete set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME"
fi

nft -f "$SCRIPT_DIR/{name}.nft"
"""

    write_text(nft_path, nft_content)
    write_text(sh_path, sh_content)
    return [nft_path, sh_path]


def export_ipset(name: str, networks: list[ipaddress.IPv4Network]) -> Path:
    path = DIST_DIR / "ipset" / f"{name}.sh"
    set_name = safe_name(f"{IPSET_PREFIX}-{name}").replace("-", "_")
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f'SET_NAME="{set_name}"',
        "",
        'ipset create "$SET_NAME" hash:net family inet -exist',
        'ipset flush "$SET_NAME"',
        "",
    ]
    for network in networks:
        lines.append(f'ipset add "$SET_NAME" {address_text(network)} -exist')
    write_text(path, "\n".join(lines) + "\n")
    return path


def chunked(values: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index:index + size]


def export_powershell(name: str, networks: list[ipaddress.IPv4Network]) -> Path:
    path = DIST_DIR / "windows" / f"{name}.ps1"
    display_prefix = f"Blocklist {name}"
    addresses = [address_text(n) for n in networks]
    lines = [
        '#requires -RunAsAdministrator',
        '$ErrorActionPreference = "Stop"',
        "",
        f'$Group = "{WINDOWS_RULE_GROUP}"',
        f'$Prefix = "{display_prefix}"',
        "",
        'Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue |',
        '    Where-Object DisplayName -Like "$Prefix *" |',
        "    Remove-NetFirewallRule",
        "",
    ]
    for index, group in enumerate(chunked(addresses, WINDOWS_RULE_CHUNK_SIZE), start=1):
        array_values = ", ".join(f'"{value}"' for value in group)
        lines.extend([
            f"$Addresses = @({array_values})",
            "New-NetFirewallRule `",
            f'    -DisplayName "$Prefix {index:03d}" `',
            "    -Group $Group `",
            "    -Direction Inbound `",
            "    -Action Block `",
            "    -RemoteAddress $Addresses | Out-Null",
            "",
        ])
    write_text(path, "\n".join(lines).rstrip() + "\n")
    return path


def export_bat(name: str, networks: list[ipaddress.IPv4Network]) -> Path:
    path = DIST_DIR / "windows" / f"{name}.bat"
    addresses = [address_text(n) for n in networks]
    lines = ["@echo off", "setlocal", ""]
    for index, group in enumerate(chunked(addresses, WINDOWS_RULE_CHUNK_SIZE), start=1):
        rule_name = quote_bat(f"Blocklist {name} {index:03d}")
        remote = ",".join(group)
        lines.append(f'netsh advfirewall firewall delete rule name="{rule_name}" >nul 2>&1')
        lines.append(
            "netsh advfirewall firewall add rule "
            f'name="{rule_name}" dir=in action=block remoteip={remote}'
        )
    lines.extend(["", "endlocal", ""])
    write_text(path, "\n".join(lines))
    return path


def export_pf(name: str, networks: list[ipaddress.IPv4Network]) -> Path:
    path = DIST_DIR / "pf" / f"{name}.txt"
    write_text(path, "\n".join(address_text(n) for n in networks) + "\n")
    return path


def export_all(
    output_name: str,
    source_names: tuple[str, ...],
    networks: list[ipaddress.IPv4Network],
) -> dict[str, list[str]]:
    files: dict[str, list[str]] = {}

    def record(kind: str, paths: Path | list[Path]) -> None:
        path_list = paths if isinstance(paths, list) else [paths]
        files[kind] = [path.as_posix() for path in path_list]

    if EXPORTS.get("plain"):
        record("plain", export_plain(output_name, networks))
    if EXPORTS.get("mikrotik"):
        record("mikrotik", export_mikrotik(output_name, source_names, networks))
    if EXPORTS.get("nftables"):
        record("nftables", export_nftables(output_name, networks))
    if EXPORTS.get("ipset"):
        record("ipset", export_ipset(output_name, networks))
    if EXPORTS.get("powershell"):
        record("powershell", export_powershell(output_name, networks))
    if EXPORTS.get("bat"):
        record("bat", export_bat(output_name, networks))
    if EXPORTS.get("pf"):
        record("pf", export_pf(output_name, networks))
    return files


def build_lists(
    downloaded: dict[str, set[ipaddress.IPv4Network]],
) -> dict[str, dict[str, object]]:
    manifest: dict[str, dict[str, object]] = {}
    for configured_name, source_names in LISTS.items():
        output_name = safe_name(configured_name)
        merged: set[ipaddress.IPv4Network] = set()
        for source_name in source_names:
            merged.update(downloaded[source_name])
        networks = collapse_networks(merged)
        files = export_all(output_name, source_names, networks)
        manifest[output_name] = {
            "sources": list(source_names),
            "entries": len(networks),
            "files": files,
        }
        print(
            f"built   {output_name}: {len(networks):,} entries "
            f"from {len(source_names)} source(s)"
        )
    return manifest


def markdown_link(label: str, path: str) -> str:
    return f"[{label}]({path})"


def build_readme_table(manifest: dict[str, dict[str, object]]) -> str:
    lines = [
        README_TABLE_START,
        "| List | Sources | Entries | Plain | MikroTik | nftables | ipset | Windows | pf |",
        "|---|---|---:|---|---|---|---|---|---|",
    ]
    for name, item in manifest.items():
        sources = " + ".join(f"`{source}`" for source in item["sources"])
        entries = int(item["entries"])
        files = item["files"]
        plain = " / ".join(markdown_link("TXT", p) for p in files.get("plain", [])) or "-"
        mikrotik = " / ".join(markdown_link("RSC", p) for p in files.get("mikrotik", [])) or "-"
        nft = " / ".join(
            markdown_link(Path(p).suffix.lstrip(".").upper(), p)
            for p in files.get("nftables", [])
        ) or "-"
        ipset = " / ".join(markdown_link("SH", p) for p in files.get("ipset", [])) or "-"
        windows_links: list[str] = []
        for p in files.get("powershell", []):
            windows_links.append(markdown_link("PS1", p))
        for p in files.get("bat", []):
            windows_links.append(markdown_link("BAT", p))
        windows = " / ".join(windows_links) or "-"
        pf = " / ".join(markdown_link("TXT", p) for p in files.get("pf", [])) or "-"
        lines.append(
            f"| `{name}` | {sources} | {entries:,} | {plain} | {mikrotik} | "
            f"{nft} | {ipset} | {windows} | {pf} |"
        )
    lines.append(README_TABLE_END)
    return "\n".join(lines)


def update_readme(manifest: dict[str, dict[str, object]]) -> None:
    generated_table = build_readme_table(manifest)
    if not README_PATH.exists():
        write_text(
            README_PATH,
            "# Generated Blocklists\n\n## Generated Lists\n\n"
            f"{generated_table}\n",
        )
        print(f"created {README_PATH}")
        return

    content = README_PATH.read_text(encoding="utf-8")
    start = content.find(README_TABLE_START)
    end = content.find(README_TABLE_END)
    if start == -1 and end == -1:
        updated = content.rstrip() + "\n\n## Generated Lists\n\n" + generated_table + "\n"
    elif start == -1 or end == -1 or end < start:
        raise RuntimeError(
            f"{README_PATH}: malformed blocklist markers; remove both markers or fix their order"
        )
    else:
        end += len(README_TABLE_END)
        updated = content[:start] + generated_table + content[end:]

    if updated != content:
        write_text(README_PATH, updated)
        print(f"updated {README_PATH}")
    else:
        print(f"unchanged {README_PATH}")


def write_manifest(manifest: dict[str, dict[str, object]]) -> None:
    data = {"sources": SOURCES, "exports": EXPORTS, "lists": manifest}
    write_text(MANIFEST_PATH, json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_checksums() -> None:
    files = sorted(
        path for path in DIST_DIR.rglob("*") if path.is_file() and path != CHECKSUM_PATH
    )
    lines: list[str] = []
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.as_posix()}")
    write_text(CHECKSUM_PATH, "\n".join(lines) + "\n")


def clean_dist() -> None:
    if not DIST_DIR.exists():
        return
    for path in sorted(DIST_DIR.rglob("*"), reverse=True):
        if path.is_file() or path.is_symlink():
            path.unlink()
        elif path.is_dir():
            try:
                path.rmdir()
            except OSError:
                pass


def main() -> int:
    try:
        validate_config()
        clean_dist()
        ensure_dir(DIST_DIR)
        downloaded: dict[str, set[ipaddress.IPv4Network]] = {}
        for source_name in required_sources():
            networks = fetch_source(source_name)
            downloaded[source_name] = networks
            print(f"fetched {source_name}: {len(networks):,} entries")
        manifest = build_lists(downloaded)
        write_manifest(manifest)
        write_checksums()
        update_readme(manifest)
        print(f"done: {len(manifest)} configured list(s)")
        return 0
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
