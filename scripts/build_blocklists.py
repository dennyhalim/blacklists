#!/usr/bin/env python3
"""Build synchronized firewall/blocklist exports from generic IPv4 sources."""

from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import re
import shutil
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

DIST_DIR = Path("dist")
README_PATH = Path("README.md")
INDEX_PATH = Path("index.html")
MANIFEST_PATH = DIST_DIR / "manifest.json"
CHECKSUM_PATH = DIST_DIR / "SHA256SUMS"

TIMEOUT_SECONDS = 60
USER_AGENT = "blocklist-builder/3.0"
STALE_AFTER_DAYS = 3

README_TABLE_START = "<!-- BLOCKLIST_COUNTS_START -->"
README_TABLE_END = "<!-- BLOCKLIST_COUNTS_END -->"
INDEX_TABLE_START = "<!-- BLOCKLIST_INDEX_START -->"
INDEX_TABLE_END = "<!-- BLOCKLIST_INDEX_END -->"

SOURCES: dict[str, str] = {
    "feodo": ("https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    "botnet": ("https://malware-filter.gitlab.io/malware-filter/botnet-filter.txt"),
    "threatfox": ("https://raw.githubusercontent.com/elliotwutingfeng/ThreatFox-IOC-IPs/main/ips.txt"),
    "etblock": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/et_block.netset"),
    "etcompromised": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/et_compromised.ipset"),
    "level2": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/firehol_level2.netset"),
    "level3": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/firehol_level3.netset"),
    "level4": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/firehol_level4.netset"),
    "hijack": ("https://raw.githubusercontent.com/"
        "kraloveckey/ipsets-blocklist/main/iblocklist_hijacked.netset"),
    "strongips": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/blocklist_de_strongips.ipset"),
    "toxic": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/stopforumspam_toxic.netset"),
    "dshield7": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/dshield_7d.netset"),
    "dshield30": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/dshield_30d.netset"),
    "webserver": ("https://raw.githubusercontent.com/"
        "firehol/blocklist-ipsets/master/firehol_webserver.netset"),
    "abuseipdb7": ("https://raw.githubusercontent.com/"
        "borestad/blocklist-abuseipdb/main/stats/hallofshame/subnets/abuseipdb-s99-hallofshame-7d-75percent.ipv4"),
    "abuseipdb30": ("https://raw.githubusercontent.com/"
        "borestad/blocklist-abuseipdb/main/stats/hallofshame/subnets/abuseipdb-s99-hallofshame-30d-75percent.ipv4"),
    "ipsum3": ("https://raw.githubusercontent.com/"
        "stamparm/ipsum/master/levels/3.txt"),
    "ipsum7": ("https://raw.githubusercontent.com/"
        "stamparm/ipsum/master/levels/7.txt"),
}

LISTS: dict[str, tuple[str, ...]] = {
    "level4": ("level4",),
    "threatfox": ("threatfox",),
    "hijack": ("hijack",),
    "botnet": ("botnet",),
    "compact": ("etblock","feodo","dshield7","abuseipdb7","ipsum7","toxic"),
    "compact1": ("etblock","feodo","dshield7","abuseipdb7"),
    "combined": ("etblock","feodo","webserver","dshield30","abuseipdb30","ipsum3","toxic","strongips","etcompromised"),
    "combined1": ("etblock","feodo","webserver","dshield30","abuseipdb30","ipsum3","toxic"),
    "combined2": ("etblock","feodo","webserver","dshield30","abuseipdb30","strongips","ipsum3","toxic"),
    "complete": ("etblock","feodo","webserver","dshield30","abuseipdb30","strongips","ipsum3","toxic","level2","level3","botnet","etcompromised"),
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
ROUTEROS_MANAGED_COMMENT = "ipbl.dennyhalim.com"
NFT_TABLE_FAMILY = "inet"
NFT_TABLE_NAME = "filter"
IPSET_PREFIX = "blocklist"
PF_TABLE_PREFIX = "blocklist"
WINDOWS_RULE_GROUP = "ipbl.dennyhalim.com Blocklists"
WINDOWS_RULE_CHUNK_SIZE = 500

SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]+")


def safe_name(value: str) -> str:
    return SAFE_NAME_RE.sub("-", value).strip("-").lower()


def object_name(value: str) -> str:
    return safe_name(value).replace("-", "_")


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
    if STALE_AFTER_DAYS < 1:
        raise RuntimeError("STALE_AFTER_DAYS must be >= 1")
    if WINDOWS_RULE_CHUNK_SIZE < 1:
        raise RuntimeError("WINDOWS_RULE_CHUNK_SIZE must be >= 1")

    normalized_outputs: set[str] = set()

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
        if normalized in normalized_outputs:
            raise RuntimeError(
                f"duplicate normalized output name: {normalized!r}"
            )
        normalized_outputs.add(normalized)

        if not source_names:
            raise RuntimeError(
                f"{output_name}: at least one source is required"
            )
        if len(source_names) != len(set(source_names)):
            raise RuntimeError(
                f"{output_name}: duplicate sources are not allowed"
            )

        missing = [name for name in source_names if name not in SOURCES]
        if missing:
            raise RuntimeError(
                f"{output_name}: undefined source(s): {', '.join(missing)}"
            )


def fetch_source(name: str) -> set[ipaddress.IPv4Network]:
    url = SOURCES[name]
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain,*/*;q=0.8",
        },
    )

    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
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
        if " #" in value:
            value = value.split(" #", 1)[0].strip()

        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            print(
                f"warning: {name}: ignored non-IP line "
                f"{line_number}: {value!r}",
                file=sys.stderr,
            )
            continue

        if network.version == 4:
            networks.add(network)
        else:
            print(
                f"warning: {name}: ignored non-IPv4 line "
                f"{line_number}: {value!r}",
                file=sys.stderr,
            )

    if not networks:
        raise RuntimeError(f"{name}: source is empty")

    return networks


def collapse_networks(
    networks: Iterable[ipaddress.IPv4Network],
) -> list[ipaddress.IPv4Network]:
    collapsed = list(ipaddress.collapse_addresses(networks))
    return sorted(collapsed, key=lambda n: (int(n.network_address), n.prefixlen))


def address_text(network: ipaddress.IPv4Network) -> str:
    return (
        str(network.network_address)
        if network.prefixlen == 32
        else str(network)
    )


def quote_routeros(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def write_text(path: Path, content: str) -> None:
    ensure_dir(path.parent)
    path.write_text(content, encoding="utf-8", newline="\n")


def chunked(values: list[str], size: int) -> Iterable[list[str]]:
    for index in range(0, len(values), size):
        yield values[index:index + size]


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
    timeout = f"{STALE_AFTER_DAYS}d"

    lines = [
        f"# Generated from: {', '.join(source_names)}",
        f"# Entries: {len(networks)}",
        f"# Managed entries expire after: {timeout}",
        "/ip firewall address-list",
        (
            "remove [find where "
            f"list={quote_routeros(list_name)} and "
            f"comment={quote_routeros(ROUTEROS_MANAGED_COMMENT)}]"
        ),
    ]

    for network in networks:
        lines.append(
            "add "
            f"list={quote_routeros(list_name)} "
            f"address={quote_routeros(address_text(network))} "
            f"timeout={timeout} "
            f"comment={quote_routeros(ROUTEROS_MANAGED_COMMENT)}"
        )

    write_text(path, "\n".join(lines) + "\n")
    return path


def export_nftables(
    name: str,
    networks: list[ipaddress.IPv4Network],
) -> list[Path]:
    nft_path = DIST_DIR / "nftables" / f"{name}.nft"
    sh_path = DIST_DIR / "nftables" / f"{name}.sh"
    set_name = object_name(f"blocklist-{name}")
    timeout = f"{STALE_AFTER_DAYS}d"
    elements = ",\n        ".join(address_text(n) for n in networks)

    nft_content = f"""flush set {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {set_name}
add element {NFT_TABLE_FAMILY} {NFT_TABLE_NAME} {set_name} {{
        {elements}
}}
"""

    sh_content = f"""#!/usr/bin/env bash
set -euo pipefail

TABLE_FAMILY={NFT_TABLE_FAMILY!r}
TABLE_NAME={NFT_TABLE_NAME!r}
SET_NAME={set_name!r}
TIMEOUT={timeout!r}
SCRIPT_DIR="$(cd -- "$(dirname -- "${{BASH_SOURCE[0]}}")" && pwd)"

if ! nft list table "$TABLE_FAMILY" "$TABLE_NAME" >/dev/null 2>&1; then
    nft add table "$TABLE_FAMILY" "$TABLE_NAME"
fi

if ! nft list set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" >/dev/null 2>&1; then
    nft add set "$TABLE_FAMILY" "$TABLE_NAME" "$SET_NAME" \
        "{{ type ipv4_addr; flags interval,timeout; timeout $TIMEOUT; }}"
fi

# Flush + repopulate are applied in one nft transaction.
nft -f "$SCRIPT_DIR/{name}.nft"
"""

    write_text(nft_path, nft_content)
    write_text(sh_path, sh_content)
    return [nft_path, sh_path]


def export_ipset(
    name: str,
    networks: list[ipaddress.IPv4Network],
) -> Path:
    path = DIST_DIR / "ipset" / f"{name}.sh"
    set_name = object_name(f"{IPSET_PREFIX}-{name}")
    temp_name = f"{set_name}_new"
    timeout_seconds = STALE_AFTER_DAYS * 86400

    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        f'SET_NAME="{set_name}"',
        f'TEMP_NAME="{temp_name}"',
        f'TIMEOUT="{timeout_seconds}"',
        "",
        'ipset create "$SET_NAME" hash:net family inet timeout "$TIMEOUT" -exist',
        'ipset destroy "$TEMP_NAME" >/dev/null 2>&1 || true',
        'ipset create "$TEMP_NAME" hash:net family inet timeout "$TIMEOUT"',
        "",
    ]

    for network in networks:
        lines.append(
            f'ipset add "$TEMP_NAME" {address_text(network)} timeout "$TIMEOUT"'
        )

    lines.extend([
        "",
        'ipset swap "$TEMP_NAME" "$SET_NAME"',
        'ipset destroy "$TEMP_NAME"',
        "",
    ])

    write_text(path, "\n".join(lines))
    return path


def export_powershell(
    name: str,
    networks: list[ipaddress.IPv4Network],
) -> Path:
    path = DIST_DIR / "windows" / f"{name}.ps1"
    display_prefix = f"Blocklist {name}"
    addresses = [address_text(n) for n in networks]

    lines = [
        '#requires -RunAsAdministrator',
        '$ErrorActionPreference = "Stop"',
        "",
        f'$Group = "{WINDOWS_RULE_GROUP}"',
        f'$Prefix = "{display_prefix}"',
        '$RunId = [Guid]::NewGuid().ToString("N")',
        '$NewPrefix = "$Prefix new-$RunId"',
        "",
    ]

    for index, group in enumerate(
        chunked(addresses, WINDOWS_RULE_CHUNK_SIZE),
        start=1,
    ):
        array_values = ", ".join(f'"{value}"' for value in group)
        lines.extend([
            f"$Addresses = @({array_values})",
            "New-NetFirewallRule `",
            f'    -DisplayName "$NewPrefix {index:03d}" `',
            "    -Group $Group `",
            "    -Direction Inbound `",
            "    -Action Block `",
            "    -RemoteAddress $Addresses | Out-Null",
            "",
        ])

    lines.extend([
        '# New rules exist before old managed rules are removed.',
        'Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue |',
        '    Where-Object {',
        '        $_.DisplayName -Like "$Prefix *" -and',
        '        $_.DisplayName -NotLike "$NewPrefix *"',
        '    } |',
        '    Remove-NetFirewallRule',
        "",
    ])

    write_text(path, "\n".join(lines))
    return path


def export_bat(
    name: str,
    networks: list[ipaddress.IPv4Network],
) -> Path:
    path = DIST_DIR / "windows" / f"{name}.bat"
    addresses = [address_text(n) for n in networks]
    prefix = f"Blocklist {name}"

    lines = [
        "@echo off",
        "setlocal EnableExtensions",
        "",
        "rem Compatibility export: delete/recreate is not atomic.",
        f'netsh advfirewall firewall delete rule name="{prefix}*" >nul 2>&1',
        "",
    ]

    for index, group in enumerate(
        chunked(addresses, WINDOWS_RULE_CHUNK_SIZE),
        start=1,
    ):
        remote = ",".join(group)
        lines.append(
            "netsh advfirewall firewall add rule "
            f'name="{prefix} {index:03d}" '
            "dir=in action=block "
            f"remoteip={remote}"
        )

    lines.extend(["", "endlocal", ""])
    write_text(path, "\n".join(lines))
    return path


def export_pf(
    name: str,
    networks: list[ipaddress.IPv4Network],
) -> list[Path]:
    txt_path = DIST_DIR / "pf" / f"{name}.txt"
    sh_path = DIST_DIR / "pf" / f"{name}.sh"
    table_name = safe_name(f"{PF_TABLE_PREFIX}-{name}")

    write_text(
        txt_path,
        "\n".join(address_text(n) for n in networks) + "\n",
    )

    sh_content = f"""#!/usr/bin/env sh
set -eu

TABLE={table_name!r}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Replace the table contents in one operation so removed source IPs disappear.
pfctl -t "$TABLE" -T replace -f "$SCRIPT_DIR/{name}.txt"
"""
    write_text(sh_path, sh_content)
    return [txt_path, sh_path]


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
        record(
            "mikrotik",
            export_mikrotik(output_name, source_names, networks),
        )
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
            f"built   {output_name}: "
            f"{len(networks):,} entries "
            f"from {len(source_names)} source(s)"
        )

    return manifest



def generated_timestamp() -> str:
    """Return the current build time in UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def markdown_link(label: str, path: str) -> str:
    return f"[{label}]({path})"


def build_readme_table(
    manifest: dict[str, dict[str, object]],
) -> str:
    lines = [
        README_TABLE_START,
        f"Last updated: **{generated_timestamp()}**",
        "",
        "| List | Sources | Entries | Plain | MikroTik | nftables | ipset | Windows | pf |",
        "|---|---|---:|---|---|---|---|---|---|",
    ]

    for name, item in manifest.items():
        sources = " + ".join(f"`{source}`" for source in item["sources"])
        entries = int(item["entries"])
        files = item["files"]

        def links(kind: str) -> str:
            values = []
            for file_path in files.get(kind, []):
                suffix = Path(file_path).suffix.lstrip(".").upper() or "FILE"
                values.append(markdown_link(suffix, file_path))
            return " / ".join(values) or "-"

        windows = []
        for kind in ("powershell", "bat"):
            if kind in files:
                windows.append(links(kind))

        lines.append(
            f"| `{name}` | {sources} | {entries:,} | "
            f"{links('plain')} | {links('mikrotik')} | "
            f"{links('nftables')} | {links('ipset')} | "
            f"{' / '.join(windows) or '-'} | {links('pf')} |"
        )

    lines.append(README_TABLE_END)
    return "\n".join(lines)


def update_readme(manifest: dict[str, dict[str, object]]) -> None:
    generated_table = build_readme_table(manifest)

    if not README_PATH.exists():
        write_text(
            README_PATH,
            "# Generated Blocklists\n\n"
            "## Generated Lists\n\n"
            f"{generated_table}\n",
        )
        print(f"created {README_PATH}")
        return

    content = README_PATH.read_text(encoding="utf-8")
    start = content.find(README_TABLE_START)
    end = content.find(README_TABLE_END)

    if start == -1 and end == -1:
        updated = (
            content.rstrip()
            + "\n\n## Generated Lists\n\n"
            + generated_table
            + "\n"
        )
    elif start == -1 or end == -1 or end < start:
        raise RuntimeError(
            f"{README_PATH}: malformed blocklist markers; "
            "remove both markers or fix their order"
        )
    else:
        end += len(README_TABLE_END)
        updated = content[:start] + generated_table + content[end:]

    if updated != content:
        write_text(README_PATH, updated)
        print(f"updated {README_PATH}")
    else:
        print(f"unchanged {README_PATH}")



def html_link(label: str, path: str) -> str:
    href = "/" + path.lstrip("/")
    return (
        f'<a href="{html.escape(href, quote=True)}">'
        f'{html.escape(label)}</a>'
    )


def build_index_table(manifest: dict[str, dict[str, object]]) -> str:
    rows: list[str] = []

    for name, item in manifest.items():
        sources = " + ".join(
            f"<code>{html.escape(str(source))}</code>"
            for source in item["sources"]
        )
        entries = int(item["entries"])
        files = item["files"]

        def links(kind: str) -> str:
            values: list[str] = []
            for file_path in files.get(kind, []):
                suffix = Path(file_path).suffix.lstrip(".").upper() or "FILE"
                values.append(html_link(suffix, file_path))
            return " / ".join(values) or "-"

        windows: list[str] = []
        for kind in ("powershell", "bat"):
            value = links(kind)
            if value != "-":
                windows.append(value)

        rows.append(
            "        <tr>\n"
            f"          <td><code>{html.escape(name)}</code></td>\n"
            f"          <td>{sources}</td>\n"
            f"          <td>{entries:,}</td>\n"
            f"          <td>{links('plain')}</td>\n"
            f"          <td>{links('mikrotik')}</td>\n"
            f"          <td>{links('nftables')}</td>\n"
            f"          <td>{links('ipset')}</td>\n"
            f"          <td>{' / '.join(windows) or '-'}</td>\n"
            f"          <td>{links('pf')}</td>\n"
            "        </tr>"
        )

    return (
        f"{INDEX_TABLE_START}\n"
        f'    <p class="updated">Last updated: '
        f'<time datetime="{datetime.now(timezone.utc).isoformat()}">'
        f'{generated_timestamp()}</time></p>\n'
        '    <div class="table-wrap">\n'
        "      <table>\n"
        "        <thead>\n"
        "          <tr>\n"
        "            <th>List</th>\n"
        "            <th>Sources</th>\n"
        "            <th>Entries</th>\n"
        "            <th>Plain</th>\n"
        "            <th>MikroTik</th>\n"
        "            <th>nftables</th>\n"
        "            <th>ipset</th>\n"
        "            <th>Windows</th>\n"
        "            <th>pf</th>\n"
        "          </tr>\n"
        "        </thead>\n"
        "        <tbody>\n"
        + "\n".join(rows)
        + "\n        </tbody>\n"
        "      </table>\n"
        "    </div>\n"
        f"{INDEX_TABLE_END}"
    )


def default_index_html(table: str) -> str:
    return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Generated Blocklists</title>
  <style>
    :root {{ color-scheme: dark; font-family: system-ui, sans-serif; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: #151719; color: #e7e9eb; }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 32px 20px; }}
    h1 {{ margin: 0 0 8px; }}
    p {{ margin: 0 0 24px; color: #b8bec4; }}
    .table-wrap {{ overflow-x: auto; border: 1px solid #3b4147; border-radius: 10px; }}
    table {{ width: 100%; min-width: 900px; border-collapse: collapse; background: #1c1f22; }}
    th, td {{ padding: 12px 14px; text-align: left; vertical-align: top; border-bottom: 1px solid #343a40; }}
    th {{ background: #24282c; color: #f3f4f5; }}
    tr:last-child td {{ border-bottom: 0; }}
    a {{ color: #9bc1ff; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  </style>
</head>
<body>
  <main>
    <h1>Generated Blocklists</h1>
    <p>Download the latest generated firewall and plain-text blocklists.</p>
{table}
  </main>
</body>
</html>
'''


def update_index(manifest: dict[str, dict[str, object]]) -> None:
    generated_table = build_index_table(manifest)

    if not INDEX_PATH.exists():
        write_text(INDEX_PATH, default_index_html(generated_table))
        print(f"created {INDEX_PATH}")
        return

    content = INDEX_PATH.read_text(encoding="utf-8")
    start = content.find(INDEX_TABLE_START)
    end = content.find(INDEX_TABLE_END)

    if start == -1 and end == -1:
        write_text(INDEX_PATH, default_index_html(generated_table))
        print(f"recreated {INDEX_PATH}")
        return

    if start == -1 or end == -1 or end < start:
        raise RuntimeError(
            f"{INDEX_PATH}: malformed blocklist index markers; "
            "remove both markers or fix their order"
        )

    end += len(INDEX_TABLE_END)
    updated = content[:start] + generated_table + content[end:]

    if updated != content:
        write_text(INDEX_PATH, updated)
        print(f"updated {INDEX_PATH}")
    else:
        print(f"unchanged {INDEX_PATH}")

def write_manifest(manifest: dict[str, dict[str, object]]) -> None:
    data = {
        "stale_after_days": STALE_AFTER_DAYS,
        "sources": SOURCES,
        "exports": EXPORTS,
        "lists": manifest,
    }
    write_text(
        MANIFEST_PATH,
        json.dumps(data, indent=2, sort_keys=True) + "\n",
    )


def write_checksums() -> None:
    files = sorted(
        path
        for path in DIST_DIR.rglob("*")
        if path.is_file() and path != CHECKSUM_PATH
    )

    lines: list[str] = []
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.as_posix()}")

    write_text(CHECKSUM_PATH, "\n".join(lines) + "\n")


def clean_dist() -> None:
    if DIST_DIR.exists():
        shutil.rmtree(DIST_DIR)


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
        update_index(manifest)

        print(f"done: {len(manifest)} configured list(s)")
        return 0

    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
