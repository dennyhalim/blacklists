# FireHOL → MikroTik Blocklists

Automatically downloads selected [FireHOL](https://iplists.firehol.org/) IP blocklists, combines them as configured, and generates ready-to-import MikroTik RouterOS `.rsc` address lists.

The generated lists are rebuilt by GitHub Actions and committed back to the repository when they change.

## Generated Lists

> Counts above are examples. They change as FireHOL updates its feeds and should ideally be generated automatically during each build.

### Warning! Firehol Level1 contain bogons (local reserved) IP Addresses

- https://en.wikipedia.org/wiki/List_of_reserved_IP_addresses
- https://en.wikipedia.org/wiki/Bogon_filtering
- if you want similar to level1 IP list without bogons, try et_block

## Configuration

Lists and combinations are configured in `scripts/build_blocklists.py`:

```python
LISTS = {
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
```

Each key creates one `.rsc` file.

For example:

```text
combined1
    = firehol_level1
    + firehol_level2

→ dist/combined1.rsc
→ MikroTik list: firehol-combined1
```

Add or remove combinations by editing only `LISTS`.

## Output

Generated files are stored in:

```text
dist/
├── level1.rsc
├── level2.rsc
├── level3.rsc
├── webserver.rsc
├── combined1.rsc
├── combined2.rsc
├── combined3.rsc
└── combined4.rsc
```

Each file contains a standard RouterOS address list:

```routeros
/ip firewall address-list
add list="firehol-combined1" address="1.2.3.0/24" comment="FireHOL: firehol_level1 + firehol_level2"
add list="firehol-combined1" address="5.6.7.8" comment="FireHOL: firehol_level1 + firehol_level2"
```

Overlapping and adjacent networks are collapsed where possible before generating the RouterOS list.

## Import to MikroTik

Upload the required `.rsc` file to the router and import it:

```routeros
/import file-name=combined1.rsc
```

The corresponding address list is then available as:

```text
firehol-combined1
```

For example, to drop traffic from the list:

```routeros
/ip firewall filter
add chain=input src-address-list=firehol-combined1 action=drop
```

Review firewall placement before applying rules to a production router.

## Local Build

Requires Python 3.10+ and no third-party packages.

```bash
python scripts/build_blocklists.py
```

The builder:

* downloads each required FireHOL feed only once;
* validates IPv4 addresses and CIDRs;
* removes duplicate entries;
* merges configured combinations;
* collapses overlapping and adjacent networks;
* rejects malformed or empty feeds;
* removes stale generated `.rsc` files;
* generates only lists configured in `LISTS`.

## Automatic Updates

GitHub Actions periodically runs the builder.

When generated blocklists change, the workflow commits the updated `dist/*.rsc` files back to the repository using `github-actions[bot]`.

The workflow can also be started manually from:

```text
Actions → Build MikroTik FireHOL blocklists → Run workflow
```

The repository must allow GitHub Actions write access:

```text
Settings
→ Actions
→ General
→ Workflow permissions
→ Read and write permissions
```

## Files

```text
.
├── .github/
│   └── workflows/
│       └── build-blocklists.yml
├── scripts/
│   └── build_blocklists.py
├── dist/
│   └── *.rsc
└── README.md
```

## Data Source

IP blocklists are provided by FireHOL IP Lists.

The contents and size of each source list can change over time. This repository only converts and combines the configured source data for MikroTik RouterOS use.

## Generated Lists

<!-- BLOCKLIST_COUNTS_START -->
| List | Sources | Entries | Plain | MikroTik | nftables | ipset | Windows | pf |
|---|---|---:|---|---|---|---|---|---|
| `level1` | `level1` | 4,670 | [TXT](dist/plain/level1.txt) | [RSC](dist/mikrotik/level1.rsc) | [NFT](dist/nftables/level1.nft) / [SH](dist/nftables/level1.sh) | [SH](dist/ipset/level1.sh) | [PS1](dist/windows/level1.ps1) / [BAT](dist/windows/level1.bat) | [TXT](dist/pf/level1.txt) / [SH](dist/pf/level1.sh) |
| `webserver` | `webserver` | 1,255 | [TXT](dist/plain/webserver.txt) | [RSC](dist/mikrotik/webserver.rsc) | [NFT](dist/nftables/webserver.nft) / [SH](dist/nftables/webserver.sh) | [SH](dist/ipset/webserver.sh) | [PS1](dist/windows/webserver.ps1) / [BAT](dist/windows/webserver.bat) | [TXT](dist/pf/webserver.txt) / [SH](dist/pf/webserver.sh) |
| `combined1` | `etblock` + `forumspam` + `webserver` + `dshield7` + `abuseipdb7` | 2,907 | [TXT](dist/plain/combined1.txt) | [RSC](dist/mikrotik/combined1.rsc) | [NFT](dist/nftables/combined1.nft) / [SH](dist/nftables/combined1.sh) | [SH](dist/ipset/combined1.sh) | [PS1](dist/windows/combined1.ps1) / [BAT](dist/windows/combined1.bat) | [TXT](dist/pf/combined1.txt) / [SH](dist/pf/combined1.sh) |
| `combined2` | `etblock` + `forumspam` + `webserver` + `dshield30` + `abuseipdb30` | 2,889 | [TXT](dist/plain/combined2.txt) | [RSC](dist/mikrotik/combined2.rsc) | [NFT](dist/nftables/combined2.nft) / [SH](dist/nftables/combined2.sh) | [SH](dist/ipset/combined2.sh) | [PS1](dist/windows/combined2.ps1) / [BAT](dist/windows/combined2.bat) | [TXT](dist/pf/combined2.txt) / [SH](dist/pf/combined2.sh) |
| `combined3` | `etblock` + `forumspam` + `webserver` + `dshield30` + `abuseipdb30` + `hijack` | 141,280 | [TXT](dist/plain/combined3.txt) | [RSC](dist/mikrotik/combined3.rsc) | [NFT](dist/nftables/combined3.nft) / [SH](dist/nftables/combined3.sh) | [SH](dist/ipset/combined3.sh) | [PS1](dist/windows/combined3.ps1) / [BAT](dist/windows/combined3.bat) | [TXT](dist/pf/combined3.txt) / [SH](dist/pf/combined3.sh) |
<!-- BLOCKLIST_COUNTS_END -->
