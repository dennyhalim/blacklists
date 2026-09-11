# IP Blocklists

Automatically downloads selected [FireHOL](https://iplists.firehol.org/) IP blocklists, combines them as configured, and generates ready-to-import MikroTik RouterOS `.rsc` address lists.

The generated lists are rebuilt by GitHub Actions and committed back to the repository when they change.

## Generated Lists

<!-- BLOCKLIST_COUNTS_START -->
Last updated: **2026-09-11 08:31:24 UTC**

| List | Sources | Entries | Plain | MikroTik | nftables | ipset | Windows | pf |
|---|---|---:|---|---|---|---|---|---|
| `level2` | `level2` | 18,770 | [TXT](dist/plain/level2.txt) | [RSC](dist/mikrotik/level2.rsc) | [NFT](dist/nftables/level2.nft) / [SH](dist/nftables/level2.sh) | [SH](dist/ipset/level2.sh) | [PS1](dist/windows/level2.ps1) / [BAT](dist/windows/level2.bat) | [TXT](dist/pf/level2.txt) / [SH](dist/pf/level2.sh) |
| `hijack` | `hijack` | 512 | [TXT](dist/plain/hijack.txt) | [RSC](dist/mikrotik/hijack.rsc) | [NFT](dist/nftables/hijack.nft) / [SH](dist/nftables/hijack.sh) | [SH](dist/ipset/hijack.sh) | [PS1](dist/windows/hijack.ps1) / [BAT](dist/windows/hijack.bat) | [TXT](dist/pf/hijack.txt) / [SH](dist/pf/hijack.sh) |
| `webserver` | `webserver` | 1,255 | [TXT](dist/plain/webserver.txt) | [RSC](dist/mikrotik/webserver.rsc) | [NFT](dist/nftables/webserver.nft) / [SH](dist/nftables/webserver.sh) | [SH](dist/ipset/webserver.sh) | [PS1](dist/windows/webserver.ps1) / [BAT](dist/windows/webserver.bat) | [TXT](dist/pf/webserver.txt) / [SH](dist/pf/webserver.sh) |
| `combined1` | `etblock` + `feodo` + `toxic` + `webserver` + `hijack` + `dshield7` + `abuseipdb7` | 3,285 | [TXT](dist/plain/combined1.txt) | [RSC](dist/mikrotik/combined1.rsc) | [NFT](dist/nftables/combined1.nft) / [SH](dist/nftables/combined1.sh) | [SH](dist/ipset/combined1.sh) | [PS1](dist/windows/combined1.ps1) / [BAT](dist/windows/combined1.bat) | [TXT](dist/pf/combined1.txt) / [SH](dist/pf/combined1.sh) |
| `combined2` | `etblock` + `feodo` + `toxic` + `webserver` + `hijack` + `dshield30` + `abuseipdb30` + `strongips` | 3,543 | [TXT](dist/plain/combined2.txt) | [RSC](dist/mikrotik/combined2.rsc) | [NFT](dist/nftables/combined2.nft) / [SH](dist/nftables/combined2.sh) | [SH](dist/ipset/combined2.sh) | [PS1](dist/windows/combined2.ps1) / [BAT](dist/windows/combined2.bat) | [TXT](dist/pf/combined2.txt) / [SH](dist/pf/combined2.sh) |
| `complete` | `etblock` + `feodo` + `toxic` + `webserver` + `hijack` + `dshield30` + `abuseipdb30` + `strongips` + `level2` + `level4` + `botnet` | 169,260 | [TXT](dist/plain/complete.txt) | [RSC](dist/mikrotik/complete.rsc) | [NFT](dist/nftables/complete.nft) / [SH](dist/nftables/complete.sh) | [SH](dist/ipset/complete.sh) | [PS1](dist/windows/complete.ps1) / [BAT](dist/windows/complete.bat) | [TXT](dist/pf/complete.txt) / [SH](dist/pf/complete.sh) |
<!-- BLOCKLIST_COUNTS_END -->

### Warning! Firehol Level1 contain bogons (local reserved) IP Addresses

- https://en.wikipedia.org/wiki/List_of_reserved_IP_addresses
- https://en.wikipedia.org/wiki/Bogon_filtering
- if you want similar to level1 IP list without bogons, try et_block

## Mikrotik settings

> first, download, examine, audit the script before you execute on your router!

Run this ONCE in you mikrotik to activate block rule and install the scheduler

```bash
#first activate firewall block rules
/ip/firewall/raw/add chain=prerouting action=drop log-prefix=ipbl comment=ipbl.dennyhalim.com place-before=0 src-address-list=blocklist-combined1
/ip/firewall/raw/add chain=prerouting action=drop log-prefix=ipbl comment=ipbl.dennyhalim.com place-before=0 src-address-list=blocklist-combined2
/ip/firewall/raw/add chain=prerouting action=drop log-prefix=ipbl comment=ipbl.dennyhalim.com place-before=0 src-address-list=blocklist-complete

#download and run installer 
/tool fetch url="https://blacklists.pages.dev/ipbl-installer.rsc"
/system/script/run ipbl-installer.rsc
```

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

The contents and size of each source list can change over time. This repository only converts and combines the configured source data.
