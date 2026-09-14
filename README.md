# IP Blocklists

Automatically downloads selected [FireHOL](https://iplists.firehol.org/) IP blocklists, combines them as configured, and generates ready-to-import MikroTik RouterOS `.rsc` address lists.

The generated lists are rebuilt by GitHub Actions and committed back to the repository when they change.

## Generated Lists

<!-- BLOCKLIST_COUNTS_START -->
Last updated: **2026-09-14 09:50:10 UTC**

| List | Sources | Entries | Plain | MikroTik | nftables | ipset | Windows | pf |
|---|---|---:|---|---|---|---|---|---|
| `level4` | `level4` | 146,301 | [TXT](dist/plain/level4.txt) | [RSC](dist/mikrotik/level4.rsc) | [NFT](dist/nftables/level4.nft) / [SH](dist/nftables/level4.sh) | [SH](dist/ipset/level4.sh) | [PS1](dist/windows/level4.ps1) / [BAT](dist/windows/level4.bat) | [TXT](dist/pf/level4.txt) / [SH](dist/pf/level4.sh) |
| `etblock` | `etblock` | 1,632 | [TXT](dist/plain/etblock.txt) | [RSC](dist/mikrotik/etblock.rsc) | [NFT](dist/nftables/etblock.nft) / [SH](dist/nftables/etblock.sh) | [SH](dist/ipset/etblock.sh) | [PS1](dist/windows/etblock.ps1) / [BAT](dist/windows/etblock.bat) | [TXT](dist/pf/etblock.txt) / [SH](dist/pf/etblock.sh) |
| `hijack` | `hijack` | 512 | [TXT](dist/plain/hijack.txt) | [RSC](dist/mikrotik/hijack.rsc) | [NFT](dist/nftables/hijack.nft) / [SH](dist/nftables/hijack.sh) | [SH](dist/ipset/hijack.sh) | [PS1](dist/windows/hijack.ps1) / [BAT](dist/windows/hijack.bat) | [TXT](dist/pf/hijack.txt) / [SH](dist/pf/hijack.sh) |
| `webserver` | `webserver` | 1,323 | [TXT](dist/plain/webserver.txt) | [RSC](dist/mikrotik/webserver.rsc) | [NFT](dist/nftables/webserver.nft) / [SH](dist/nftables/webserver.sh) | [SH](dist/ipset/webserver.sh) | [PS1](dist/windows/webserver.ps1) / [BAT](dist/windows/webserver.bat) | [TXT](dist/pf/webserver.txt) / [SH](dist/pf/webserver.sh) |
| `compact` | `etblock` + `feodo` + `toxic` + `dshield7` + `abuseipdb7` + `ipsum7` | 1,890 | [TXT](dist/plain/compact.txt) | [RSC](dist/mikrotik/compact.rsc) | [NFT](dist/nftables/compact.nft) / [SH](dist/nftables/compact.sh) | [SH](dist/ipset/compact.sh) | [PS1](dist/windows/compact.ps1) / [BAT](dist/windows/compact.bat) | [TXT](dist/pf/compact.txt) / [SH](dist/pf/compact.sh) |
| `compact1` | `etblock` + `feodo` + `dshield7` + `abuseipdb7` | 1,674 | [TXT](dist/plain/compact1.txt) | [RSC](dist/mikrotik/compact1.rsc) | [NFT](dist/nftables/compact1.nft) / [SH](dist/nftables/compact1.sh) | [SH](dist/ipset/compact1.sh) | [PS1](dist/windows/compact1.ps1) / [BAT](dist/windows/compact1.bat) | [TXT](dist/pf/compact1.txt) / [SH](dist/pf/compact1.sh) |
| `combined` | `etblock` + `feodo` + `toxic` + `webserver` + `dshield30` + `abuseipdb30` + `ipsum3` + `strongips` + `etcompromised` | 14,484 | [TXT](dist/plain/combined.txt) | [RSC](dist/mikrotik/combined.rsc) | [NFT](dist/nftables/combined.nft) / [SH](dist/nftables/combined.sh) | [SH](dist/ipset/combined.sh) | [PS1](dist/windows/combined.ps1) / [BAT](dist/windows/combined.bat) | [TXT](dist/pf/combined.txt) / [SH](dist/pf/combined.sh) |
| `combined1` | `etblock` + `feodo` + `toxic` + `webserver` + `dshield30` + `abuseipdb30` + `ipsum3` | 14,078 | [TXT](dist/plain/combined1.txt) | [RSC](dist/mikrotik/combined1.rsc) | [NFT](dist/nftables/combined1.nft) / [SH](dist/nftables/combined1.sh) | [SH](dist/ipset/combined1.sh) | [PS1](dist/windows/combined1.ps1) / [BAT](dist/windows/combined1.bat) | [TXT](dist/pf/combined1.txt) / [SH](dist/pf/combined1.sh) |
| `combined2` | `etblock` + `feodo` + `toxic` + `webserver` + `dshield30` + `abuseipdb30` + `strongips` + `ipsum3` | 14,182 | [TXT](dist/plain/combined2.txt) | [RSC](dist/mikrotik/combined2.rsc) | [NFT](dist/nftables/combined2.nft) / [SH](dist/nftables/combined2.sh) | [SH](dist/ipset/combined2.sh) | [PS1](dist/windows/combined2.ps1) / [BAT](dist/windows/combined2.bat) | [TXT](dist/pf/combined2.txt) / [SH](dist/pf/combined2.sh) |
| `complete` | `etblock` + `feodo` + `toxic` + `webserver` + `dshield30` + `abuseipdb30` + `strongips` + `ipsum3` + `level2` + `level3` + `botnet` + `etcompromised` | 53,294 | [TXT](dist/plain/complete.txt) | [RSC](dist/mikrotik/complete.rsc) | [NFT](dist/nftables/complete.nft) / [SH](dist/nftables/complete.sh) | [SH](dist/ipset/complete.sh) | [PS1](dist/windows/complete.ps1) / [BAT](dist/windows/complete.bat) | [TXT](dist/pf/complete.txt) / [SH](dist/pf/complete.sh) |
<!-- BLOCKLIST_COUNTS_END -->

## first, download, examine, audit the script before you execute on your router!

## Mikrotik settings

Run this ONCE in you mikrotik to activate block rule and install the scheduler

```bash
#first activate firewall block rules
/ip/firewall/raw/add chain=prerouting action=drop log-prefix=ipbl comment=ipbl.dennyhalim.com place-before=0 src-address-list=blocklist-complete
/ip/firewall/raw/add chain=prerouting action=drop log-prefix=ipbl comment=ipbl.dennyhalim.com place-before=0 src-address-list=blocklist-combined
/ip/firewall/raw/add chain=prerouting action=drop log-prefix=ipbl comment=ipbl.dennyhalim.com place-before=0 src-address-list=blocklist-compact

#download and run installer 
/tool fetch url="https://blacklists.pages.dev/ipbl-installer.rsc"
import ipbl-installer.rsc
```

Overlapping and adjacent networks are collapsed where possible before generating the RouterOS list.

## Ubiquiti / Unifi / UDR / UCG blacklist install

```bash
#download
cd /data
curl -O https://blacklists.pages.dev/ui-install.sh
#examine
less ui-install.sh
# INSTALL
sudo ./ui-install.sh
```


## Local Build

Requires Python 3.10+ and no third-party packages.

```bash
python scripts/build_blocklists.py
```

The builder:

* downloads each required feed only once;
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


## Data Source

IP blocklists are provided by FireHOL IP Lists.

The contents and size of each source list can change over time. This repository only converts and combines the configured source data.
