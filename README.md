# IP Blocklists

Automatically downloads selected [FireHOL](https://iplists.firehol.org/) IP blocklists, combines them as configured, and generates ready-to-import MikroTik RouterOS `.rsc` address lists.

The generated lists are rebuilt by GitHub Actions and committed back to the repository when they change.

## Generated Lists

<!-- BLOCKLIST_COUNTS_START -->
Last updated: **2026-09-16 14:03:01 UTC**

| List | Sources | Entries | Plain | MikroTik | nftables | ipset | Windows | pf |
|---|---|---:|---|---|---|---|---|---|
| `base3` | `etblock` + `webserver` + `dshield30` + `abuseipdb30` + `feodo` | 2,815 | [TXT](dist/plain/base3.txt) | [RSC](dist/mikrotik/base3.rsc) | [NFT](dist/nftables/base3.nft) / [SH](dist/nftables/base3.sh) | [SH](dist/ipset/base3.sh) | [PS1](dist/windows/base3.ps1) / [BAT](dist/windows/base3.bat) | [TXT](dist/pf/base3.txt) / [SH](dist/pf/base3.sh) |
| `base7` | `etblock` + `webserver` + `dshield7` + `abuseipdb7` + `feodo` | 2,826 | [TXT](dist/plain/base7.txt) | [RSC](dist/mikrotik/base7.rsc) | [NFT](dist/nftables/base7.nft) / [SH](dist/nftables/base7.sh) | [SH](dist/ipset/base7.sh) | [PS1](dist/windows/base7.ps1) / [BAT](dist/windows/base7.bat) | [TXT](dist/pf/base7.txt) / [SH](dist/pf/base7.sh) |
| `baseip` | `feodo` + `strongips` + `etcompromised` + `webclient` | 1,398 | [TXT](dist/plain/baseip.txt) | [RSC](dist/mikrotik/baseip.rsc) | [NFT](dist/nftables/baseip.nft) / [SH](dist/nftables/baseip.sh) | [SH](dist/ipset/baseip.sh) | [PS1](dist/windows/baseip.ps1) / [BAT](dist/windows/baseip.bat) | [TXT](dist/pf/baseip.txt) / [SH](dist/pf/baseip.sh) |
| `compact` | `etblock` + `webserver` + `dshield7` + `abuseipdb7` + `feodo` + `ipsum7` + `strongips` + `etcompromised` + `webclient` | 4,203 | [TXT](dist/plain/compact.txt) | [RSC](dist/mikrotik/compact.rsc) | [NFT](dist/nftables/compact.nft) / [SH](dist/nftables/compact.sh) | [SH](dist/ipset/compact.sh) | [PS1](dist/windows/compact.ps1) / [BAT](dist/windows/compact.bat) | [TXT](dist/pf/compact.txt) / [SH](dist/pf/compact.sh) |
| `combined` | `etblock` + `webserver` + `dshield30` + `abuseipdb30` + `feodo` + `ipsum3` + `strongips` + `etcompromised` + `webclient` | 13,993 | [TXT](dist/plain/combined.txt) | [RSC](dist/mikrotik/combined.rsc) | [NFT](dist/nftables/combined.nft) / [SH](dist/nftables/combined.sh) | [SH](dist/ipset/combined.sh) | [PS1](dist/windows/combined.ps1) / [BAT](dist/windows/combined.bat) | [TXT](dist/pf/combined.txt) / [SH](dist/pf/combined.sh) |
| `combined4server` | `etblock` + `webserver` + `dshield30` + `abuseipdb30` + `feodo` + `threatfox` + `level4` + `abuser` + `botnet` + `abuseipdb` | 217,756 | [TXT](dist/plain/combined4server.txt) | [RSC](dist/mikrotik/combined4server.rsc) | [NFT](dist/nftables/combined4server.nft) / [SH](dist/nftables/combined4server.sh) | [SH](dist/ipset/combined4server.sh) | [PS1](dist/windows/combined4server.ps1) / [BAT](dist/windows/combined4server.bat) | [TXT](dist/pf/combined4server.txt) / [SH](dist/pf/combined4server.sh) |
| `complete` | `etblock` + `webserver` + `dshield30` + `abuseipdb30` + `feodo` + `ipsum3` + `strongips` + `etcompromised` + `webclient` + `threatfox` + `level2` + `level3` + `tif` | 73,555 | [TXT](dist/plain/complete.txt) | [RSC](dist/mikrotik/complete.rsc) | [NFT](dist/nftables/complete.nft) / [SH](dist/nftables/complete.sh) | [SH](dist/ipset/complete.sh) | [PS1](dist/windows/complete.ps1) / [BAT](dist/windows/complete.bat) | [TXT](dist/pf/complete.txt) / [SH](dist/pf/complete.sh) |
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



## Generated Domain Lists

<!-- DOMAIN_BLOCKLISTS_START -->
Last updated: **2026-09-16 14:03:09 UTC**

| List | Domains | Native rules | Plain | Hosts | Adblock | dnsmasq | RPZ | Wildcard |
|---|---:|---:|---|---|---|---|---|---|
| `threat` | 186,544 | 8,901 | [plain](dist/plain/threat.txt) | [hosts](dist/hosts/threat.txt) | [adblock](dist/adblock/threat.txt) | [dnsmasq](dist/dnsmasq/threat.conf) | [rpz](dist/rpz/threat.rpz) | [wildcard](dist/wildcard/threat.txt) |
| `fake` | 205,038 | 28,127 | [plain](dist/plain/fake.txt) | [hosts](dist/hosts/fake.txt) | [adblock](dist/adblock/fake.txt) | [dnsmasq](dist/dnsmasq/fake.conf) | [rpz](dist/rpz/fake.rpz) | [wildcard](dist/wildcard/fake.txt) |
| `gambling` | 74,785 | 6,644 | [plain](dist/plain/gambling.txt) | [hosts](dist/hosts/gambling.txt) | [adblock](dist/adblock/gambling.txt) | [dnsmasq](dist/dnsmasq/gambling.conf) | [rpz](dist/rpz/gambling.rpz) | [wildcard](dist/wildcard/gambling.txt) |
| `nsfw` | 124,214 | 76,770 | [plain](dist/plain/nsfw.txt) | [hosts](dist/hosts/nsfw.txt) | [adblock](dist/adblock/nsfw.txt) | [dnsmasq](dist/dnsmasq/nsfw.conf) | [rpz](dist/rpz/nsfw.rpz) | [wildcard](dist/wildcard/nsfw.txt) |

### Platform compatibility

- **Pi-hole** → `plain` output
- **AdGuard Home** → `adblock` output
- **uBlock Origin** → `adblock` output
- **Adblock Plus** → `adblock` output
- **dnsmasq** → `dnsmasq` output
- **BIND RPZ** → `rpz` output
<!-- DOMAIN_BLOCKLISTS_END -->

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

