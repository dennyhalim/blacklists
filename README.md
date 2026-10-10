# IP Blocklists

Automatically downloads selected [FireHOL](https://iplists.firehol.org/) IP blocklists, combines them as configured, and generates ready-to-import MikroTik RouterOS `.rsc` address lists.

The generated lists are rebuilt by GitHub Actions and committed back to the repository when they change.

## Generated Lists

<!-- BLOCKLIST_COUNTS_START -->
Last updated: **2026-10-10 04:30:22 UTC**

| List | Sources | Entries | Plain | MikroTik | nftables | ipset | Windows | pf |
|---|---|---:|---|---|---|---|---|---|
| `base3` | `etblock` + `webserver` + `dshield30` + `abuseipdb30` + `lessbogons` + `webclient` + `feodo` | 6,292 | [TXT](dist/plain/base3.txt) | [RSC](dist/mikrotik/base3.rsc) | [NFT](dist/nftables/base3.nft) / [SH](dist/nftables/base3.sh) | [SH](dist/ipset/base3.sh) | [PS1](dist/windows/base3.ps1) / [BAT](dist/windows/base3.bat) | [TXT](dist/pf/base3.txt) / [SH](dist/pf/base3.sh) |
| `baseip` | `feodo` + `etcompromised` + `alienvault` + `threatviewc2` + `censys` | 2,126 | [TXT](dist/plain/baseip.txt) | [RSC](dist/mikrotik/baseip.rsc) | [NFT](dist/nftables/baseip.nft) / [SH](dist/nftables/baseip.sh) | [SH](dist/ipset/baseip.sh) | [PS1](dist/windows/baseip.ps1) / [BAT](dist/windows/baseip.bat) | [TXT](dist/pf/baseip.txt) / [SH](dist/pf/baseip.sh) |
| `server` | `etblock` + `dshield30` + `abuseipdbhuge` + `threatviewc2` + `censys` + `feodo` | 2,664 | [TXT](dist/plain/server.txt) | [RSC](dist/mikrotik/server.rsc) | [NFT](dist/nftables/server.nft) / [SH](dist/nftables/server.sh) | [SH](dist/ipset/server.sh) | [PS1](dist/windows/server.ps1) / [BAT](dist/windows/server.bat) | [TXT](dist/pf/server.txt) / [SH](dist/pf/server.sh) |
| `c2` | `etblock` + `dshield30` + `abuseipdbhuge` + `threatviewc2` + `censys` + `feodo` + `level2` + `threatfox` | 34,564 | [TXT](dist/plain/c2.txt) | [RSC](dist/mikrotik/c2.rsc) | [NFT](dist/nftables/c2.nft) / [SH](dist/nftables/c2.sh) | [SH](dist/ipset/c2.sh) | [PS1](dist/windows/c2.ps1) / [BAT](dist/windows/c2.bat) | [TXT](dist/pf/c2.txt) / [SH](dist/pf/c2.sh) |
| `compact` | `etblock` + `webserver` + `dshield30` + `abuseipdb30` + `lessbogons` + `webclient` + `feodo` + `etcompromised` + `alienvault` + `threatviewc2` + `censys` | 8,312 | [TXT](dist/plain/compact.txt) | [RSC](dist/mikrotik/compact.rsc) | [NFT](dist/nftables/compact.nft) / [SH](dist/nftables/compact.sh) | [SH](dist/ipset/compact.sh) | [PS1](dist/windows/compact.ps1) / [BAT](dist/windows/compact.bat) | [TXT](dist/pf/compact.txt) / [SH](dist/pf/compact.sh) |
| `combined` | `etblock` + `webserver` + `dshield30` + `abuseipdb30` + `lessbogons` + `webclient` + `feodo` + `level2` + `etcompromised` + `alienvault` + `threatviewc2` + `censys` | 26,602 | [TXT](dist/plain/combined.txt) | [RSC](dist/mikrotik/combined.rsc) | [NFT](dist/nftables/combined.nft) / [SH](dist/nftables/combined.sh) | [SH](dist/ipset/combined.sh) | [PS1](dist/windows/combined.ps1) / [BAT](dist/windows/combined.bat) | [TXT](dist/pf/combined.txt) / [SH](dist/pf/combined.sh) |
| `combined4server` | `etblock` + `dshield30` + `abuseipdbhuge` + `threatviewc2` + `censys` + `feodo` + `level4` + `botnet` + `abuser` + `threatview` + `malin` + `graphicline` | 207,495 | [TXT](dist/plain/combined4server.txt) | [RSC](dist/mikrotik/combined4server.rsc) | [NFT](dist/nftables/combined4server.nft) / [SH](dist/nftables/combined4server.sh) | [SH](dist/ipset/combined4server.sh) | [PS1](dist/windows/combined4server.ps1) / [BAT](dist/windows/combined4server.bat) | [TXT](dist/pf/combined4server.txt) / [SH](dist/pf/combined4server.sh) |
| `complete` | `etblock` + `webserver` + `dshield30` + `abuseipdb30` + `lessbogons` + `webclient` + `feodo` + `level2` + `etcompromised` + `alienvault` + `threatviewc2` + `censys` + `threatfox` + `tif` + `mal40k` | 83,058 | [TXT](dist/plain/complete.txt) | [RSC](dist/mikrotik/complete.rsc) | [NFT](dist/nftables/complete.nft) / [SH](dist/nftables/complete.sh) | [SH](dist/ipset/complete.sh) | [PS1](dist/windows/complete.ps1) / [BAT](dist/windows/complete.bat) | [TXT](dist/pf/complete.txt) / [SH](dist/pf/complete.sh) |
| `goliath` | `etblock` + `dshield30` + `abuseipdbhuge` + `threatviewc2` + `censys` + `feodo` + `ipsum2` + `level3` + `abuser30` + `abuseipdb` | 198,785 | [TXT](dist/plain/goliath.txt) | [RSC](dist/mikrotik/goliath.rsc) | [NFT](dist/nftables/goliath.nft) / [SH](dist/nftables/goliath.sh) | [SH](dist/ipset/goliath.sh) | [PS1](dist/windows/goliath.ps1) / [BAT](dist/windows/goliath.bat) | [TXT](dist/pf/goliath.txt) / [SH](dist/pf/goliath.sh) |
<!-- BLOCKLIST_COUNTS_END -->

## first, download, examine, audit the script before you execute on your router!

## Mikrotik settings

Mikrotik with 1 core cpu, choose base. with memory <512M use compact. bigger mikrotik, use combined/complete. just test and see how your mikrotik resources usage.

Run this ONCE in you mikrotik to activate block rule and install the scheduler.

Default script use compact set. make sure your firewall rule match your chosen set to block listed ips.

```bash
#download and run installer 
/tool fetch url="https://blacklists.pages.dev/setup/ipbl-installer.rsc"
/import ipbl-installer.rsc

/tool fetch url="https://blacklists.pages.dev/setup/mtik-dns.rsc"
/import mtik-dns.rsc

```

Overlapping and adjacent networks are collapsed where possible before generating the RouterOS list.

## Proxmox install

first install, run only once
! make sure your proxmox using latest nftables, otherwise use iptables version!
```bash
wget https://blacklists.pages.dev/setup/proxmox-update.sh -O /etc/pve/dhblacklist-update.sh
wget https://blacklists.pages.dev/setup/pve-blacklist.sh -O /usr/local/sbin/dh-blacklist
chmod +x /usr/local/sbin/dh-blacklist
echo '17 */13 * * * root /usr/local/sbin/dh-blacklist >/dev/null 2>&1' >> /etc/crontab
/usr/local/sbin/dh-blacklist
```

check the result

```bash
journalctl -t dh-blacklist
nft list table inet dh_blacklist
nft monitor trace
```

## Ubiquiti / Unifi / UDR / UCG blacklist install

```bash
#download
cd /data
curl -O https://blacklists.pages.dev/setup/ui-install.sh
# INSTALL
sudo ./ui-install.sh
```



## Generated Domain Lists

<!-- DOMAIN_BLOCKLISTS_START -->
Last updated: **2026-10-10 04:30:31 UTC**

| List | Domains | Native rules | Plain | Hosts | Adblock | dnsmasq | dnsmasq nftset | RPZ | Wildcard |
|---|---:|---:|---|---|---|---|---|---|---|
| `phishing` | 127,391 | 76 | [plain](dist/plain/phishing.txt) | [hosts](dist/hosts/phishing.txt) | [adblock](dist/adblock/phishing.txt) | [dnsmasq](dist/dnsmasq/phishing.conf) | [dnsmasq-nftset](dist/dnsmasq-nftset/phishing.conf) | [rpz](dist/rpz/phishing.rpz) | [wildcard](dist/wildcard/phishing.txt) |
| `threat` | 239,681 | 0 | [plain](dist/plain/threat.txt) | [hosts](dist/hosts/threat.txt) | [adblock](dist/adblock/threat.txt) | [dnsmasq](dist/dnsmasq/threat.conf) | [dnsmasq-nftset](dist/dnsmasq-nftset/threat.conf) | [rpz](dist/rpz/threat.rpz) | [wildcard](dist/wildcard/threat.txt) |
| `scam` | 16,979 | 12 | [plain](dist/plain/scam.txt) | [hosts](dist/hosts/scam.txt) | [adblock](dist/adblock/scam.txt) | [dnsmasq](dist/dnsmasq/scam.conf) | [dnsmasq-nftset](dist/dnsmasq-nftset/scam.conf) | [rpz](dist/rpz/scam.rpz) | [wildcard](dist/wildcard/scam.txt) |
| `gambling` | 138,933 | 6,699 | [plain](dist/plain/gambling.txt) | [hosts](dist/hosts/gambling.txt) | [adblock](dist/adblock/gambling.txt) | [dnsmasq](dist/dnsmasq/gambling.conf) | [dnsmasq-nftset](dist/dnsmasq-nftset/gambling.conf) | [rpz](dist/rpz/gambling.rpz) | [wildcard](dist/wildcard/gambling.txt) |
| `nsfw` | 138,691 | 76,797 | [plain](dist/plain/nsfw.txt) | [hosts](dist/hosts/nsfw.txt) | [adblock](dist/adblock/nsfw.txt) | [dnsmasq](dist/dnsmasq/nsfw.conf) | [dnsmasq-nftset](dist/dnsmasq-nftset/nsfw.conf) | [rpz](dist/rpz/nsfw.rpz) | [wildcard](dist/wildcard/nsfw.txt) |

### Platform compatibility

- **Pi-hole** → `plain` output
- **AdGuard Home** → `adblock` output
- **uBlock Origin** → `adblock` output
- **Adblock Plus** → `adblock` output
- **dnsmasq** → `dnsmasq` output
- **dnsmasq+nftables** → `dnsmasq-nftset` output
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

