#!/usr/bin/env python3
"""
Compact DNS/adblock list builder.

Downloads public blocklists, normalizes domains, protects Tranco top sites,
uses PSL boundaries for safe parent collapsing, ranks candidates, and writes
small category lists for Adblock/uBlock/AdGuard, Pi-hole and MikroTik.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
import urllib.request
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

UA = "compact-blocklist/1.0 (+local list compiler)"
DEFAULT_LIMIT = 50
COLLAPSE_MIN = 4

SOURCES = {
    "ads": [
        ("peter-ads", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain&showintro=0&notrackers=1"),
#        ("steven-base", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
#        ("hagezi-light", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt"),
        ("easylist", "https://easylist.to/easylist/easylist.txt"),
    ],
    "trackers": [
        ("peter-trackers", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=plain&showintro=0&onlytrackers=1"),
#        ("hagezi-light", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt"),
        ("easyprivacy", "https://easylist.to/easylist/easyprivacy.txt"),
    ],
    "nsfw": [
        ("hagezi-nsfw", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt"),
        ("steven-porn", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"),
    ],
    "threats": [
        ("hagezi-tif", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt"),
        ("urlhaus", "https://urlhaus.abuse.ch/downloads/text"),
    ],
    "gambling": [
        ("hagezi-gambling-mini", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling.mini-onlydomains.txt"),
        ("steven-gambling", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts"),
    ],
}

STREAM_BASE1 = "https://raw.githubusercontent.com/pedro-nsy/nsy-dns-blocklist/main/lists/"
STREAM_BASE2 = "https://raw.githubusercontent.com/lennysh/dns-blocklists/main/service-filters/"
SOURCES["streaming"] = [
    ("yt", STREAM_BASE1 + "youtube.txt"),
    ("short", STREAM_BASE1 + "short-video.txt"),
    ("streaming", STREAM_BASE1 + "streaming-tv.txt"),
    ("netflix", STREAM_BASE2 + "netflix.txt"),
    ("tiktok", STREAM_BASE2 + "tiktok.txt"),
]

DOMAIN_RE = re.compile(
    r"(?i)(?:^|[\s|/@=,:])(?:https?://)?(?:www\.)?"
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63})"
)

def fetch(url: str, timeout: int = 45) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def normalize(domain: str) -> str | None:
    d = domain.strip().lower().rstrip(".")
    if d.startswith(("localhost", "local.")) or len(d) > 253 or "." not in d:
        return None
    try:
        d = d.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = d.split(".")
    if any(not x or len(x) > 63 or x[0] == "-" or x[-1] == "-" for x in labels):
        return None
    if not all(re.fullmatch(r"[a-z0-9-]+", x) for x in labels):
        return None
    return d

def parse_domains(text: str) -> set[str]:
    out = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "!", "[", ";")):
            continue
        line = line.split("#", 1)[0].strip()
        # hosts, plain-domain, ABP/uBO/AdGuard and dnsmasq-ish inputs
        for token in re.findall(r"[A-Za-z0-9._-]+\.[A-Za-z0-9.-]+", line):
            d = normalize(token.strip("|^.*"))
            if d and not re.fullmatch(r"\d+(?:\.\d+){3}", d):
                out.add(d)
    return out

class PSL:
    def __init__(self, text: str):
        self.normal, self.wild, self.exc = set(), set(), set()
        for raw in text.splitlines():
            s = raw.strip().lower()
            if not s or s.startswith("//"):
                continue
            if s.startswith("!"):
                self.exc.add(s[1:])
            elif s.startswith("*."):
                self.wild.add(s[2:])
            else:
                self.normal.add(s)

    def registrable(self, domain: str) -> str:
        parts = domain.split(".")
        best = 1
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if suffix in self.exc:
                best = max(1, len(parts) - i - 1)
                break
            if suffix in self.normal:
                best = max(best, len(parts) - i)
            if i + 1 < len(parts) and ".".join(parts[i + 1:]) in self.wild:
                best = max(best, len(parts) - i)
        return domain if len(parts) <= best else ".".join(parts[-(best + 1):])

def load_tranco(limit: int) -> tuple[dict[str, int], set[str]]:
    data = fetch("https://tranco-list.eu/top-1m.csv.zip")
    ranks, top = {}, set()
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        name = zf.namelist()[0]
        with zf.open(name) as fh:
            for row in csv.reader(io.TextIOWrapper(fh, encoding="utf-8")):
                if len(row) < 2:
                    continue
                rank, domain = int(row[0]), normalize(row[1])
                if not domain:
                    continue
                ranks[domain] = rank
                if rank <= limit:
                    top.add(domain)
                if rank >= max(limit, 100_000):
                    break
    return ranks, top

def collapse(domains: set[str], psl: PSL, protected: set[str]) -> set[str]:
    groups = defaultdict(set)
    for d in domains:
        groups[psl.registrable(d)].add(d)

    out = set()
    for parent, children in groups.items():
        # Never promote a blocked subdomain to a popular registrable parent.
        if parent not in protected and (parent in children or len(children) >= COLLAPSE_MIN):
            out.add(parent)
        else:
            out.update(children)
    return out

def rank_domains(domains: set[str], votes: Counter, tranco: dict[str, int],
                 psl: PSL, limit: int) -> list[str]:
    def score(d: str):
        parent = psl.registrable(d)
        rank = tranco.get(parent, 2_000_000)
        # More independent source votes first, then web popularity, then shorter rules.
        return (-votes[d], rank, d.count("."), len(d), d)
    return sorted(domains, key=score)[:limit]

def pattern_report(outdir: Path, category: str, domains: set[str],
                   psl: PSL, protected: set[str], minimum: int = 3) -> None:
    """Suggest frequent label patterns; never deploy them automatically."""
    counts = Counter()
    examples = defaultdict(list)
    popular = Counter()
    for domain in sorted(domains):
        parent = psl.registrable(domain)
        # Ignore suffix labels and one/two-character fragments.
        labels = domain[:-len(parent)].rstrip(".").split(".") if domain != parent else []
        labels += parent.split(".")[:1]
        tokens = {x for label in labels for x in re.split(r"[-_0-9]+", label)
                  if 3 <= len(x) <= 24 and x not in {"www", "com", "net", "org", "cdn", "static"}}
        for token in tokens:
            counts[token] += 1
            if len(examples[token]) < 5:
                examples[token].append(domain)
            if parent in protected:
                popular[token] += 1
    rows = [{"pattern": token, "domains": count,
             "tranco_protected_matches": popular[token], "examples": examples[token],
             "suggested_regex": rf"(^|\.)[^.]*{re.escape(token)}[^.]*\."
             } for token, count in counts.most_common() if count >= minimum]
    # Frequent tokens are discovery hints, not safe DNS rules.
    (outdir / f"{category}.patterns.json").write_text(
        json.dumps(rows[:100], indent=2) + "\n", encoding="utf-8")
    with (outdir / f"{category}.patterns.txt").open("w", encoding="utf-8") as f:
        f.write("# REVIEW ONLY: substring patterns may block legitimate domains.\n")
        f.write("# pattern | matched domains | Tranco-protected matches | examples\n")
        for row in rows[:100]:
            f.write(f"{row['pattern']} | {row['domains']} | "
                    f"{row['tranco_protected_matches']} | {', '.join(row['examples'])}\n")


def collect(category: str, psl: PSL, tranco: dict[str, int],
            protected: set[str], limit: int, outdir: Path,
            minimum: int) -> list[str]:
    votes, union = Counter(), set()
    for name, url in SOURCES[category]:
        print(f"[{category}] {name}", file=sys.stderr)
        domains = parse_domains(fetch(url).decode("utf-8", "replace"))
        for d in domains:
            votes[d] += 1
        union |= domains

    pattern_report(outdir, category, union, psl, protected, minimum)
    compact = collapse(union, psl, protected)
    # Parent rules inherit the strongest vote among their covered source domains.
    parent_votes = defaultdict(int)
    for domain, count in votes.items():
        parent = psl.registrable(domain)
        parent_votes[parent] = max(parent_votes[parent], count)
    for d in compact:
        if votes[d] == 0:
            votes[d] = parent_votes[psl.registrable(d)] or 1
    return rank_domains(compact, votes, tranco, psl, limit)

def write_outputs(outdir: Path, category: str, domains: list[str]) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    header = f"! compact-blocklist category={category} entries={len(domains)}\n"

    (outdir / f"{category}.adblock.txt").write_text(
        header + "\n".join(f"||{d}^" for d in domains) + "\n", encoding="utf-8")
    (outdir / f"{category}.pihole.txt").write_text(
        "\n".join(domains) + "\n", encoding="utf-8")

    # MikroTik: group up to 5 domains per regex to keep rule count small.
    mt = ["# RouterOS DNS static NXDOMAIN rules"]
    for i in range(0, len(domains), 5):
        chunk = domains[i:i + 5]
        alternatives = "|".join(re.escape(d) for d in chunk)
        mt.append(f'/ip dns static add regexp="(^|\\\\.)({alternatives})$" type=NXDOMAIN comment="{category}"')
    (outdir / f"{category}.mikrotik.rsc").write_text("\n".join(mt) + "\n", encoding="utf-8")

def main() -> int:
    ap = argparse.ArgumentParser(description="Build small ranked DNS/adblock category lists.")
    ap.add_argument("-n", "--limit", type=int, default=DEFAULT_LIMIT, help="rules per category (default: 50)")
    ap.add_argument("-o", "--out", default="compact-blocklists", help="output directory")
    ap.add_argument("--tranco-protect", type=int, default=100_000,
                    help="never collapse subdomains into these top Tranco parents")
    ap.add_argument("--pattern-min", type=int, default=3, help="minimum domains per suggested pattern")
    ap.add_argument("--categories", nargs="+",
                    choices=["ads", "trackers", "nsfw", "gambling", "streaming", "threats"],
                    default=["ads", "trackers", "nsfw", "gambling", "streaming", "threats"])
    args = ap.parse_args()

    if args.limit < 1 or args.tranco_protect < 0 or args.pattern_min < 1:
        ap.error("limits must be positive")

    print("[meta] Public Suffix List", file=sys.stderr)
    psl = PSL(fetch("https://publicsuffix.org/list/public_suffix_list.dat").decode("utf-8", "replace"))
    print("[meta] Tranco", file=sys.stderr)
    tranco, protected = load_tranco(args.tranco_protect)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for category in args.categories:
        domains = collect(category, psl, tranco, protected, args.limit, out, args.pattern_min)
        write_outputs(out, category, domains)
        print(f"[done] {category}: {len(domains)}", file=sys.stderr)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

