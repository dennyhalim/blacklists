#!/usr/bin/env python3
"""Convert a small DNS hostname rule language to common DNS blocker formats."""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

KINDS = {"domain", "suffix", "contains", "prefix", "endswith", "regex"}
TARGETS = {"pihole", "adguard", "ublock", "rpz", "mikrotik"}


@dataclass(frozen=True, slots=True)
class Rule:
    kind: str
    value: str
    line: int = 0


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("."):
        value = value[1:]
    if not value or len(value) > 253:
        raise ValueError("invalid domain")
    labels = value.split(".")
    if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9_-]+", label) for label in labels):
        raise ValueError(f"invalid domain: {value!r}")
    return value


def parse_simple(text: str) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[tuple[str, str]] = set()

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "!")):
            continue
        if ":" not in line:
            raise ValueError(f"line {lineno}: expected TYPE:VALUE")

        kind, raw_value = (part.strip() for part in line.split(":", 1))
        kind = kind.lower()
        if kind not in KINDS:
            raise ValueError(f"line {lineno}: unsupported rule type {kind!r}")
        if not raw_value:
            raise ValueError(f"line {lineno}: empty value")

        # "|" separates compact value lists except for regex, where it keeps
        # its normal alternation meaning.
        values = [raw_value] if kind == "regex" else [v.strip() for v in raw_value.split("|")]
        if any(not value for value in values):
            raise ValueError(f"line {lineno}: empty value in list")

        for value in values:
            if kind in {"domain", "suffix"}:
                value = normalize_domain(value)
            elif kind != "regex":
                value = value.lower()
            else:
                try:
                    re.compile(value)
                except re.error as exc:
                    raise ValueError(f"line {lineno}: invalid regex: {exc}") from exc

            key = (kind, value)
            if key not in seen:
                seen.add(key)
                rules.append(Rule(kind, value, lineno))

    return rules

def hostname_regex(rule: Rule) -> str:
    """Return an unanchored/anchored regex applied to a DNS hostname."""
    v = rule.value
    if rule.kind == "domain":
        return rf"(^|\.){re.escape(v)}$"
    if rule.kind == "suffix":
        return rf"(^|\.){re.escape(v)}$"
    if rule.kind == "contains":
        return re.escape(v)
    if rule.kind == "prefix":
        return rf"(^|\.){re.escape(v)}"
    if rule.kind == "endswith":
        return rf"{re.escape(v)}(\.|$)"
    return v


def render_pihole(rules: list[Rule]) -> tuple[str, list[str]]:
    # Pi-hole regex blacklist: one hostname regex per line.
    return "\n".join(hostname_regex(r) for r in rules) + "\n", []


def render_adguard(rules: list[Rule]) -> tuple[str, list[str]]:
    out: list[str] = []
    for r in rules:
        if r.kind in {"domain", "suffix"}:
            out.append(f"||{r.value}^")
        else:
            out.append(f"/{hostname_regex(r)}/")
    return "\n".join(out) + "\n", []


def render_ublock(rules: list[Rule]) -> tuple[str, list[str]]:
    # DNS-only intent: constrain native rules to hostname and regex rules to
    # document hostnames using $domain= is not equivalent. Therefore emit
    # hostname-oriented network rules only; consumers must apply at DNS scope.
    out: list[str] = []
    for r in rules:
        if r.kind in {"domain", "suffix"}:
            out.append(f"||{r.value}^")
        else:
            out.append(f"/{hostname_regex(r)}/")
    return "\n".join(out) + "\n", []


def render_rpz(rules: list[Rule]) -> tuple[str, list[str]]:
    out: list[str] = []
    warnings: list[str] = []
    for r in rules:
        if r.kind not in {"domain", "suffix"}:
            warnings.append(f"line {r.line}: RPZ cannot represent {r.kind}:{r.value}")
            continue
        out.append(f"{r.value} CNAME .")
        out.append(f"*.{r.value} CNAME .")
    return ("\n".join(out) + ("\n" if out else "")), warnings


def routeros_quote(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render_mikrotik(rules: list[Rule]) -> tuple[str, list[str]]:
    out = ["/ip dns static"]
    for r in rules:
        rx = routeros_quote(hostname_regex(r))
        out.append(f'add regexp="{rx}" type=NXDOMAIN comment="dnsfilterconv"')
    return "\n".join(out) + "\n", []


RENDERERS = {
    "pihole": render_pihole,
    "adguard": render_adguard,
    "ublock": render_ublock,
    "rpz": render_rpz,
    "mikrotik": render_mikrotik,
}


def convert(text: str, target: str) -> tuple[str, list[str]]:
    if target not in TARGETS:
        raise ValueError(f"unsupported target: {target}")
    return RENDERERS[target](parse_simple(text))


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert DNS hostname filters between simple target formats.")
    parser.add_argument("inputs", type=Path, nargs="+", help="input files using TYPE:VALUE rules")
    parser.add_argument("--to", choices=sorted(TARGETS), help="output format; omit to generate every supported format")
    parser.add_argument("-o", "--output", type=Path, help="output file; only valid with one input and --to")
    parser.add_argument(
        "-d", "--output-dir",
        type=Path,
        help="directory for generated files; defaults to each input file's directory",
    )
    args = parser.parse_args()

    if args.output and (not args.to or len(args.inputs) != 1):
        parser.error("--output requires exactly one input and --to")
    if args.output and args.output_dir:
        parser.error("--output and --output-dir cannot be used together")

    try:
        if args.output_dir:
            args.output_dir.mkdir(parents=True, exist_ok=True)

        for input_path in args.inputs:
            text = input_path.read_text(encoding="utf-8")
            targets = [args.to] if args.to else sorted(TARGETS)

            for target in targets:
                output, warnings = convert(text, target)

                if args.output:
                    output_path = args.output
                else:
                    output_dir = args.output_dir or input_path.parent
                    output_path = output_dir / f"{input_path.stem}-{target}.txt"

                output_path.write_text(output, encoding="utf-8")
                print(output_path)

                for warning in warnings:
                    print(
                        f"warning [{input_path.name}:{target}]: {warning}",
                        file=sys.stderr,
                    )

    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
