#!/usr/bin/env python3
"""Fail if staged (or all) files reintroduce scan-target breadcrumbs.

Does not print forbidden plaintext. Hits are reported by rule id and location.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST_PATH = ROOT / "config" / "host-allowlist.txt"

SKIP_DIR_PARTS = {
    ".git",
    "target",
    "vendor",
    "node_modules",
    ".cursor",
}

SKIP_FILES = {
    "config/gitleaks.toml",  # upstream catalog
    "config/host-allowlist.txt",
    "scripts/host_hygiene.py",
}

# sha256(utf-8) of strings that must never reappear. Labels are generic.
FORBIDDEN_SHA256 = {
    "2f0123184a6cd0c63ea3f6bbb9f3da7d30c9e5d82a531e43c1a7875b736eaf2d": "named-scan-host",
    "ef4781dfb825c8c91e475ecb59bf689a18c330eb5742ed8b4398a9e60b45953d": "live-finding-token",
    "a1119dca3a3949d273cfefd9948025cc5fa8ec191004a22329a82d9da7f1f04b": "live-gtm-id",
    "19115a18da945c5952e3b30b741a267d6d9834e36de42de8c99b1de0c97952ca": "live-gtm-id",
    "406fb0d2cbb314c2b0b20da5691c4d0ccee114e3b1ba8dee8d2404e7ee3a1993": "named-company-host",
    "27758b3c561ec38c495037c509ccd3d9238fb106b36ec0145d36243dc96ee54f": "named-company",
    "67e89fcc5bec9736224996d23e660535e87b148ceda9650a448052b542a29a13": "scan-derived-key",
    "4281b6977613ca30b9ebd884daad9298b820011e0c954c0199478f7400b25f7d": "scan-derived-uuid",
    "3e61ee121c63cb561e54e88fc01301979a8d65da9de49df1972b63cf9b8c407b": "corpus-provenance",
    "ca363c20a2551ac1e5bada5ad7eb74214611a0f9e6c5700780c83e6dd92be149": "corpus-count",
}

PROVENANCE = [
    (
        "corpus-mcp",
        re.compile(r"analyst\s+MCP", re.I),
    ),
    (
        "corpus-23k",
        re.compile(r"\b23k\s+DB\b", re.I),
    ),
    (
        "corpus-count",
        re.compile(r"\ba checked set of\b"),
    ),
    (
        "corpus-historical-nk",
        re.compile(r"historical\s+\d+k\s+DB", re.I),
    ),
    (
        "observed-on",
        re.compile(r"observed\s+(?:on|at)\b", re.I),
    ),
    (
        "n-sites",
        re.compile(r"\b(?:across\s+)?\d+\s+sites\b", re.I),
    ),
    (
        "like-company-host",
        re.compile(r"\blike\s+[A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+)*\.com\b"),
    ),
]

HOST_RE = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|edu|gov|bank|me)\b",
    re.I,
)

TOKEN_RE = re.compile(r"[A-Za-z0-9_./+-]{8,}")


def load_allowlist() -> tuple[set[str], list[str]]:
    exact: set[str] = set()
    suffixes: list[str] = []
    for raw in ALLOWLIST_PATH.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        if line.startswith("."):
            suffixes.append(line)
        else:
            exact.add(line)
    return exact, suffixes


def host_allowed(host: str, exact: set[str], suffixes: list[str]) -> bool:
    h = host.lower().rstrip(".")
    parts = h.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in exact:
            return True
    for suf in suffixes:
        if h == suf[1:] or h.endswith(suf):
            return True
    if len(parts) == 2 and parts[0] in {
        "test",
        "ok",
        "foo",
        "bar",
        "baz",
        "qux",
    }:
        return True
    return False


def should_skip(path: Path) -> bool:
    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        return True
    if rel.as_posix() in SKIP_FILES:
        return True
    return any(part in SKIP_DIR_PARTS for part in rel.parts)


def staged_paths() -> list[Path]:
    out = subprocess.check_output(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        cwd=ROOT,
        text=True,
    )
    paths = []
    for line in out.splitlines():
        p = ROOT / line
        if p.is_file() and not should_skip(p):
            paths.append(p)
    return paths


def tree_paths() -> list[Path]:
    out = subprocess.check_output(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        text=True,
    )
    paths = []
    for line in out.split("\0"):
        if not line:
            continue
        p = ROOT / line
        if p.is_file() and not should_skip(p):
            paths.append(p)
    return paths


def sha256_utf8(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def scan_text(rel: str, text: str, exact: set[str], suffixes: list[str]) -> list[str]:
    hits: list[str] = []
    for i, line in enumerate(text.splitlines(), 1):
        for rule, cre in PROVENANCE:
            if cre.search(line):
                hits.append(f"{rel}:{i}: {rule}")
        for tok in TOKEN_RE.findall(line):
            digest = sha256_utf8(tok)
            if digest in FORBIDDEN_SHA256:
                hits.append(f"{rel}:{i}: forbidden:{FORBIDDEN_SHA256[digest]}")
        commentish = (
            rel.endswith((".md", ".toml"))
            or line.lstrip().startswith(("#", "//", "///", "//!", "*"))
        )
        if commentish:
            for host in HOST_RE.findall(line):
                if not host_allowed(host, exact, suffixes):
                    hits.append(f"{rel}:{i}: unallowlisted-host")
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Scan the working tree instead of staged files",
    )
    args = parser.parse_args()

    exact, suffixes = load_allowlist()
    paths = tree_paths() if args.all else staged_paths()
    if not args.all and not paths:
        print("host-hygiene: no staged files")
        return 0

    hits: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = path.relative_to(ROOT).as_posix()
        hits.extend(scan_text(rel, text, exact, suffixes))

    if hits:
        print("host-hygiene: scan-target / provenance breadcrumbs found:")
        for h in hits:
            print(f"  {h}")
        print(
            "Rewrite comments by identifier shape. Do not add another real host or token."
        )
        return 1
    print(f"host-hygiene: ok ({len(paths)} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
