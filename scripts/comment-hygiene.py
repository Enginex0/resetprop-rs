#!/usr/bin/env python3
"""Comment-hygiene gate: the cargo-native mirror of the Casting law's
mold.comment-hygiene (banners-only). Fails on decorative box-drawing or divider
comments in tracked first-party sources, kept in lockstep with the law's Kotlin
rule. A file carrying the token comment-hygiene:allow-file is exempt.
"""
import re
import subprocess
import sys
from pathlib import Path

MARKER = re.compile(r"^(//+!?|/\*+|\*+/?)\s*")
BANNER_PUNCT = set("=-#*_~+")


def is_banner(line):
    trimmed = line.strip()
    m = MARKER.match(trimmed)
    if not m:
        return False
    body = trimmed[m.end():]
    if sum(1 for c in body if c != " ") < 4:
        return False
    return all(c == " " or c in BANNER_PUNCT or "─" <= c <= "▟" for c in body)


def is_third_party(path):
    return (
        path.startswith(".claude/")
        or "/.claude/" in path
        or path.startswith("vendor/")
        or "/vendor/" in path
    )


def tracked_sources():
    try:
        out = subprocess.run(
            ["git", "ls-files", "--", "*.kt", "*.kts", "*.java", "*.rs"],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return [p for p in out.splitlines() if p and not is_third_party(p)]


def main():
    files = tracked_sources()
    if files is None:
        print("comment-hygiene: git unavailable", file=sys.stderr)
        return 2
    violations = []
    for rel in files:
        text = Path(rel).read_text(encoding="utf-8", errors="replace")
        if "comment-hygiene:allow-file" in text:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if is_banner(line):
                violations.append(f"{rel}:{i}: {line.strip()}")
    if violations:
        print(f"Comment hygiene: {len(violations)} decorative banner comment(s).")
        print("Box-drawing and repeated divider runs are banned: write a plain comment,")
        print("or add the token comment-hygiene:allow-file to a file that needs one.")
        for v in violations:
            print(f"  {v}")
        return 1
    print(f"comment-hygiene: clean ({len(files)} files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
