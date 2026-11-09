#!/usr/bin/env python3
"""Guard 1 (manifest-purity): fail if Cargo.lock resolves any package from outside
crates.io (a stray path/git dependency would show up here), apart from OpenMLS pinned to
one exact revision.

This crate is meant to build from a bare checkout with no path dependencies and no git
dependency but that one. A dependency that resolves fine inside a larger workspace can silently fail (or
worse, secretly succeed by pulling in code that only exists in that larger context)
from a bare checkout of just this repo. This guard catches that at the manifest level
in milliseconds, before the slower standalone-build CI job even runs.
"""

import re
import sys
from pathlib import Path

CRATES_IO_SOURCE = 'source = "registry+https://github.com/rust-lang/crates.io-index"'
NAME_RE = re.compile(r'^name = "([^"]+)"$')
# OpenMLS tracks its main branch, always at an exact revision, so a build is reproducible.
OPENMLS_AT_A_REVISION = re.compile(r"^git\+https://github\.com/openmls/openmls\?rev=([0-9a-f]{40})#\1$")


def local_package_names(lockfile: str) -> set[str]:
    """Packages with no `source` line at all are local path packages (this crate itself)."""
    names = set()
    for block in lockfile.split("[[package]]"):
        name_match = NAME_RE.search(block, re.MULTILINE) or re.search(
            r'^name = "([^"]+)"$', block, re.MULTILINE
        )
        if name_match and "source = " not in block:
            names.add(name_match.group(1))
    return names


def main() -> int:
    lockfile_path = Path(__file__).resolve().parent.parent / "Cargo.lock"
    if not lockfile_path.exists():
        print(f"error: {lockfile_path} not found", file=sys.stderr)
        return 2
    text = lockfile_path.read_text()

    expected_local = {"crypto-core"}
    actual_local = local_package_names(text)
    unexpected = actual_local - expected_local
    if unexpected:
        print(
            f"MANIFEST-PURITY VIOLATION: unexpected local/path package(s) with no "
            f"registry source: {sorted(unexpected)}. crypto-core must resolve every "
            f"dependency from crates.io, no path=/git= dependencies.",
            file=sys.stderr,
        )
        return 1

    bad_sources = set()
    for block in text.split("[[package]]"):
        source_match = re.search(r'^source = "([^"]+)"$', block, re.MULTILINE)
        if (
            source_match
            and not source_match.group(1).startswith("registry+https://github.com/rust-lang/crates.io-index")
            and not OPENMLS_AT_A_REVISION.match(source_match.group(1))
        ):
            name_match = re.search(r'^name = "([^"]+)"$', block, re.MULTILINE)
            bad_sources.add((name_match.group(1) if name_match else "?", source_match.group(1)))
    if bad_sources:
        print(f"MANIFEST-PURITY VIOLATION: non-crates.io sources found: {bad_sources}", file=sys.stderr)
        return 1

    print("manifest-purity: OK (deps resolve to crates.io or OpenMLS at a revision; only crypto-core is local)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
