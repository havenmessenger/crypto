#!/usr/bin/env python3
"""Guard 1 (manifest-purity): fail if Cargo.lock resolves any package from outside
crates.io (a stray path/git dependency would show up here), apart from OpenMLS pinned to
one exact revision and the mls-didwebvh crate pinned to one exact revision of its repository.

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
# mls-didwebvh, the did_webvh credential's reference crate, is not released on crates.io yet. It is taken from its
# repository at an exact revision, and only that one crate may come from there.
DIDWEBVH_AT_A_REVISION = re.compile(r"^git\+https://github\.com/MarkAtwood/mimid\?rev=([0-9a-f]{40})#\1$")
FROM_DIDWEBVH_REPOSITORY = {"mls-didwebvh"}


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
    revisions = {"openmls": set(), "mls-didwebvh": set()}
    for block in text.split("[[package]]"):
        source_match = re.search(r'^source = "([^"]+)"$', block, re.MULTILINE)
        if not source_match:
            continue
        source = source_match.group(1)
        name_match = re.search(r'^name = "([^"]+)"$', block, re.MULTILINE)
        name = name_match.group(1) if name_match else "?"
        openmls = OPENMLS_AT_A_REVISION.match(source)
        didwebvh = DIDWEBVH_AT_A_REVISION.match(source) if name in FROM_DIDWEBVH_REPOSITORY else None
        if openmls:
            revisions["openmls"].add(openmls.group(1))
        elif didwebvh:
            revisions["mls-didwebvh"].add(didwebvh.group(1))
        elif not source.startswith("registry+https://github.com/rust-lang/crates.io-index"):
            bad_sources.add((name, source))
    if bad_sources:
        print(f"MANIFEST-PURITY VIOLATION: non-crates.io sources found: {bad_sources}", file=sys.stderr)
        return 1
    # One revision of each: two would link two copies, and two members of one group could then validate differently.
    several = {repo: sorted(revs) for repo, revs in revisions.items() if len(revs) > 1}
    if several:
        print(f"MANIFEST-PURITY VIOLATION: more than one revision of {several}", file=sys.stderr)
        return 1

    print(
        "manifest-purity: OK (deps resolve to crates.io, OpenMLS at one revision, or mls-didwebvh at one revision; "
        "only crypto-core is local)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
