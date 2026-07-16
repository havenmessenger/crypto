#!/usr/bin/env python3
"""Guard 4 (tell-scan commit-gate): this repo is PUBLIC source-of-truth for crypto-core
(not a scrubbed export like the `client` repo), so sensitive references must be blocked
at BIRTH, not scrubbed later, because there is no export step to catch them.

Blocks, generically, on the committed tree: internal tracker IDs (DISPATCH-###, BUG-###,
SEQ-###, hyphenated or the underscore identifier form Rust code must use, e.g.
bug_sec_034), dangling internal doc-paths (.agent/...), and internal dev-infra IPs
(10.10.x.x). A maintainer or CI can additionally populate a local, gitignored
_tell_scan_denylist.py sidecar (see _tell_scan_denylist.py.example for the expected
shape) with project-specific sensitive terms: personal names, internal codenames, or
any other literal that shouldn't leak into public source. The sidecar keeps those
literals out of this published script; its absence degrades coverage to the generic
patterns above rather than breaking the guard.

Usage:
    check_tell_scan.py [file ...]     # pre-commit passes staged files
    check_tell_scan.py                # no args -> scan the whole tracked tree (CI mode)
    check_tell_scan.py --self-test    # fixture proof, see run_self_test()
"""

import re
import subprocess
import sys
from pathlib import Path

GENERIC_PATTERNS = {
    "internal tracker ID": re.compile(r"\b(DISPATCH|BUG|SEQ)[_-]?(SEC[_-]?)?\d+\b", re.IGNORECASE),
    "dangling .agent/ path": re.compile(r"\.agent/[\w\-./]+"),
    "internal dev IP": re.compile(r"10\.10\.\d{1,3}\.\d{1,3}"),
}

# A comment-scoped pattern class needs its own carve-out from a whole-text scan: some
# project-specific terms collide with legitimate code tokens (type params, const names,
# hex literals) unless restricted to `//`/`///` comment lines. The sidecar can supply such
# patterns via COMMENT_SCOPED_PATTERNS; this stays empty (and inert) when the sidecar is
# absent.
COMMENT_LINE_RE = re.compile(r"^\s*//")

try:
    from _tell_scan_denylist import SENSITIVE_PATTERNS
except ImportError:
    SENSITIVE_PATTERNS = {}

try:
    from _tell_scan_denylist import COMMENT_SCOPED_PATTERNS
except ImportError:
    COMMENT_SCOPED_PATTERNS = {}

PATTERNS = {**GENERIC_PATTERNS, **SENSITIVE_PATTERNS}

EXCLUDE_DIR_PARTS = {"target", ".git"}
EXCLUDE_FILES = {
    "scripts/check_tell_scan.py",  # this file legitimately names the pattern labels it blocks
    "scripts/_tell_scan_denylist.py",  # the sidecar itself contains the real sensitive literals
    "scripts/_tell_scan_denylist.py.example",  # the committed template — placeholder text only
    # guard 5's self-test fixtures deliberately contain synthetic tell-shaped text (that's how it
    # proves it catches every class) — the same self-referential exclusion as this file's own entry.
    "scripts/check_public_comment_hygiene.py",
    # guard 6's self-test fixtures need a realistic tracker-ID/doc-path SHAPE to prove the generic
    # patterns catch it — same self-referential exclusion as the two entries above.
    "scripts/check_commit_message_hygiene.py",
    "scripts/oss-external-pins.txt",
    "scripts/oss-public-token-manifest.txt",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def tracked_files() -> list[Path]:
    root = repo_root()
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
    ).stdout
    return [root / line for line in out.splitlines() if line]


def scan(files: list[Path]) -> int:
    root = repo_root()
    hits = []
    for f in files:
        try:
            rel = f.resolve().relative_to(root)
        except ValueError:
            continue
        if EXCLUDE_DIR_PARTS & set(rel.parts) or str(rel) in EXCLUDE_FILES:
            continue
        if not f.is_file():
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for label, pattern in PATTERNS.items():
            for m in pattern.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                hits.append(f"{rel}:{line_no}: [{label}] {m.group(0)}")

        if rel.suffix == ".rs" and COMMENT_SCOPED_PATTERNS:
            for line_no, line in enumerate(text.splitlines(), start=1):
                if not COMMENT_LINE_RE.match(line):
                    continue
                for label, pattern in COMMENT_SCOPED_PATTERNS.items():
                    for m in pattern.finditer(line):
                        hits.append(f"{rel}:{line_no}: [{label}] {m.group(0)}")

    if hits:
        print("TELL-SCAN VIOLATION — internal reference(s) found in public source:", file=sys.stderr)
        for h in hits:
            print(f"  {h}", file=sys.stderr)
        return 1
    print(f"tell-scan: OK ({len(files)} file(s) checked, zero hits)")
    return 0


# Realistic clean code this scan must NOT flag - each line exercises a specific
# false-positive risk the pattern comments above call out.
_SELF_TEST_CLEAN_FIXTURE = """
// A round-trip encode/decode proof.
fn verify_vec_roundtrip(bytes: &[u8]) -> bool { true }
// Ciphersuite pinned to 0x0001 (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).
const SUITE: u16 = 0x0001;
// RFC 3686 section 6, test vector #9.
// See https://acme-demo.org and https://iana.org for the spec.
"""

# A planted tell this scan MUST flag - one instance of each generic committed class.
_SELF_TEST_TELL_FIXTURE = """
// See BUG-123 for the original report.
// .agent/plans/example_plan.md has the design notes.
let host = "10.10.99.99";
"""


def run_self_test() -> int:
    """Proves the committed GENERIC_PATTERNS are false-positive-safe on realistic clean
    code AND still catch a planted tell of each class. Exits non-zero if either proof
    fails. This only exercises the patterns shipped in this file - sidecar-specific
    patterns (if a maintainer has populated one locally) are not covered here, since
    this file must be provable standalone on a fresh, sidecar-less clone."""
    clean_hits = [
        (label, m.group(0))
        for label, pattern in GENERIC_PATTERNS.items()
        for m in pattern.finditer(_SELF_TEST_CLEAN_FIXTURE)
    ]
    tell_hits = {
        label: list(pattern.finditer(_SELF_TEST_TELL_FIXTURE))
        for label, pattern in GENERIC_PATTERNS.items()
    }

    ok = True
    if clean_hits:
        ok = False
        print("SELF-TEST FAILED: clean fixture triggered false positive(s):", file=sys.stderr)
        for label, text in clean_hits:
            print(f"  [{label}] {text!r}", file=sys.stderr)
    else:
        print("self-test: clean fixture triggers zero hits (false-positive proof OK)")

    missing = [label for label, matches in tell_hits.items() if not matches]
    if missing:
        ok = False
        print(f"SELF-TEST FAILED: planted tell(s) NOT caught: {missing}", file=sys.stderr)
    else:
        print(f"self-test: planted tell caught for all {len(GENERIC_PATTERNS)} generic classes")

    return 0 if ok else 1


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return run_self_test()
    files = [Path(a) for a in args] if args else tracked_files()
    return scan(files)


if __name__ == "__main__":
    sys.exit(main())
