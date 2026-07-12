#!/usr/bin/env python3
"""Guard 5 (public-comment-hygiene commit-gate): this repo is PUBLIC source-of-truth, so a
comment/doc must describe what the code IS, what it DOES, and WHY (with spec references) - never
HOW it came to be. This is structurally distinct from guard 4 (check_tell_scan.py): that guard
blocks literal internal vocabulary (a permanently one-shape-behind blocklist); this guard blocks
tell SHAPES generically, so it stays effective even for vocabulary nobody has typed yet, and can
ship with ZERO internal literal codenames (a structural rule doesn't need to name what it forbids
in Haven-specific terms - "a bare git-SHA cited in prose" is a shape any project can define).

Scope: comment/doc TEXT only, never code/identifiers/data. For `.rs` files this means lines whose
stripped form starts with `//` (covers `//`, `///`, `//!`) - block comments (`/* */`) are out of
scope for this version (an empty-corpus check confirmed neither this repo nor its sibling uses
them for narrative prose). `.md` files are scanned in full (a doc file IS prose). `.toml` files are
restricted to `#`-prefixed lines. Restricting to comment syntax is what keeps this guard from ever
touching a byte array, a hex test-vector constant, or a string literal - those are DATA, and this
guard's whole design premise is that it never needs to reason about data, only about what a human
wrote to explain the data.

Two allowlist data files (not code - addable without a code change):
  - oss-external-pins.txt: commit hashes of EXTERNAL repos this project legitimately cites
    (e.g. a pinned upstream fork commit for a reproducibility cross-check). One hash per line.
  - oss-public-token-manifest.txt: letter+digit tokens that are legitimate self-resolving public
    identifiers in THIS project (conformance-row IDs defined in a public doc, or established
    external technical vocabulary) rather than an internal review/finding tag. One token per line.

Usage:
    check_public_comment_hygiene.py [file ...]     # pre-commit passes staged files
    check_public_comment_hygiene.py                # no args -> scan the whole tracked tree (CI)
    check_public_comment_hygiene.py --self-test     # fixture proof, see run_self_test()
"""

import re
import subprocess
import sys
from pathlib import Path

COMMENT_LINE_RE = re.compile(r"^\s*//")
TOML_COMMENT_LINE_RE = re.compile(r"^\s*#")

# Structural, shape-only rules. Every pattern here is generic English/punctuation-shape
# vocabulary - none names a Haven-specific proper noun, script, person, or codename. That's the
# whole point: this file ships publicly and must remain provable standalone on a fresh clone.
GENERIC_PATTERNS = {
    "date-as-cadence status stamp": re.compile(
        r"\bsince 20\d\d-\d\d-\d\d \(#\d+[a-z]?\)|\bA[↔<]-?>?B[- ]?verified\b"
    ),
    "digit-leading finding-tag": re.compile(r"\b\d{1,3}[a-z]:\s"),
    # `Part-[A-Z] <letter><digit>`, `TASK-N`, and a DOTTED sub-phase number (P6.1) are
    # unambiguous internal-process tag shapes with no observed legitimate collision in this
    # codebase (verified empirically before shipping - a bare `P6` IS a legitimate conformance
    # ID here, which is exactly why this only matches the DOTTED form). Deliberately EXCLUDES a
    # bare `TIER-\d`/`Phase \d`: this codebase's own legitimate "Tier-0/Tier-1" custody-taxonomy
    # and "Generation (Phase 1)/Acceptance (Phase 2)" expository labels collide with those shapes
    # (confirmed by grep against the current tree) - a known, accepted recall tradeoff; Layer 4
    # (an independent-model pre-publish pass) is the backstop for a novel tag shape like these.
    "task-tag shape": re.compile(r"Part-[A-Z]\s+[A-Za-z]\d|\bTASK-\d|\bP\d+\.\d+\b"),
    # Path-SHAPE only - no literal internal script/doc name (that would itself be the leak this
    # guard exists to prevent). Any consumer's internal doc-root, tooling directory, or
    # `-architecture.md` doc-naming convention is caught by shape, without spelling it.
    "internal doc/script path shape": re.compile(
        r"\.agent/[\w\-./]+|\bscripts/oss/\S+|\S+[-_]architecture\.md\b|\bsteering/\S+"
    ),
    # Path/extension-SHAPE only - no literal private symbol name (a module/function name is a
    # proper noun, not a shape; those stay in a maintainer's local, gitignored denylist).
    "private app-client path shape": re.compile(r"\.dart\b|crate::api::|rust/src/api|\brust/"),
    # "extracted" alone is ambiguous: this codebase's own legitimate crypto/protocol sense
    # ("the key material extracted from the header") reads identically to a provenance narration
    # ("this module extracted from the private repo") until the OBJECT of "from" disambiguates -
    # confirmed by testing this guard against realistic clean prose before shipping it, not
    # assumed. So "extracted from" only fires when followed by a provenance-shaped object
    # (private/original/earlier/prior/monorepo); "extracted verbatim"/"extracted <date>" are
    # unambiguous on their own. `\b` doesn't break on `_`, so identifier families like
    # `foo_extracted_bar` are never touched either. Deliberately EXCLUDES a bare `formerly`: this
    # codebase's own legitimate "(formerly active) member" describes protocol STATE, not history.
    "extraction/provenance narration": re.compile(
        r"\bextracted from (?:the |an? )?(?:private|original|earlier|prior|monorepo)\b"
        r"|\bextracted (?:verbatim|\d{4}-\d{2}-\d{2})\b"
        r"|\bpre-split\b|\bpost-split\b|\bcarved out\b|\brelocated \(?verbatim\)?\b"
        r"|\ban? (?:earlier|prior) version\b|\bused to be\b|\bbefore the split\b"
        r"|\bwhen this lived in\b",
        re.IGNORECASE,
    ),
    # KEEP (must not match): the positive "standalone / no networking / no submodules" claim -
    # verified this doesn't collide (the claim is always plural "submodules", this pattern is
    # singular only).
    "monorepo/submodule/parent-app framing": re.compile(
        r"\bmonorepo\b|\bsubmodule\b|\bconsumed as a submodule\b|\bre-extraction\b"
        r"|\bshipping app\b|\bthe app ships\b",
        re.IGNORECASE,
    ),
    "closed-infra enumeration": re.compile(
        r"\banti-abuse\b|\bmail-delivery infrastructure\b", re.IGNORECASE
    ),
    "audience-targeting phrasing": re.compile(
        r"reader at\b|points (?:a|the) .{0,20} reader\b", re.IGNORECASE
    ),
}

# These two classes need a per-match VALUE check against an allowlist file, not a bare
# regex-hit-is-a-violation rule - see EXTERNAL_PINS / PUBLIC_TOKENS below.
GIT_SHA_RE = re.compile(
    r"\b(?:commit|checkout|pinned to)\b[^\n]{0,25}?\b(?P<hash1>[0-9a-f]{7,40})\b"
    r"|\b(?:main|HEAD) `(?P<hash2>[0-9a-f]{7,40})`",
    re.IGNORECASE,
)
# Negative lookbehind for a hyphen excludes the tail of a larger compound public ID
# (e.g. `INV-MLS-001a`'s `001a`) from ever reaching this regex in the first place - a belt+
# suspenders complement to the manifest allowlist below (the manifest lists exact whole tokens;
# this stops a substring match on a hyphenated ID from being evaluated at all).
LETTER_DIGIT_TAG_RE = re.compile(r"(?<!-)\b([A-Z]\d+[a-z]?)\b")

EXCLUDE_DIR_PARTS = {"target", ".git"}
EXCLUDE_FILES = {
    "scripts/check_public_comment_hygiene.py",
    "scripts/oss-external-pins.txt",
    "scripts/oss-public-token-manifest.txt",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_lines(name: str) -> set[str]:
    p = repo_root() / "scripts" / name
    if not p.exists():
        return set()
    out = set()
    for line in p.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def tracked_files() -> list[Path]:
    root = repo_root()
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
    ).stdout
    return [root / line for line in out.splitlines() if line]


def comment_text_lines(rel: Path, text: str) -> list[tuple[int, str]]:
    """Returns (line_no, line_text) pairs restricted to comment/doc TEXT for this file type."""
    if rel.suffix == ".md":
        return list(enumerate(text.splitlines(), start=1))
    if rel.suffix == ".rs":
        return [
            (i, line) for i, line in enumerate(text.splitlines(), start=1) if COMMENT_LINE_RE.match(line)
        ]
    if rel.suffix == ".toml":
        return [
            (i, line)
            for i, line in enumerate(text.splitlines(), start=1)
            if TOML_COMMENT_LINE_RE.match(line)
        ]
    return []


def scan_lines(lines: list[tuple[int, str]], external_pins: set[str], public_tokens: set[str]):
    hits = []
    for line_no, line in lines:
        for label, pattern in GENERIC_PATTERNS.items():
            for m in pattern.finditer(line):
                hits.append((line_no, label, m.group(0)))
        for m in GIT_SHA_RE.finditer(line):
            h = m.group("hash1") or m.group("hash2")
            if h and h.lower() not in external_pins:
                hits.append((line_no, "git-SHA-in-prose", h))
        for m in LETTER_DIGIT_TAG_RE.finditer(line):
            tok = m.group(1)
            if tok not in public_tokens:
                hits.append((line_no, "letter-digit finding-tag", tok))
    return hits


def scan(files: list[Path]) -> int:
    root = repo_root()
    external_pins = {h.lower() for h in load_lines("oss-external-pins.txt")}
    public_tokens = load_lines("oss-public-token-manifest.txt")
    all_hits = []
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
        lines = comment_text_lines(rel, text)
        for line_no, label, snippet in scan_lines(lines, external_pins, public_tokens):
            all_hits.append(f"{rel}:{line_no}: [{label}] {snippet}")

    if all_hits:
        print(
            "PUBLIC-COMMENT-HYGIENE VIOLATION — a comment/doc narrates HOW the code came to be, "
            "not what it IS/DOES/WHY:",
            file=sys.stderr,
        )
        for h in all_hits:
            print(f"  {h}", file=sys.stderr)
        return 1
    print(f"public-comment-hygiene: OK ({len(files)} file(s) checked, zero hits)")
    return 0


# Realistic clean code this scan must NOT flag - each line is a documented false-positive risk
# found by testing this guard against the actual repo before shipping it (see the DEV plan this
# guard was built from). A KEEP fixture proving the guard doesn't break real content.
_SELF_TEST_KEEP_FIXTURE = """
/// conformance C1/C2/C3: this codec round-trips every content-09 message kind.
/// See `mimi_core::gate` conformance K3/K4 for the acceptance-side half of this contract.
/// mimi-core has no compile-time link to the WASM-target build, so this constant is kept in
/// lockstep with a documented value-match + a test, not a compile-time dependency.
/// `INV-MLS-001a` (successor of INV-MLS-001) permanently disallows external commits.
/// The pinned nightly toolchain is 2026-03-28 (see rust-toolchain.toml).
/// `draft-ietf-mls-pq-ciphersuites-05` (fetched 2026-07-03, datatracker) names TBD1.
/// Wire format: `[role u32=00000002]`, ASCII printable range is `0x20..=0x7e`.
/// Example URI: `mimi://a.example/d/3b52249d-68f9-45ce-8bf5-c799f3cad7ec/0003`.
/// Tier-0: wipe the retained passphrase copy on drop.
/// Generation (Phase 1): what Haven produces. Acceptance (Phase 2): what Haven accepts.
/// The key material extracted from the header is validated against the signature.
/// After Remove, the (formerly active) member is rejected by every subsequent commit.
/// Apache-2.0, no submodules, no services needed to build and run the tests.
/// Cross-checked against `openmls/openmls`, commit `f3040aaac59b8c72a9d4e0b7970eefcde9c1dd11`
/// (an allowlisted external reproducibility pin, not a self-repo SHA).
"""

# A planted tell this scan MUST flag - one instance of each structural class.
_SELF_TEST_TELL_FIXTURE = """
// since 2026-06-16 (#2b) this has been A<->B-verified against the reference implementation.
// 52b: switched this module to a per-file thiserror enum.
// Part-B U1 raised a question about this default; TASK-3 tracked the fix; see also P6.1.
// design notes live at .agent/plans/example_plan.md and scripts/oss/export_client.sh; the
// naming convention matches oss-monorepo-architecture.md and steering/example.md.
// see the rust/ crate for the FRB-bound wrapper; crate::api::example mirrors this.
// this module was extracted from an earlier version before the split.
// this crate was consumed as a submodule of the monorepo until it shipped standalone.
// closed anti-abuse and mail-delivery infrastructure handle the rest of the pipeline.
// this example points a curious reader at the wire format in detail.
// see commit a50226cafeed1234567890abcdef1234567890ab for the original derivation.
// D11c: this was a review-batch finding tag shape (letter-digit, no manifest entry).
"""


def run_self_test() -> int:
    """Proves GENERIC_PATTERNS + the two value-checked classes are false-positive-safe on
    realistic clean code (using the KEEP fixture's own public IDs/pins as an inline allowlist,
    since this file must be provable standalone on a fresh, sidecar-less clone) AND still catch a
    planted tell of every class on the empty-allowlist case."""
    keep_pins = {"f3040aaac59b8c72a9d4e0b7970eefcde9c1dd11"}
    keep_tokens = {"C1", "C2", "C3", "K3", "K4"}

    keep_lines = list(enumerate(_SELF_TEST_KEEP_FIXTURE.splitlines(), start=1))
    tell_lines = list(enumerate(_SELF_TEST_TELL_FIXTURE.splitlines(), start=1))

    keep_hits = scan_lines(keep_lines, keep_pins, keep_tokens)
    tell_hits = scan_lines(tell_lines, set(), set())

    ok = True
    if keep_hits:
        ok = False
        print("SELF-TEST FAILED: KEEP fixture triggered false positive(s):", file=sys.stderr)
        for line_no, label, snippet in keep_hits:
            print(f"  line {line_no}: [{label}] {snippet!r}", file=sys.stderr)
    else:
        print("self-test: KEEP fixture triggers zero hits (false-positive proof OK)")

    caught_labels = {label for _, label, _ in tell_hits}
    all_labels = set(GENERIC_PATTERNS) | {"git-SHA-in-prose", "letter-digit finding-tag"}
    missing = all_labels - caught_labels
    if missing:
        ok = False
        print(f"SELF-TEST FAILED: planted tell(s) NOT caught: {sorted(missing)}", file=sys.stderr)
    else:
        print(f"self-test: planted tell caught for all {len(all_labels)} structural classes")

    return 0 if ok else 1


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return run_self_test()
    files = [Path(a) for a in args] if args else tracked_files()
    return scan(files)


if __name__ == "__main__":
    sys.exit(main())
