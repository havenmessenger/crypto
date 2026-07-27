#!/usr/bin/env python3
"""Guard (pre-push): blocks a push whose commit range contains a message naming internal
editorial-mechanics vocabulary - a message can be perfectly fine on the tree it describes and
still be a tell (e.g. "Voice register pass: cut emphasis-adverb tells from src/ comments" names
an internal review process even though the code change itself was unremarkable).

check_tell_scan.py (guard 4) and check_public_comment_hygiene.py (guard 5) both scan file
CONTENT. Neither looks at commit MESSAGES, which is a separate surface with the same failure
mode. This file closes that gap by reusing guard 5's own pattern set rather than shipping a
second, narrower one - a message is unstructured prose just like a doc file's text, so the same
structural patterns apply directly (none of guard 5's patterns depend on a leading `//`; that
prefix only selects which LINES of a source file count as comment text to scan, not something
the patterns themselves look for).

Same sidecar split as check_tell_scan.py: the SHAPE patterns (imported from guard 5) are
generic and project-agnostic - safe to publish because naming the SHAPE of an internal
reference doesn't leak what the reference names. The actual sensitive vocabulary (internal
thread/tool/process names) is loaded from the SAME gitignored _tell_scan_denylist.py sidecar
check_tell_scan.py already uses - see that file's module doc for the sidecar contract. A public
denylist naming these terms would itself be the tell, so it never ships in this tracked file.

Enforcement point: `pre-commit install --hook-type pre-push` must be run once per clone for
this to actually fire - wiring the hook into .pre-commit-config.yaml alone does not install it
(verified: a fresh clone of this repo has no installed git hooks at all, only the framework's
own `.sample` stubs).

Invocation reality (found by testing the installed hook end-to-end, not assumed): when run
under the `pre-commit` framework, `pre-commit`'s own `hook-impl` consumes git's raw pre-push
stdin protocol itself (to compute which files changed, for other hooks' file-filtering) and does
NOT forward it to this script's stdin - a naive stdin-reading implementation silently sees zero
lines and passes every push unchecked. The framework instead exposes the computed range as the
`PRE_COMMIT_FROM_REF`/`PRE_COMMIT_TO_REF` environment variables (set whenever the push extends
existing remote history) - that is the real interface this script uses when run this way. Raw
stdin is kept as a fallback only for the case this script is wired as a plain git hook directly
(bypassing pre-commit), which this repo does not currently do; and a HEAD-only check is the last
resort when neither interface has anything (e.g. a brand-new branch/root push, which sets
neither ref env var and gives no stdin either).

Usage:
    check_commit_message_hygiene.py            # pre-push hook mode (env vars, or stdin/HEAD fallback)
    check_commit_message_hygiene.py --check MSG # check one message string directly (manual use)
    check_commit_message_hygiene.py --self-test # fixture proof, see run_self_test()
"""

import re
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_public_comment_hygiene import (  # noqa: E402
    GENERIC_PATTERNS as SHARED_COMMENT_PATTERNS,
    GIT_SHA_RE,
    LETTER_DIGIT_TAG_RE,
    load_lines,
)

# Guard 5 deliberately has NO tracker-ID pattern: `BUG-SEC-###` is legitimately public in
# COMMENTS (SECURITY-FIXES.md is the disclosure record those citations resolve against), so a
# comment citing one is not a tell. A commit MESSAGE has no equivalent legitimate-citation
# convention - nothing resolves a `DISPATCH-###`/`BUG-###` cited in a message the way
# SECURITY-FIXES.md resolves one cited in code - so this class stays local to THIS script
# rather than living in the shared, comment-scoped set.
GENERIC_PATTERNS = {
    "internal tracker-ID reference": re.compile(r"\bDISPATCH-\d+\b|\bBUG(?:-SEC)?-\d+\b"),
}

try:
    from _tell_scan_denylist import SENSITIVE_PATTERNS
except ImportError:
    SENSITIVE_PATTERNS = {}

PATTERNS = {**SHARED_COMMENT_PATTERNS, **GENERIC_PATTERNS, **SENSITIVE_PATTERNS}

ZERO_SHA = "0" * 40


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def check_message(
    sha: str, message: str, external_pins: set[str], public_tokens: set[str]
) -> list[str]:
    hits = []
    for label, pattern in PATTERNS.items():
        m = pattern.search(message)
        if m:
            hits.append(f"{sha[:12]}: [{label}] {m.group(0)!r}")
    for m in GIT_SHA_RE.finditer(message):
        h = m.group("hash1") or m.group("hash2")
        if h and h.lower() not in external_pins:
            hits.append(f"{sha[:12]}: [git-SHA-in-prose] {h!r}")
    for m in LETTER_DIGIT_TAG_RE.finditer(message):
        tok = m.group(1)
        if tok not in public_tokens:
            hits.append(f"{sha[:12]}: [letter-digit finding-tag] {tok!r}")
    return hits


def messages_in_range(from_ref: str | None, to_ref: str) -> list[tuple[str, str]]:
    root = repo_root()
    if from_ref is None:
        # No remote-side reference available - check just the tip commit rather than walking its
        # entire ancestry (which may predate this guard and isn't what's newly being pushed).
        args = ["git", "log", "-1", "--format=%H%x00%B%x03", to_ref]
    else:
        args = ["git", "log", "--format=%H%x00%B%x03", f"{from_ref}..{to_ref}"]
    out = subprocess.run(args, cwd=root, capture_output=True, text=True, check=True).stdout
    result = []
    for chunk in out.split("\x03"):
        if not chunk.strip():
            continue
        sha, _, msg = chunk.partition("\x00")
        result.append((sha.strip(), msg))
    return result


# Same escape shape as the monorepo's [no-doc-update — reason: ...] convention (matched
# case-insensitively, same as that one) - a rare, explicit, reasoned override rather than a
# silent skip. Checked per-message: one legitimately-escaped commit in a pushed range does not
# suppress the check for its siblings.
_ESCAPE_PREFIX = "[hygiene-reviewed"


def _load_allowlists() -> tuple[set[str], set[str]]:
    external_pins = {h.lower() for h in load_lines("oss-external-pins.txt")}
    public_tokens = load_lines("oss-public-token-manifest.txt")
    return external_pins, public_tokens


def run_prepush() -> int:
    all_hits = []
    external_pins, public_tokens = _load_allowlists()

    def check_range(from_ref: str | None, to_ref: str) -> None:
        for sha, msg in messages_in_range(from_ref, to_ref):
            if _ESCAPE_PREFIX in msg.lower():
                continue
            all_hits.extend(check_message(sha, msg, external_pins, public_tokens))

    from_ref = os.environ.get("PRE_COMMIT_FROM_REF")
    to_ref = os.environ.get("PRE_COMMIT_TO_REF")
    if to_ref:
        # Running under the pre-commit framework (the real, tested invocation path).
        check_range(from_ref, to_ref)
    elif not sys.stdin.isatty():
        # Fallback: invoked as a plain git pre-push hook, reading git's raw protocol directly.
        found_any = False
        for line in sys.stdin:
            parts = line.split()
            if len(parts) != 4:
                continue
            found_any = True
            _local_ref, local_sha, _remote_ref, remote_sha = parts
            if local_sha == ZERO_SHA:
                continue  # a branch/tag delete - nothing to check
            ref = None if remote_sha == ZERO_SHA else remote_sha
            check_range(ref, local_sha)
        if not found_any:
            # Neither interface gave us anything to check (e.g. pre-commit's own brand-new-
            # branch/root-push case) - degrade to checking just the current tip rather than
            # silently passing every such push.
            check_range(None, "HEAD")
    else:
        # No ref env vars and no piped stdin at all (e.g. run interactively) - check HEAD only.
        check_range(None, "HEAD")

    if all_hits:
        print("COMMIT-MESSAGE HYGIENE VIOLATION — blocked push:", file=sys.stderr)
        for h in all_hits:
            print(f"  {h}", file=sys.stderr)
        print(
            "Reword the offending commit message(s) before pushing (see "
            "public-technical-voice.md's commit-message register rule), or if this is a "
            "legitimate exception, add '[hygiene-reviewed — reason: ...]' to the message.",
            file=sys.stderr,
        )
        return 1
    print("commit-message-hygiene: OK")
    return 0


# Realistic clean messages this scan must NOT flag.
_SELF_TEST_CLEAN_FIXTURE = [
    "Tidy comment wording in src/",
    "Fix dead client-repo link, add a runnable OpenPGP example",
    "Bound every unbounded-input footgun in the public API surface",
]

# A planted tell this scan MUST flag - one instance of each generic committed class.
_SELF_TEST_TELL_FIXTURE = [
    "Fold in DISPATCH-190 packaging follow-through",
    "Reference .agent/plans/some_internal_plan.md in the changelog",
    "this module was extracted from an earlier version before the split",
    "this crate was consumed as a submodule of the monorepo until it shipped standalone",
    "Part-B U1 raised a question about this default; TASK-3 tracked the fix",
    "since 2026-06-16 (#2b) this has been A<->B-verified against the reference implementation",
    "52b: switched this module to a per-file thiserror enum",
    "see the rust/ crate for the FRB-bound wrapper",
    "closed anti-abuse and mail-delivery infrastructure handle the rest of the pipeline",
    "this example points a curious reader at the wire format in detail",
]


def run_self_test() -> int:
    """Proves the shape-only patterns (guard 5's shared set + this file's own local
    tracker-ID class) are false-positive-safe on realistic clean commit messages AND still
    catch a planted tell of each class. Sidecar-specific patterns and the two allowlist-checked
    classes (which need external_pins/public_tokens state) are not covered here, since this
    file must be provable standalone on a fresh, sidecar-less clone (same discipline as
    check_tell_scan.py's self-test)."""
    ok = True
    shape_patterns = {**SHARED_COMMENT_PATTERNS, **GENERIC_PATTERNS}

    clean_hits = [
        (msg, label)
        for msg in _SELF_TEST_CLEAN_FIXTURE
        for label, pattern in shape_patterns.items()
        if pattern.search(msg)
    ]
    if clean_hits:
        ok = False
        print("SELF-TEST FAILED: clean fixture triggered false positive(s):", file=sys.stderr)
        for msg, label in clean_hits:
            print(f"  [{label}] {msg!r}", file=sys.stderr)
    else:
        print("self-test: clean fixtures trigger zero hits (false-positive proof OK)")

    caught_labels = {
        label
        for msg in _SELF_TEST_TELL_FIXTURE
        for label, pattern in shape_patterns.items()
        if pattern.search(msg)
    }
    missing = set(shape_patterns) - caught_labels
    if missing:
        ok = False
        print(f"SELF-TEST FAILED: planted tell(s) NOT caught: {sorted(missing)}", file=sys.stderr)
    else:
        print(f"self-test: planted tell caught for all {len(shape_patterns)} shape classes")

    escaped_hits = check_message("test", f"{_ESCAPE_PREFIX} — reason: test DISPATCH-1]", set(), set())
    # The escape token itself is only honored by run_prepush's per-message skip, not by
    # check_message (which has no escape logic - the skip has to happen before check_message is
    # ever called, so a message CAN be both escaped and still contain a real tracker-ID token
    # without check_message being fooled into silence). Confirm that division of responsibility:
    # check_message alone still reports the DISPATCH-1 token even inside an escaped-looking string.
    if not escaped_hits:
        ok = False
        print(
            "SELF-TEST FAILED: check_message must NOT itself honor the escape token - "
            "only run_prepush's per-message skip should",
            file=sys.stderr,
        )
    else:
        print("self-test: escape token is a run_prepush-level skip, not a check_message blind spot")

    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv:
        return run_self_test()
    if "--check" in sys.argv:
        idx = sys.argv.index("--check")
        msg = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else ""
        external_pins, public_tokens = _load_allowlists()
        hits = check_message("manual", msg, external_pins, public_tokens)
        if hits:
            for h in hits:
                print(h, file=sys.stderr)
            return 1
        print("commit-message-hygiene: OK (no match)")
        return 0
    return run_prepush()


if __name__ == "__main__":
    sys.exit(main())
