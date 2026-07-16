#!/usr/bin/env python3
"""Guard (pre-push): blocks a push whose commit range contains a message naming internal
editorial-mechanics vocabulary - a message can be perfectly fine on the tree it describes and
still be a tell (e.g. "Voice register pass: cut emphasis-adverb tells from src/ comments" names
an internal review process even though the code change itself was unremarkable).

check_tell_scan.py (guard 4) and check_public_comment_hygiene.py (guard 5) both scan file
CONTENT. Neither looks at commit MESSAGES, which is a separate surface with the same failure
mode. This file closes that gap.

Same sidecar split as check_tell_scan.py: this file ships with only generic, project-agnostic
patterns (an internal-tracker-ID shape, an internal doc-path reference) - safe to publish
because naming the SHAPE of an internal reference doesn't leak what the reference names. The
actual sensitive vocabulary (internal thread/tool/process names) is loaded from the SAME
gitignored _tell_scan_denylist.py sidecar check_tell_scan.py already uses - see that file's
module doc for the sidecar contract. A public denylist naming these terms would itself be the
tell, so it never ships in this tracked file.

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

import os
import re
import subprocess
import sys
from pathlib import Path

GENERIC_PATTERNS = {
    "internal tracker-ID reference": re.compile(r"\bDISPATCH-\d+\b|\bBUG(?:-SEC)?-\d+\b"),
    "internal doc-path reference": re.compile(r"\.agent/[\w./-]+"),
}

try:
    from _tell_scan_denylist import SENSITIVE_PATTERNS
except ImportError:
    SENSITIVE_PATTERNS = {}

PATTERNS = {**GENERIC_PATTERNS, **SENSITIVE_PATTERNS}

ZERO_SHA = "0" * 40


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def check_message(sha: str, message: str) -> list[str]:
    hits = []
    for label, pattern in PATTERNS.items():
        m = pattern.search(message)
        if m:
            hits.append(f"{sha[:12]}: [{label}] {m.group(0)!r}")
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


def run_prepush() -> int:
    all_hits = []

    from_ref = os.environ.get("PRE_COMMIT_FROM_REF")
    to_ref = os.environ.get("PRE_COMMIT_TO_REF")
    if to_ref:
        # Running under the pre-commit framework (the real, tested invocation path).
        for sha, msg in messages_in_range(from_ref, to_ref):
            all_hits.extend(check_message(sha, msg))
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
            for sha, msg in messages_in_range(ref, local_sha):
                all_hits.extend(check_message(sha, msg))
        if not found_any:
            # Neither interface gave us anything to check (e.g. pre-commit's own brand-new-
            # branch/root-push case) - degrade to checking just the current tip rather than
            # silently passing every such push.
            for sha, msg in messages_in_range(None, "HEAD"):
                all_hits.extend(check_message(sha, msg))
    else:
        # No ref env vars and no piped stdin at all (e.g. run interactively) - check HEAD only.
        for sha, msg in messages_in_range(None, "HEAD"):
            all_hits.extend(check_message(sha, msg))

    if all_hits:
        print("COMMIT-MESSAGE HYGIENE VIOLATION — blocked push:", file=sys.stderr)
        for h in all_hits:
            print(f"  {h}", file=sys.stderr)
        print(
            "Reword the offending commit message(s) before pushing "
            "(see public-technical-voice.md's commit-message register rule).",
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
]


def run_self_test() -> int:
    """Proves the committed GENERIC_PATTERNS are false-positive-safe on realistic clean commit
    messages AND still catch a planted tell of each class. Only exercises the patterns shipped
    in this file - sidecar-specific patterns are not covered, since this file must be provable
    standalone on a fresh, sidecar-less clone (same discipline as check_tell_scan.py's
    self-test)."""
    ok = True

    clean_hits = [
        (msg, label)
        for msg in _SELF_TEST_CLEAN_FIXTURE
        for label, pattern in GENERIC_PATTERNS.items()
        if pattern.search(msg)
    ]
    if clean_hits:
        ok = False
        print("SELF-TEST FAILED: clean fixture triggered false positive(s):", file=sys.stderr)
        for msg, label in clean_hits:
            print(f"  [{label}] {msg!r}", file=sys.stderr)
    else:
        print("self-test: clean fixtures trigger zero hits (false-positive proof OK)")

    caught = {
        label: any(pattern.search(msg) for msg in _SELF_TEST_TELL_FIXTURE)
        for label, pattern in GENERIC_PATTERNS.items()
    }
    missing = [label for label, found in caught.items() if not found]
    if missing:
        ok = False
        print(f"SELF-TEST FAILED: planted tell(s) NOT caught: {missing}", file=sys.stderr)
    else:
        print(f"self-test: planted tell caught for all {len(GENERIC_PATTERNS)} generic classes")

    return 0 if ok else 1


def main() -> int:
    if "--self-test" in sys.argv:
        return run_self_test()
    if "--check" in sys.argv:
        idx = sys.argv.index("--check")
        msg = sys.argv[idx + 1] if idx + 1 < len(sys.argv) else ""
        hits = check_message("manual", msg)
        if hits:
            for h in hits:
                print(h, file=sys.stderr)
            return 1
        print("commit-message-hygiene: OK (no match)")
        return 0
    return run_prepush()


if __name__ == "__main__":
    sys.exit(main())
