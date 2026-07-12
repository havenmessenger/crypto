#!/usr/bin/env python3
"""Guard 3 (one-way-dependency): crypto-core is a leaf library. It must never import
app-specific or FRB-binding-crate types — the dependency arrow only ever points the
consuming binding crate -> crypto-core, never the reverse.

Fails if `src/**/*.rs` has actual CODE (not doc-comment prose) referencing
`flutter_rust_bridge`, a binding-crate name (loaded from the local
_tell_scan_denylist.py sidecar if present — see check_tell_scan.py's docstring for
why that lives in a gitignored sidecar rather than this published script), or
an `#[frb(...)]` attribute. This crate is a leaf library with zero
flutter_rust_bridge coupling by design; this is mostly a regression tripwire that
should never fire, catching the "a leaf reached up into a binding-layer type" bug
class if it ever does.

Deliberately comment-aware (unlike a bare grep): crypto-core's own doc-comments
legitimately SAY "this module is outside crate::api, so flutter_rust_bridge never
scans it" / "the Dart-EXPOSED struct stays in the binding crate" as architectural
documentation of its OWN FRB-freedom — a naive scan would false-positive on the
exact sentences proving the guard's invariant holds. Only lines that are not
comment-only are checked (comment lines start with `//`, `///`, or `//!` after
trimming leading whitespace).
"""

import re
import sys
from pathlib import Path

try:
    from _tell_scan_denylist import ONE_WAY_DEP_SENSITIVE_PATTERN
except ImportError:
    ONE_WAY_DEP_SENSITIVE_PATTERN = None

FORBIDDEN_PATTERNS = [
    re.compile(r"\bflutter_rust_bridge\b"),
    re.compile(r"#\[frb\b"),
]
if ONE_WAY_DEP_SENSITIVE_PATTERN is not None:
    FORBIDDEN_PATTERNS.append(ONE_WAY_DEP_SENSITIVE_PATTERN)


def is_comment_only(line: str) -> bool:
    return line.strip().startswith("//")


def code_part(line: str) -> str:
    """Strip a trailing `// comment` from a code line before matching, so an explanatory
    comment on a real code line (e.g. `#[allow(...)] // safe: this lint fires on an
    intentional pattern, see the module doc`) doesn't false-positive. Not string-literal-aware
    (a `//` inside a string would truncate
    early) -- acceptable here because Rust source rarely embeds `//` in a string literal on
    the same line as one of the forbidden patterns, and under-matching in that rare case is
    strictly safer than the guard crying wolf on legitimate documentation."""
    idx = line.find("//")
    return line if idx == -1 else line[:idx]


def main() -> int:
    src_dir = Path(__file__).resolve().parent.parent / "src"
    hits = []
    for f in src_dir.rglob("*.rs"):
        for line_no, line in enumerate(f.read_text(errors="replace").splitlines(), start=1):
            if is_comment_only(line):
                continue
            line = code_part(line)
            for pattern in FORBIDDEN_PATTERNS:
                if pattern.search(line):
                    hits.append(f"{f}:{line_no}: {line.strip()}")

    if hits:
        print("ONE-WAY-DEPENDENCY VIOLATION: crypto-core has CODE (not comment) referencing app/binding-crate symbols:", file=sys.stderr)
        for h in hits:
            print(f"  {h}", file=sys.stderr)
        return 1

    print(f"one-way-dep: OK (no flutter_rust_bridge / binding-crate / #[frb] CODE references in src/; "
          f"binding-crate-name check {'active' if ONE_WAY_DEP_SENSITIVE_PATTERN is not None else 'INACTIVE (sidecar absent)'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
