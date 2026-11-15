#!/usr/bin/env python3
"""Print the CHANGELOG.md section for one version, without its heading: the release notes for that version's tag.

  changelog_section.py <version>     (e.g. 0.0.2 or v0.0.2)

Exits non-zero when the changelog has no section for it, so a release is never published without its notes.
"""

import re
import sys
from pathlib import Path


def section(text: str, version: str) -> str | None:
    version = version.removeprefix("v")
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if re.match(rf"^## {re.escape(version)}(\s|$)", l)), None)
    if start is None:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[start + 1 : end]).strip() + "\n"


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    changelog = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
    body = section(changelog.read_text(), sys.argv[1])
    if not body or not body.strip():
        print(f"CHANGELOG.md has no section for {sys.argv[1]}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
