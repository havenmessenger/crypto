#!/usr/bin/env python3
"""Fail on a published advisory for a crate pinned to a git revision, unless it has been read.

`cargo audit` and `cargo deny` match an advisory only against a crate from crates.io, so a crate
pinned to a git revision drops out of both and they still pass. This reads Cargo.lock and, for each
git-sourced crate, the same RustSec database by crate name.

A pinned revision has no release number to compare: a crate on main can read 0.9.0 and hold a fix
"patched in 0.9.2". So the only way past an advisory is an entry in git-pin-advisories.toml, naming
the advisory, the revision that has the fix, and why that was accepted. A new advisory stays red
until someone has read it.

Usage: check_git_pin_advisories.py [--db PATH] | --selftest
Exit 0 clean, 1 an unread advisory, 2 the check could not run.
"""

import argparse
import re
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REVISION = re.compile(r"^[0-9a-f]{40}$")
FRONT_MATTER = re.compile(r"```toml\n(.*?)\n```", re.DOTALL)


class CannotRun(Exception):
    pass


def git_crates(lock_text: str) -> set[str]:
    try:
        packages = tomllib.loads(lock_text).get("package", [])
    except tomllib.TOMLDecodeError as error:
        raise CannotRun(f"Cargo.lock does not parse: {error}") from error
    return {p["name"] for p in packages if p.get("source", "").startswith("git+")}


def read_entries(text: str) -> set[str]:
    try:
        entries = tomllib.loads(text).get("advisory", [])
    except tomllib.TOMLDecodeError as error:
        raise CannotRun(f"git-pin-advisories.toml does not parse: {error}") from error
    ids = set()
    for entry in entries:
        name = entry.get("id", "")
        if not name or not REVISION.match(entry.get("fixed_in", "")) or not entry.get("why", "").strip():
            raise CannotRun(f"git-pin-advisories.toml: {name or entry} needs id, a full fixed_in revision and why")
        ids.add(name)
    return ids


def advisories_for(db: Path, crate: str) -> list[tuple[str, set[str]]]:
    found = []
    for path in sorted((db / "crates" / crate).glob("*.md")):
        match = FRONT_MATTER.search(path.read_text())
        if match is None:
            raise CannotRun(f"{path} has no front matter")
        try:
            advisory = tomllib.loads(match.group(1))["advisory"]
        except (tomllib.TOMLDecodeError, KeyError) as error:
            raise CannotRun(f"{path} does not parse: {error}") from error
        if advisory.get("withdrawn"):
            continue
        found.append((advisory["id"], {advisory["id"], *advisory.get("aliases", [])}))
    return found


def check_db(db: Path) -> None:
    crates = db / "crates"
    if not crates.is_dir() or next(crates.glob("*/*.md"), None) is None:
        raise CannotRun(f"{db} holds no advisories")


def unread(lock_text: str, entries_text: str, db: Path) -> tuple[set[str], list[str]]:
    check_db(db)
    crates = git_crates(lock_text)
    read = read_entries(entries_text)
    return crates, [
        f"{crate}: {advisory}"
        for crate in sorted(crates)
        for advisory, names in advisories_for(db, crate)
        if not names & read
    ]


def default_db() -> Path:
    cargo = Path.home() / ".cargo"
    candidates = sorted((cargo / "advisory-dbs").glob("advisory-db-*/"), key=lambda p: p.stat().st_mtime)
    return candidates[-1] if candidates else cargo / "advisory-db"


def plant(db: Path, crate: str, advisory: str, extra: str = "") -> None:
    folder = db / "crates" / crate
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{advisory}.md").write_text(
        f'```toml\n[advisory]\nid = "{advisory}"\npackage = "{crate}"\n{extra}\n```\n\n# planted\n'
    )


GOOD_REVISION = "0" * 40
ENTRY = '[[advisory]]\nid = "{}"\nfixed_in = "{}"\nwhy = "read"\n'
LOCK = (
    'version = 4\n[[package]]\nname = "pinned"\nversion = "1.0.0"\n'
    f'source = "git+https://example.test/pinned?rev={GOOD_REVISION}#{GOOD_REVISION}"\n'
    '[[package]]\nname = "released"\nversion = "1.0.0"\n'
    'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
)


def selftest() -> int:
    def outcome(lock: str, entries: str, db: Path):
        try:
            return unread(lock, entries, db)[1]
        except CannotRun:
            return "cannot run"

    def fresh(base: Path, name: str) -> Path:
        db = base / name
        plant(db, "unrelated", "RUSTSEC-2099-0000")
        return db

    failures = []

    def expect(name, got, wanted):
        if got != wanted:
            failures.append(f"{name}: got {got!r}, wanted {wanted!r}")

    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)

        db = fresh(base, "planted")
        plant(db, "pinned", "RUSTSEC-2099-0001")
        expect("an unread advisory is reported", outcome(LOCK, "", db), ["pinned: RUSTSEC-2099-0001"])
        expect("a listed advisory passes", outcome(LOCK, ENTRY.format("RUSTSEC-2099-0001", GOOD_REVISION), db), [])
        expect(
            "another advisory's entry does not cover it",
            outcome(LOCK, ENTRY.format("RUSTSEC-2099-0002", GOOD_REVISION), db),
            ["pinned: RUSTSEC-2099-0001"],
        )
        expect(
            "an entry with a short revision is refused",
            outcome(LOCK, ENTRY.format("RUSTSEC-2099-0001", "abc123"), db),
            "cannot run",
        )

        db = fresh(base, "alias")
        plant(db, "pinned", "RUSTSEC-2099-0003", 'aliases = ["GHSA-aaaa-bbbb-cccc"]')
        expect("an entry by alias passes", outcome(LOCK, ENTRY.format("GHSA-aaaa-bbbb-cccc", GOOD_REVISION), db), [])

        db = fresh(base, "withdrawn")
        plant(db, "pinned", "RUSTSEC-2099-0004", 'withdrawn = "2099-01-01"')
        expect("a withdrawn advisory is ignored", outcome(LOCK, "", db), [])

        db = fresh(base, "released")
        plant(db, "released", "RUSTSEC-2099-0005")
        expect("a crates.io crate is left to cargo audit", outcome(LOCK, "", db), [])

        expect("a missing database cannot pass", outcome(LOCK, "", base / "absent"), "cannot run")
        (base / "empty" / "crates").mkdir(parents=True)
        expect("an empty database cannot pass", outcome(LOCK, "", base / "empty"), "cannot run")

        lock_text = (ROOT / "Cargo.lock").read_text()
        for crate in sorted(git_crates(lock_text)):
            db = fresh(base, f"real-{crate}")
            plant(db, crate, "RUSTSEC-2099-0006")
            expect(
                f"this repository's Cargo.lock reports {crate}",
                outcome(lock_text, "", db),
                [f"{crate}: RUSTSEC-2099-0006"],
            )

    for failure in failures:
        print(f"SELFTEST FAILED: {failure}", file=sys.stderr)
    if failures:
        return 1
    print("git-pin advisories selftest: OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--db", type=Path)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()
    try:
        if args.selftest:
            return selftest()
        db = args.db or default_db()
        crates, reported = unread(
            (ROOT / "Cargo.lock").read_text(), (ROOT / "git-pin-advisories.toml").read_text(), db
        )
    except (CannotRun, OSError) as error:
        print(f"git-pin advisories: could not run: {error}", file=sys.stderr)
        return 2
    if reported:
        print("GIT-PIN ADVISORY: read each and add it to git-pin-advisories.toml:", file=sys.stderr)
        for line in reported:
            print(f"  {line}", file=sys.stderr)
        return 1
    print(f"git-pin advisories: OK ({len(crates)} git-sourced crates, none with an unread advisory)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
