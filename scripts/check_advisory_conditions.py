#!/usr/bin/env python3
"""Each advisory ignore in deny.toml ends with a machine-checked condition, and this checks it.

cargo-deny already fails an ignore whose advisory no longer matches anything (`advisory-not-detected`). What it cannot
see is the moment an ignore should be revisited although the vulnerable version is still locked: an upgrade becoming
available (a dependent taking the fixed line, a newer release of the crate itself). Each ignore's reason therefore ends
with one condition, and this script fails when that condition has come true:

    until: lock <crate> >= <version>             every locked <crate> is at least <version>
    until: release <crate> beyond <version>      <crate>'s newest stable release is newer than <version>
    until: release <crate> requires <dep> <req>  <crate>'s newest stable release requires <dep> as <req>
    until: release <crate> drops <dep>           <crate>'s newest stable release no longer depends on <dep>

It fails closed: an ignore with no condition, a condition it cannot parse, a lock it cannot read and (online) an index
it cannot reach are failures, not passes. `--offline` checks syntax and lock conditions only, so a pull request never
depends on the network; the scheduled run checks everything.

Usage: check_advisory_conditions.py [--offline] [--deny deny.toml] [--lock Cargo.lock]
       check_advisory_conditions.py --self-test
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
import tomllib
import urllib.request
from pathlib import Path

UNTIL = re.compile(r"until:\s*(.+?)\s*$")
FORMS = (
    ("lock", re.compile(r"^lock\s+([\w-]+)\s*>=\s*([\w.+-]+)$")),
    ("beyond", re.compile(r"^release\s+([\w-]+)\s+beyond\s+([\w.+-]+)$")),
    ("requires", re.compile(r"^release\s+([\w-]+)\s+requires\s+([\w-]+)\s+(\S+)$")),
    ("drops", re.compile(r"^release\s+([\w-]+)\s+drops\s+([\w-]+)$")),
)
INDEX = "https://index.crates.io"


class Unreadable(Exception):
    """A lock or an index answer that could not be read: a failure, never a pass."""


def version_key(v: str) -> tuple:
    core = v.split("+", 1)[0]
    main, _, pre = core.partition("-")
    parts = []
    for p in main.split("."):
        if not p.isdigit():
            raise Unreadable(f"not a version: {v!r}")
        parts.append(int(p))
    while len(parts) < 3:
        parts.append(0)
    # A release sorts after its own pre-releases.
    return (*parts, 0 if pre else 1, pre)


def locked_versions(lock: Path, crate: str) -> list[str]:
    try:
        data = tomllib.loads(lock.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Unreadable(f"{lock}: {e}") from None
    return [p["version"] for p in data.get("package", []) if p.get("name") == crate]


def index_path(crate: str) -> str:
    c = crate.lower()
    if len(c) <= 2:
        return f"{len(c)}/{c}"
    if len(c) == 3:
        return f"3/{c[0]}/{c}"
    return f"{c[:2]}/{c[2:4]}/{c}"


def newest_stable(crate: str, fetch) -> dict:
    try:
        lines = [json.loads(line) for line in fetch(f"{INDEX}/{index_path(crate)}").splitlines() if line.strip()]
    except Exception as e:  # noqa: BLE001 - any failure to read the index is a failure of the check
        raise Unreadable(f"index for {crate}: {e}") from None
    stable = [r for r in lines if not r.get("yanked") and "-" not in r["vers"].split("+", 1)[0]]
    if not stable:
        raise Unreadable(f"index for {crate}: no stable release")
    return max(stable, key=lambda r: version_key(r["vers"]))


def http_fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "advisory-conditions-check"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.read().decode()


def condition_of(reason: str) -> tuple[str, tuple] | None:
    m = UNTIL.search(reason)
    if not m:
        return None
    text = m.group(1)
    for kind, pattern in FORMS:
        mm = pattern.match(text)
        if mm:
            return kind, mm.groups()
    return ("unknown", (text,))


def came_true(kind: str, args: tuple, lock: Path, offline: bool, fetch) -> str | None:
    """Why the condition has come true, or None. Raises Unreadable when it cannot be decided."""
    if kind == "lock":
        crate, floor = args
        versions = locked_versions(lock, crate)
        if versions and all(version_key(v) >= version_key(floor) for v in versions):
            return f"every locked {crate} ({', '.join(versions)}) is at least {floor}"
        return None
    if offline:
        return None
    if kind == "beyond":
        crate, ceiling = args
        newest = newest_stable(crate, fetch)
        if version_key(newest["vers"]) > version_key(ceiling):
            return f"{crate} {newest['vers']} is released, newer than {ceiling}"
        return None
    if kind == "requires":
        crate, dep, req = args
        newest = newest_stable(crate, fetch)
        reqs = [d.get("req", "") for d in newest.get("deps", []) if d.get("name") == dep]
        if any(r.replace(" ", "").startswith(req.replace(" ", "")) for r in reqs):
            return f"{crate} {newest['vers']} requires {dep} {', '.join(reqs)}"
        return None
    if kind == "drops":
        crate, dep = args
        newest = newest_stable(crate, fetch)
        if not any(d.get("name") == dep for d in newest.get("deps", [])):
            return f"{crate} {newest['vers']} no longer depends on {dep}"
        return None
    raise Unreadable(f"unknown condition kind {kind}")


def check(deny: Path, lock: Path, offline: bool, fetch=http_fetch) -> list[str]:
    """Every failure, as `ID: why`."""
    try:
        config = tomllib.loads(deny.read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        return [f"{deny}: cannot be read ({e})"]
    failures = []
    for entry in config.get("advisories", {}).get("ignore", []):
        if not isinstance(entry, dict) or "reason" not in entry:
            failures.append(f"{entry}: an ignore must be a table with an id (or crate) and a reason")
            continue
        name = entry.get("id") or entry.get("crate") or "?"
        cond = condition_of(entry["reason"])
        if cond is None:
            failures.append(f"{name}: the reason has no `until:` condition")
            continue
        kind, args = cond
        if kind == "unknown":
            failures.append(f"{name}: cannot read the condition `until: {args[0]}`")
            continue
        try:
            why = came_true(kind, args, lock, offline, fetch)
        except Unreadable as e:
            failures.append(f"{name}: could not decide the condition: {e}")
            continue
        if why:
            failures.append(f"{name}: its condition has come true ({why}); revisit the ignore")
    return failures


def self_test() -> int:
    """Plants, each of which must fail; and a clean case, which must pass."""
    index = {
        "3/p/pgp": [{"vers": "0.21.1", "yanked": False, "deps": [{"name": "elliptic-curve", "req": "^0.13"}]}],
        "3/r/rsa": [{"vers": "0.9.10", "yanked": False, "deps": []}, {"vers": "0.10.0-rc.1", "yanked": False, "deps": []}],
    }

    def fake(url: str) -> str:
        key = url.removeprefix(INDEX + "/")
        if key not in index:
            raise OSError("404")
        return "\n".join(json.dumps(r) for r in index[key])

    lock_text = '[[package]]\nname = "crypto-bigint"\nversion = "0.5.5"\n'
    cases = {
        "clean": ('[advisories]\nignore = [{ id = "A", reason = "x. until: release pgp requires elliptic-curve ^0.14" },'
                  ' { id = "B", reason = "x. until: release rsa beyond 0.9.10" },'
                  ' { id = "C", reason = "x. until: lock crypto-bigint >= 0.7.6" }]\n', False),
        "no until": ('[advisories]\nignore = [{ id = "A", reason = "accepted" }]\n', True),
        "unknown form": ('[advisories]\nignore = [{ id = "A", reason = "until: someday" }]\n', True),
        "a dependent took the fixed line": ('[advisories]\nignore = [{ id = "A", reason = "until: release pgp requires elliptic-curve ^0.13" }]\n', True),
        "a newer release": ('[advisories]\nignore = [{ id = "A", reason = "until: release rsa beyond 0.9.9" }]\n', True),
        "the lock moved": ('[advisories]\nignore = [{ id = "A", reason = "until: lock crypto-bigint >= 0.5.0" }]\n', True),
        "an unreachable index": ('[advisories]\nignore = [{ id = "A", reason = "until: release nosuchcrate drops x" }]\n', True),
    }
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        lock = Path(tmp, "Cargo.lock")
        lock.write_text(lock_text)
        for name, (deny_text, must_fail) in cases.items():
            deny = Path(tmp, "deny.toml")
            deny.write_text(deny_text)
            failed = bool(check(deny, lock, offline=False, fetch=fake))
            if failed != must_fail:
                bad += 1
                print(f"self-test: {name}: expected {'a failure' if must_fail else 'a pass'}")
        lock.write_text("[[package]\nname = ")
        deny = Path(tmp, "deny.toml")
        deny.write_text('[advisories]\nignore = [{ id = "A", reason = "until: lock crypto-bigint >= 0.7.6" }]\n')
        if not check(deny, lock, offline=True, fetch=fake):
            bad += 1
            print("self-test: a malformed lock passed")
    print("self-test: ok" if not bad else f"self-test: {bad} case(s) wrong")
    return 1 if bad else 0


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        return self_test()
    offline = "--offline" in argv
    deny = Path(argv[argv.index("--deny") + 1]) if "--deny" in argv else Path("deny.toml")
    lock = Path(argv[argv.index("--lock") + 1]) if "--lock" in argv else Path("Cargo.lock")
    failures = check(deny, lock, offline)
    for f in failures:
        print(f"advisory-conditions: {f}")
    if not failures:
        print(f"advisory-conditions: ok ({'offline: syntax and lock conditions' if offline else 'all conditions'})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
