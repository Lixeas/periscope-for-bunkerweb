"""Release helper: the version (vX.Y.Z, semantic versioning) lives in src/periscope/__init__.py, the
notes in CHANGELOG.md. Nothing is tagged or published from here: the release happens in CI when the
version change is merged into main (see docs/releasing.md).

  python dev/release.py current                 # prints X.Y.Z
  python dev/release.py bump major|minor|patch  # new version + "Unreleased" notes moved under it
  python dev/release.py notes X.Y.Z             # the CHANGELOG section of X.Y.Z (release notes)
  python dev/release.py check --base X.Y.Z      # PR check against the version of the target branch
"""
import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT = ROOT / "src" / "periscope" / "__init__.py"
CHANGELOG = ROOT / "CHANGELOG.md"
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
VERSION_LINE = re.compile(r'^__version__ = "([^"]*)"$', re.MULTILINE)
HEADING = re.compile(r"^## \[([^\]]+)\][^\n]*$", re.MULTILINE)


class ReleaseError(Exception):
    pass


def parse(version: str) -> tuple[int, int, int]:
    m = SEMVER.fullmatch(version.strip().removeprefix("v"))
    if not m:
        raise ReleaseError(f"not a X.Y.Z version: {version!r}")
    return int(m[1]), int(m[2]), int(m[3])


def current(init: Path = INIT) -> str:
    m = VERSION_LINE.search(init.read_text(encoding="utf-8"))
    if not m:
        raise ReleaseError(f"no __version__ line in {init}")
    parse(m[1])
    return m[1]


def bumped(version: str, part: str) -> str:
    major, minor, patch = parse(version)
    if part == "major":
        return f"{major + 1}.0.0"
    if part == "minor":
        return f"{major}.{minor + 1}.0"
    if part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ReleaseError(f"unknown part {part!r} (major, minor or patch)")


def sections(text: str) -> dict[str, str]:
    """CHANGELOG headings `## [name]` -> body (stripped)."""
    marks = list(HEADING.finditer(text))
    return {m[1]: text[m.end():(marks[i + 1].start() if i + 1 < len(marks) else len(text))].strip()
            for i, m in enumerate(marks)}


def notes(version: str, changelog: Path = CHANGELOG) -> str:
    body = sections(changelog.read_text(encoding="utf-8")).get(version, "")
    if not body:
        raise ReleaseError(f"CHANGELOG.md has no notes under '## [{version}]'")
    return body


def bump(part: str, init: Path = INIT, changelog: Path = CHANGELOG) -> str:
    """Set the new version and turn the '## [Unreleased]' section into its notes."""
    old = current(init)
    new = bumped(old, part)
    text = changelog.read_text(encoding="utf-8")
    unreleased = sections(text).get("Unreleased", "")
    if not unreleased:
        raise ReleaseError("write the changes under '## [Unreleased]' in CHANGELOG.md first")
    text = re.sub(r"^## \[Unreleased\][^\n]*$", f"## [Unreleased]\n\n## [{new}]", text, count=1, flags=re.MULTILINE)
    changelog.write_text(text, encoding="utf-8")
    init.write_text(VERSION_LINE.sub(f'__version__ = "{new}"', init.read_text(encoding="utf-8")), encoding="utf-8")
    return new


def check(base: str, init: Path = INIT, changelog: Path = CHANGELOG) -> str:
    """Pull request check. Same version as the target branch: nothing will be released (fine for
    dependency bumps). Higher version: it will be released at merge, so its notes must exist."""
    new = current(init)
    if parse(new) < parse(base):
        raise ReleaseError(f"version {new} is lower than {base} on the target branch")
    if parse(new) == parse(base):
        return f"version unchanged ({new}): no release at merge"
    notes(new, changelog)
    allowed = {bumped(base, p) for p in ("major", "minor", "patch")}
    if new not in allowed:
        raise ReleaseError(f"{base} -> {new} skips versions (expected one of {', '.join(sorted(allowed))})")
    return f"version {base} -> {new}: v{new} will be released when this is merged"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="release.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("current")
    b = sub.add_parser("bump")
    b.add_argument("part", choices=("major", "minor", "patch"))
    n = sub.add_parser("notes")
    n.add_argument("version")
    c = sub.add_parser("check")
    c.add_argument("--base", required=True, help="version on the target branch")
    args = p.parse_args(argv)
    try:
        if args.cmd == "current":
            print(current())
        elif args.cmd == "bump":
            print(bump(args.part))
        elif args.cmd == "notes":
            print(notes(args.version.removeprefix("v")))
        else:
            print(check(args.base.removeprefix("v")))
    except ReleaseError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
