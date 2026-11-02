import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("release", Path(__file__).parent.parent / "dev" / "release.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

CHANGELOG = """# Changelog

## [Unreleased]

### Added
- something new

## [1.2.3]

### Fixed
- a bug
"""


@pytest.fixture
def repo(tmp_path):
    init, log = tmp_path / "__init__.py", tmp_path / "CHANGELOG.md"
    init.write_text('# comment\n__version__ = "1.2.3"\n')
    log.write_text(CHANGELOG)
    return init, log


def test_repository_version_is_semver_with_notes():
    v = release.current()
    release.parse(v)
    assert release.notes(v)
    import periscope
    assert periscope.__version__ == v


@pytest.mark.parametrize("bad", ["1.2", "1.2.3.4", "01.2.3", "1.2.x", "", "1.2.3-rc1"])
def test_parse_rejects_non_semver(bad):
    with pytest.raises(release.ReleaseError):
        release.parse(bad)


def test_bumped():
    assert [release.bumped("1.2.3", p) for p in ("major", "minor", "patch")] == ["2.0.0", "1.3.0", "1.2.4"]
    assert release.parse("v1.2.3") == (1, 2, 3)


def test_bump_moves_unreleased_notes(repo):
    init, log = repo
    assert release.bump("minor", init, log) == "1.3.0"
    assert release.current(init) == "1.3.0" and init.read_text().startswith("# comment\n")
    assert release.notes("1.3.0", log) == "### Added\n- something new"
    assert release.notes("1.2.3", log) == "### Fixed\n- a bug"
    assert release.sections(log.read_text())["Unreleased"] == ""
    with pytest.raises(release.ReleaseError, match="Unreleased"):  # nothing to release
        release.bump("patch", init, log)


def test_check(repo):
    init, log = repo
    assert "no release" in release.check("1.2.3", init, log)
    with pytest.raises(release.ReleaseError, match="lower"):
        release.check("1.3.0", init, log)
    with pytest.raises(release.ReleaseError, match="skips"):
        release.check("1.0.0", init, log)
    init.write_text('__version__ = "1.3.0"\n')
    with pytest.raises(release.ReleaseError, match="no notes"):
        release.check("1.2.3", init, log)
    log.write_text(CHANGELOG.replace("## [Unreleased]", "## [Unreleased]\n\n## [1.3.0]\n\n- x"))
    assert "will be released" in release.check("1.2.3", init, log)


def test_cli(capsys):
    assert release.main(["current"]) == 0 and capsys.readouterr().out.strip() == release.current()
    assert release.main(["notes", "9.9.9"]) == 1 and "no notes" in capsys.readouterr().err
