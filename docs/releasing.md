# Releasing

Periscope uses [semantic versioning](https://semver.org/): `vX.Y.Z`.

| Part | Bump when | Example |
|---|---|---|
| `X` major | a change breaks an existing setup (removed setting, incompatible agent protocol, …). While `X` is `0`, breaking changes bump `Y` | `1.4.2` → `2.0.0` |
| `Y` minor | new feature, compatible | `1.4.2` → `1.5.0` |
| `Z` patch | bug fix, security fix, dependency update | `1.4.2` → `1.4.3` |

The single source of the version is `__version__` in `src/periscope/__init__.py` (read by `pyproject.toml`, the agent and the release job). The notes live in [`CHANGELOG.md`](../CHANGELOG.md).

## In a pull request

1. Describe the change under `## [Unreleased]` in `CHANGELOG.md` (`### Added`, `### Changed`, `### Fixed`, `### Removed`, `### Security`).
2. When the pull request should produce a release, bump the version:

   ```bash
   python dev/release.py bump minor   # or major / patch
   ```

   It sets the new version and moves the `Unreleased` notes under `## [X.Y.Z]`. Commit both files.
3. The `version` CI job checks the pull request: the version is either unchanged (nothing will be released, fine for dependency updates) or one step above the target branch's, with notes in `CHANGELOG.md` and no existing tag.

**Nothing is tagged or published before the merge.**

## At the merge

On every push to `main`, once the `test` and `docker` jobs pass, the `release` job reads the version. If the tag `vX.Y.Z` does not exist yet it:

1. creates the tag `vX.Y.Z` on the merged commit and the GitHub release, with the `CHANGELOG.md` section as notes;
2. builds and pushes the container image (console and agent): `ghcr.io/lixeas/periscope-for-bunkerweb:X.Y.Z`, `:X.Y` and `:latest`.

If the version did not change, the job does nothing. Merging several pull requests that share one version releases it once, at the first merge.

Useful commands:

```bash
python dev/release.py current          # version of the working tree
python dev/release.py notes 0.2.0      # notes that will be published
python dev/release.py check --base 0.1.0
```

## Repository settings

- The release job uses the workflow's `GITHUB_TOKEN` with `contents: write` (tag, release) and `packages: write` (image). If the organization restricts workflow permissions, allow them for this repository (Settings → Actions → General → Workflow permissions).
- The container package created on the first release is private by default: make it public in the package settings if the agents should pull it without credentials.
- To require a version check before merging, mark the `version` job as a required status check in the branch protection of `main`.
