# Changelog

All notable changes to Periscope for BunkerWeb are documented here. Versions follow
[semantic versioning](https://semver.org/) (`vX.Y.Z`); a version is released when the change that
introduces it is merged into `main` (see [docs/releasing.md](docs/releasing.md)).

Write new entries under `[Unreleased]`; `python dev/release.py bump major|minor|patch` moves them under
the new version.

## [Unreleased]

## [0.2.1]

### Security
- Agent listener: an invalid agent report no longer echoes the exception text in the HTTP response;
  the reason is logged on the console only (code scanning: information exposure through an exception).

## [0.2.0]

### Added
- **Agent mode** for BunkerWeb instances in networks the console cannot reach (for example one network
  per customer): `periscope agent enroll|run` collects the instance locally and pushes its reports to
  a dedicated listener over **mutual TLS**, with Periscope's own certificate authority, single-use
  enrollment bundles, automatic certificate renewal and immediate revocation. See
  [docs/agent.md](docs/agent.md).
- **Tags** on instances (for example one per customer); every view can be filtered by tag, and the
  differences between instances are then computed within the tag.
- Parallel collection bounded by `PERISCOPE_MAX_PARALLEL` / `PERISCOPE_MAX_PARALLEL_PROBES`, and
  database access outside the event loop, for fleets beyond ten instances.
- Release process: version in `src/periscope/__init__.py`, this changelog, automatic tag, GitHub
  release and container image at merge.

### Removed
- **Breaking:** the static `API_TOKEN` authentication mode (full administrator access). Instances
  that used it are kept but disabled after the upgrade: edit them and enter a restricted API user.

## [0.1.0]

First version (not tagged): read-only multi-instance console for BunkerWeb polled directly through
its API (services, bans, jobs and plugins, nodes, TLS certificates), mandatory second factor,
English and French interface.
