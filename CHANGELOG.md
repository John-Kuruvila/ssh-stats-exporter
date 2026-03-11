# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses Semantic Versioning.

## [1.0.0] - 2026-03-12

### Added
- Open source release metadata via `pyproject.toml`.
- GitHub Actions for CI and tagged release builds.
- Safer runtime defaults for network exposure, CORS, and metric-cardinality limits.
- Health reporting for log access, live tailing, and `who` refreshes.

### Changed
- Default bind address is now `127.0.0.1` instead of all interfaces.
- Runtime requests now serve cached active-session data instead of invoking `who` on every API or metrics request.
- Release documentation now centers on installing a GitHub release binary as a systemd service.
