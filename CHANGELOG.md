# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- `fix --max-days N` now sets the rotation period of flagged keys to
  `min(N, 365)` days, so a loose `N` never lengthens a period past the KMS
  default. Before, keys flagged for a slow period were reported as fixed but
  kept their period, and newly enabled keys got the 365-day default.
  `fix` rejects `--max-days` below 90, the KMS minimum.

### Changed

- Minimum Go version is 1.26 (Go 1.24 is out of support).
- AWS SDK for Go v2: core v1.47.5, config v1.33.13, service/kms v1.62.2.
- CI reads the Go version from `go.mod` and uses actions/checkout v7.0.1
  and actions/setup-go v7.0.0.

### Added

- GitHub Actions example workflow in `examples/github-actions/`.

## [0.1.0] - 2026-08-26

- First release: `audit` and `fix` commands, table and JSON output,
  `--max-days`, `--region`, `--profile`.

[Unreleased]: https://github.com/moveeeax/kms-rotation-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/moveeeax/kms-rotation-audit/releases/tag/v0.1.0
