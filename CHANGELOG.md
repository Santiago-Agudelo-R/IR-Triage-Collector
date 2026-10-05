# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.1] - YYYY-MM-DD

### Fixed
- Process creation dates no longer fail or swap day/month on non-US system locales (e.g. `es-CO`). CIM `DateTime` values are now converted to UTC directly instead of being re-parsed as text.
- A run key value with empty or null data no longer aborts that key and drops its remaining entries.
- Empty sections are serialized as `[]` instead of `null`, matching the documented output schema.

### Changed
- Authenticode signature validation now runs for every process; `-HashBinaries` only controls SHA256 hashing.
- Hash and signature results are cached per binary path, so shared images (e.g. `svchost.exe`) are checked once.
- The script now returns a result object (artifact path, hash, counts) instead of writing to the host, so it can be used in pipelines and remains visible in RTR / Live Response consoles.

### Added
- `RunOnce` under `WOW6432Node` is now collected.
- A `.sha256` sidecar file (sha256sum format) is written next to each JSON artifact.
- Pester tests, including a regression test for the `es-CO` locale.
- GitHub Actions workflow running PSScriptAnalyzer and Pester on Windows PowerShell 5.1 and PowerShell 7.

## [1.0.0] - YYYY-MM-DD

### Added
- Initial release: process, network, run key persistence and security posture collection with JSON output and SHA256 integrity hash.
