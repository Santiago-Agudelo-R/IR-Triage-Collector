# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.1] - 2026-10-05

### Fixed
- Restored scheduled task and service collection, which had been dropped from the script by mistake after v1.1.0.
- Scheduled task collection no longer stops on the first task with a COM handler action (StrictMode raised an error on the missing `Execute` property and the whole section came back empty).
- Process creation dates no longer fail or swap day/month on non-US system locales (e.g. `es-CO`). CIM `DateTime` values are now converted to UTC directly instead of being re-parsed as text.
- A run key value with empty or null data no longer aborts that key and drops its remaining entries.
- Empty sections are serialized as `[]` instead of `null`, matching the documented output schema.

### Changed
- Authenticode signature validation now runs for every process; `-HashBinaries` only controls SHA256 hashing.
- Hash and signature results are cached per binary path, so shared images (e.g. `svchost.exe`) are checked once.
- The script returns a result object (artifact path, hash, counts) instead of writing to the host, so it can be used in pipelines and stays visible in RTR / Live Response consoles.
- Scheduled task detection also flags `rundll32`, `regsvr32` and `\Users\Public\`, and records the task author.

### Added
- `RunOnce` under `WOW6432Node` is now collected.
- A `.sha256` sidecar file (sha256sum format) is written next to each JSON artifact.
- Pester tests, including a regression test for the `es-CO` locale.
- GitHub Actions workflow running PSScriptAnalyzer and Pester on Windows PowerShell 5.1 and PowerShell 7.

## [1.1.0] - 2026-10-05

### Added
- Active scheduled task enumeration (`Get-ScheduledTasksTriage`) highlighting suspicious script interpreter invocations (PowerShell, WScript, MSHTA).
- Windows service persistence collection (`Get-ServicesTriage`) mapping running and auto-start services, flagging non-standard execution paths outside `System32`.

## [1.0.0] - 2026-10-05

### Added
- Initial release: process, network, run key persistence and security posture collection with JSON output and SHA256 integrity hash.
