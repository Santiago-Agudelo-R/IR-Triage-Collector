# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-10-05

### Added
- Active scheduled task enumeration (`Get-ScheduledTasksTriage`) highlighting suspicious script interpreter invocations (PowerShell, WScript, MSHTA).
- Windows service persistence collection (`Get-ServicesTriage`) mapping running and auto-start services, flagging non-standard execution paths outside `System32`.

### Changed
- Standardized documentation layout and updated sample JSON schemas.

## [1.0.0] - 2026-10-05

### Added
- Initial release of `Invoke-IRTriage.ps1`.
- Live volatile process tree analysis with PID/PPID mapping and Authenticode signature verification.
- Active TCP connection state gathering mapped to owning processes.
- Common registry run-key persistence detection (`HKLM` and `HKCU`).
- Host security posture audit (Microsoft Defender engine status and local Administrators group enumeration).
- Strict ISO 8601 UTC timestamp normalization and SHA-256 integrity hash verification of output JSON.
