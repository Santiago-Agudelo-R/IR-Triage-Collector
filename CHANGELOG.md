# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.2.1] - 2026-11-21

### Fixed
- **Offline user hives (`-MountOfflineUserHives`):** The documentation said hives were mounted read-only, but `reg load` opens a hive read-write and can replay transaction logs into it. The collector now copies `NTUSER.DAT` and its `.LOG1`/`.LOG2` files to a temporary folder, loads the copy, and deletes it afterwards, so the original evidence is never loaded.
- **Offline user hives:** `ProfileImagePath` values such as `%SystemDrive%\Users\alice` are now expanded before use.
- **Logon sessions:** Each session now includes its account (`DOMAIN\user`) from `Win32_LoggedOnUser`; previously sessions had no owner.

## [1.2.0] - 2026-11-21

### Added
- **Multi-User Hive Run-Key Enumeration (`Get-PersistenceRegistry` — `Q5`):** Iterates all loaded user SIDs under `HKEY_USERS` (`S-1-5-21-...`) so running as `NT AUTHORITY\SYSTEM` in CrowdStrike RTR or Defender Live Response captures logged-on user `Run` and `RunOnce` keys. Added optional `-MountOfflineUserHives` switch to temporarily mount unmounted local `NTUSER.DAT` hives read-only.
- **System Binary Masquerading Detection (`Test-SystemBinaryMasquerading` — MITRE `T1036.005`, `Q6`):** Flags processes named after core Windows system executables (`svchost.exe`, `lsass.exe`, `csrss.exe`, `explorer.exe`, etc.) executing from paths outside `$env:SystemRoot` (`IsMasqueradingSuspect`).
- **UDP Endpoints, WMI Subscriptions, DNS/ARP Cache & Logon Sessions (`Get-WmiPersistenceTriage`, `Get-DnsAndArpCacheTriage`, `Get-LogonSessionTriage`):** Added UDP listening endpoint collection (`Get-NetUDPEndpoint`), `root\subscription` WMI persistence enumeration (`T1546.003`), DNS/ARP cache snapshots, and interactive/RDP logon session enumeration (`Win32_LogonSession`).

### Fixed
- **TCP State Filtering (`Get-NetworkConnectionsTriage`):** Filtered TCP connection states post-query so hosts with zero active `SynSent` sockets no longer throw a CIM exception that discarded `Established` and `Listen` connections.
- **Dynamic `$env:SystemRoot` & Interactive `$OutputDirectory` Fallback (`Q6`, `S7`):** Replaced hardcoded `C:\Windows\` path checks in `Get-ServicesTriage` with `$env:SystemRoot`, and added an `$env:TEMP\IRTriageOutput` fallback when `$PSScriptRoot` is empty in interactive RTR paste sessions.

## [1.1.3] - 2026-10-18

### Fixed
- Removed `\ProgramData\` from the unconditional user-writable service path pattern in `Get-ServicesTriage` so legitimate Authenticode-signed services executing from `C:\ProgramData\` (such as Microsoft Defender's `WinDefend` / `MsMpEng.exe`) are not flagged with `IsSuspiciousService = $true`.

## [1.1.2] - 2026-10-18

### Added
- `Resolve-ServiceExecutablePath` helper and cached Authenticode signature verification inside `Get-ServicesTriage`.

## [1.1.1] - 2026-10-05

### Fixed
- Restored scheduled task and service collection, COM handler action safety under `StrictMode`, and locale-independent UTC timestamps (`es-CO` regression test).

## [1.1.0] - 2026-10-05

### Added
- Active scheduled task enumeration (`Get-ScheduledTasksTriage`) and Windows service persistence collection (`Get-ServicesTriage`).

## [1.0.0] - 2026-10-05

### Added
- Initial release: process, network, run key persistence and security posture collection with JSON output and SHA256 integrity hash.
