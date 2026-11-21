# IR-Triage-Collector

Live-response forensic triage collector for Windows endpoints during incident response and threat hunting operations.

[![PSScriptAnalyzer](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector/actions/workflows/psscriptanalyzer.yml/badge.svg)](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector/actions)
[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Santiago-Agudelo-R/IR-Triage-Collector?color=success)](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector/releases)

---

## Overview

During active endpoint investigations, rapidly acquiring volatile state is required to detect lateral movement, malicious child processes, and unauthorized persistence. `IR-Triage-Collector` is a modular, standalone PowerShell tool designed to execute locally, via WinRM, or directly through EDR live response consoles (such as CrowdStrike Falcon Real Time Response [RTR] and Microsoft Defender for Endpoint Live Response).

All extracted dates are normalized to ISO 8601 UTC, regardless of the host's locale. The collector emits its summary object—including the SHA256 digest of the JSON artifact—directly to the remote EDR console output stream so the integrity hash is recorded off-host in the EDR audit log before artifact retrieval.

---

## Collected Telemetry

1. **Running Processes (`Get-ProcessTriage`):**
   - Process ID (PID) and Parent Process ID (PPID) mapping.
   - Command-line arguments and executable path verification.
   - High-risk path detection (flags binaries executed from `\AppData\`, `\Temp\`, `\Users\Public\`).
   - System binary masquerading detection (`IsMasqueradingSuspect` — compares core Windows process names such as `svchost.exe`, `lsass.exe`, `csrss.exe`, `explorer.exe` against `$env:SystemRoot`).
   - Authenticode digital signature validation (always) and optional SHA256 binary hashing (`-HashBinaries`), cached per binary.

2. **Network & Name Resolution State (`Get-NetworkConnectionsTriage`, `Get-DnsAndArpCacheTriage`):**
   - Active TCP connections (`Established`, `Listen`, `SynSent`) and UDP listening endpoints (`Get-NetUDPEndpoint`) mapped to owning PIDs.
   - Volatile DNS client cache (`Get-DnsClientCache`) and neighbor/ARP cache (`Get-NetNeighbor`) snapshots.

3. **Persistence Mechanisms:**
   - **Registry Run Keys (`Get-PersistenceRegistry`):** Collects `Run` and `RunOnce` across `HKLM`, `HKCU`, 32-bit `WOW6432Node`, and **all loaded user SID hives under `HKEY_USERS`** (so running as `NT AUTHORITY\SYSTEM` in RTR/Live Response still captures logged-on user Run keys). Optional `-MountOfflineUserHives` reads profiles that are not logged on by loading a temporary **copy** of their `NTUSER.DAT` (never the original, since `reg load` opens hives read-write).
   - **Scheduled Tasks (`Get-ScheduledTasksTriage`):** Enabled scheduled tasks with their actions, flagging script interpreters and LOLBins (`powershell`, `cmd`, `wscript`, `mshta`, `rundll32`, `certutil`...) or user-writable paths.
   - **Windows Services (`Get-ServicesTriage`):** Running and auto-start services, resolving underlying executable paths from `PathName`, validating Authenticode signatures (cached), and flagging unsigned binaries outside `$env:SystemRoot` or services executing from user-writable locations (`IsSuspiciousService`).
   - **WMI Event Subscriptions (`Get-WmiPersistenceTriage`):** Enumerates `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` under `root\subscription`, baseline-excluding the built-in `SCM Event Log Consumer`.

4. **Logon Sessions & Host Security Posture (`Get-LogonSessionTriage`, `Get-SecurityPosture`):**
   - Active interactive and remote (RDP) logon sessions (`Win32_LogonSession` types `2`, `10`, `11`).
   - Microsoft Defender engine status (`RealTimeProtection`, `BehaviorMonitoring`, signature freshness) and local `Administrators` (`S-1-5-32-544`) group enumeration.

---

## MITRE ATT&CK Coverage

| Telemetry Module | MITRE ATT&CK Technique | Detection Focus |
| :--- | :--- | :--- |
| **Running Processes** | `T1059.001` (PowerShell), `T1036.005` (Match Legitimate Name or Location) | Captures full `CommandLine`, parent-child PID trees, Authenticode signature status, SHA256 hashes, user-writable execution paths, and system binary path masquerading (`IsMasqueradingSuspect`). |
| **Network Endpoints** | `T1071` (Application Layer Protocol), `T1049` (System Network Connections Discovery) | Maps active TCP (`Established`, `Listen`, `SynSent`) and UDP endpoints back to owning process IDs (`OwningProcess`). |
| **Registry Run Keys** | `T1547.001` (Registry Run Keys / Startup Folder) | Audits `Run` and `RunOnce` across `HKLM`, `HKCU`, `WOW6432Node`, and loaded `HKEY_USERS\<SID>` user hives (plus optional offline `NTUSER.DAT` mounting). |
| **Scheduled Tasks** | `T1053.005` (Scheduled Task/Job: Scheduled Task) | Flags enabled tasks invoking script interpreters or LOLBins (`powershell`, `pwsh`, `cmd`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`) or user-writable paths. |
| **Windows Services** | `T1543.003` (Create or Modify System Process: Windows Service) | Resolves service executable paths, validates Authenticode signatures, and flags unsigned binaries outside `$env:SystemRoot` or services running from user-writable directories. |
| **WMI Subscriptions** | `T1546.003` (Event Triggered Execution: WMI Event Subscription) | Audits `root\subscription` (`__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`) and flags non-standard consumers beyond `SCM Event Log Consumer`. |
| **DNS & ARP Cache** | `T1071.004` (DNS), `T1018` (Remote System Discovery) | Captures volatile `Get-DnsClientCache` and `Get-NetNeighbor` snapshots prior to host network containment. |
| **Security Posture** | `T1562.001` (Impair Defenses), `T1078` (Valid Accounts) | Verifies Microsoft Defender real-time/behavior monitoring state, enumerates local `Administrators` (`S-1-5-32-544`), and lists interactive/RDP `Win32_LogonSession` entries. |

---

## Usage

### 1. Basic Execution (Fast Volatile Check)
```powershell
.\src\Invoke-IRTriage.ps1 -OutputDirectory "C:\Windows\Temp\IRTriage"
```

### 2. Full Forensic Triage with SHA256 Binary Hashing & Offline User Hive Inspection
```powershell
.\src\Invoke-IRTriage.ps1 -HashBinaries -MountOfflineUserHives -OutputDirectory "C:\IR_Output"
```

### 3. Execution via CrowdStrike RTR or Defender Live Response
```powershell
run Invoke-IRTriage.ps1 -HashBinaries -OutputDirectory "C:\Windows\Temp\Triage"
```

---

## Evidence Integrity & Off-Host Hash Verification

A `.sha256` sidecar file stored on the same compromised endpoint cannot by itself guarantee integrity against a local rootkit or administrator attacker who modifies both files before retrieval. To preserve chain-of-custody integrity:
1. `Invoke-IRTriage.ps1` returns a pipeline summary object containing the computed `SHA256` digest directly to **stdout** (which CrowdStrike RTR and Microsoft Defender Live Response record immediately in the cloud EDR console audit log off-host).
2. After downloading the JSON artifact from the endpoint, compare its local `Get-FileHash -Algorithm SHA256` against the `SHA256` value logged in the cloud EDR session transcript.
3. If `$PSScriptRoot` is empty (for example, when the script body is pasted directly into an interactive session without `-OutputDirectory`), the default output path falls back safely to `$env:TEMP\IRTriageOutput` rather than writing to the root of the system drive.

---

## Testing & CI

Every push and pull request to `main` runs in GitHub Actions on Windows:
- **PSScriptAnalyzer** linting (fails on any error or warning).
- **Pester 5** tests on both Windows PowerShell 5.1 and PowerShell 7, including `es-CO` locale regression and `T1036.005` masquerading checks.

```powershell
Invoke-Pester ./tests -Output Detailed
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
