# IR-Triage-Collector

Enterprise live-response forensic triage collector for Windows endpoints during incident response and threat hunting operations.

[![PSScriptAnalyzer](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector/actions/workflows/psscriptanalyzer.yml/badge.svg)](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector/actions)
[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Santiago-Agudelo-R/IR-Triage-Collector?color=success)](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector/releases)

---

## Overview

During active endpoint investigations, rapidly acquiring volatile state is required to detect lateral movement, malicious child processes, and unauthorized persistence. `IR-Triage-Collector` is a modular, standalone PowerShell tool designed to execute locally, via WinRM, or directly through EDR live response consoles (such as CrowdStrike Falcon Real Time Response [RTR] and Microsoft Defender for Endpoint Live Response).

All extracted dates are normalized to ISO 8601 UTC, regardless of the host's locale. Each report is written as JSON together with a `.sha256` sidecar file so its integrity can be verified later in the chain of custody.

---

## Collected Telemetry

1. **Running Processes:**
   - Process ID (PID) and Parent Process ID (PPID) mapping.
   - Command-line arguments and working directory context.
   - Executable path verification.
   - High-risk path detection (flags binaries executed from `\AppData\`, `\Temp\`, `\Users\Public\`).
   - Authenticode digital signature validation (always) and optional SHA256 binary hashing (`-HashBinaries`), cached per binary.

2. **Network State:**
   - Active TCP connections (`Established`, `Listen`, `SynSent`) mapped to owning PIDs and remote endpoints.

3. **Persistence Mechanisms:**
   - Registry run keys across `HKLM` and `HKCU` (`Run` and `RunOnce`, including the 32-bit `WOW6432Node` paths).
   - Enabled scheduled tasks with their actions, flagging script interpreters and LOLBins (`powershell`, `cmd`, `wscript`, `mshta`, `rundll32`, `certutil`...) or user-writable paths.
   - Running and auto-start services (`Get-ServicesTriage`), resolving underlying executable paths from `PathName`, validating Authenticode signatures (cached), and flagging unsigned binaries outside `C:\Windows\` or services executing from user-writable locations (`IsSuspiciousService`).

4. **Security Posture:**
   - Microsoft Defender engine status (RealTimeProtection, BehaviorMonitoring, signature freshness).
   - Local `Administrators` group enumeration.

---

## MITRE ATT&CK Coverage

| Telemetry Module | MITRE ATT&CK Technique | Detection Focus |
| :--- | :--- | :--- |
| **Running Processes** | `T1059.001` (PowerShell), `T1036` (Masquerading) | Captures full `CommandLine`, parent-child PID trees, Authenticode signature status, SHA256 hashes, and binaries executing from `\AppData\`, `\Temp\`, or `\Users\Public\`. |
| **Network State** | `T1071` (Application Layer Protocol), `T1041` (Exfiltration) | Correlates active `Established`, `Listen`, and `SynSent` TCP sockets back to owning process IDs (`OwningProcess`). |
| **Registry Run Keys** | `T1547.001` (Registry Run Keys / Startup Folder) | Audits `Run` and `RunOnce` across `HKLM`, `HKCU`, and 32-bit `WOW6432Node` hives. |
| **Scheduled Tasks** | `T1053.005` (Scheduled Task/Job: Scheduled Task) | Flags enabled tasks invoking script interpreters or LOLBins (`powershell`, `pwsh`, `cmd`, `wscript`, `cscript`, `mshta`, `rundll32`, `regsvr32`, `certutil`, `bitsadmin`) or user-writable paths. |
| **Windows Services** | `T1543.003` (Create or Modify System Process: Windows Service) | Resolves service executable paths, validates Authenticode signatures, and flags unsigned binaries outside `C:\Windows\` or services running from user-writable directories. |
| **Security Posture** | `T1562.001` (Impair Defenses), `T1098` (Account Manipulation) | Verifies Microsoft Defender real-time/behavior monitoring state and enumerates local `Administrators` group membership. |

---

## Installation & Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7+
- Administrative privileges recommended for full low-level system access.

Clone the repository:
```powershell
git clone https://github.com/Santiago-Agudelo-R/IR-Triage-Collector.git
cd IR-Triage-Collector
```

---

## Usage

### 1. Basic Execution (Fast Volatile Check)
```powershell
.\src\Invoke-IRTriage.ps1
```

### 2. Full Forensic Triage with SHA256 Binary Hashing
```powershell
.\src\Invoke-IRTriage.ps1 -HashBinaries -OutputDirectory "C:\IR_Output"
```

### 3. Execution via CrowdStrike RTR or Defender Live Response
```powershell
# Upload or paste Invoke-IRTriage.ps1 into the RTR session
run Invoke-IRTriage.ps1 -HashBinaries -OutputDirectory "C:\Windows\Temp\Triage"
```

---

### Output

Every run produces two files in the output directory and returns a summary object:

```text
Triage_WKSTN-SEC-01_20261018_162000.json
Triage_WKSTN-SEC-01_20261018_162000.json.sha256
```

```text
Status             : Completed
HostName           : WKSTN-SEC-01
ArtifactPath       : C:\IR_Output\Triage_WKSTN-SEC-01_20261018_162000.json
SHA256             : 3A7BD3E2360A3D29EEA436FCFB7E44C735D117C42D1C1835420B6B9942DD4F1B
HashFile           : C:\IR_Output\Triage_WKSTN-SEC-01_20261018_162000.json.sha256
ProcessCount       : 214
ConnectionCount    : 38
PersistenceEntries : 7
ScheduledTasks     : 142
Services           : 121
```

Verify the artifact later with:

```powershell
(Get-FileHash .\Triage_WKSTN-SEC-01_20261018_162000.json -Algorithm SHA256).Hash
```

---

## Sample JSON Output Structure

```json
{
  "Metadata": {
    "CollectorVersion": "1.1.3",
    "HostName": "WKSTN-SEC-01",
    "TimestampUtc": "2026-10-18T16:20:00.1234567Z",
    "OperatingSystem": "Microsoft Windows 11 Enterprise",
    "IsElevatedSession": true
  },
  "Processes": [
    {
      "ProcessId": 4820,
      "ParentProcessId": 1044,
      "Name": "powershell.exe",
      "CommandLine": "powershell.exe -NoP -NonI -W Hidden -Enc ...",
      "ExecutablePath": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "SHA256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "IsAuthenticodeSigned": true,
      "IsHighRiskLocation": false,
      "CreationDateUtc": "2026-10-18T16:15:30.0000000Z"
    }
  ],
  "NetworkConnections": [
    {
      "LocalAddress": "192.0.2.15",
      "LocalPort": 49832,
      "RemoteAddress": "198.51.100.24",
      "RemotePort": 443,
      "State": "Established",
      "OwningProcess": 4820
    }
  ],
  "PersistenceRegistry": [],
  "ScheduledTasks": [
    {
      "TaskName": "UpdaterTask",
      "TaskPath": "\\",
      "State": "Ready",
      "Author": null,
      "Actions": "powershell.exe -NoP -W Hidden -File C:\\Users\\Public\\upd.ps1",
      "IsSuspiciousAction": true
    }
  ],
  "Services": [
    {
      "Name": "ExampleSvc",
      "DisplayName": "Example Service",
      "State": "Running",
      "StartMode": "Auto",
      "PathName": "\"C:\\Program Files\\Example\\svc.exe\" --service",
      "ExecutablePath": "C:\\Program Files\\Example\\svc.exe",
      "StartName": "LocalSystem",
      "ProcessId": 3120,
      "IsNonStandardPath": true,
      "IsAuthenticodeSigned": true,
      "IsSuspiciousService": false
    }
  ],
  "SecurityPosture": {
    "DefenderStatus": {
      "RealTimeProtectionEnabled": true,
      "AntivirusEnabled": true
    },
    "LocalAdminMembers": ["BUILTIN\\Administrator", "CORP\\SecOpsAdmin"]
  }
}
```

---

## Testing & CI

Every push and pull request to `main` runs in GitHub Actions on Windows:

- **PSScriptAnalyzer** linting (fails on any error or warning).
- **Pester 5** tests on both Windows PowerShell 5.1 and PowerShell 7, including a regression test that runs the collector under the `es-CO` locale.

Run the tests locally:

```powershell
Install-Module Pester -MinimumVersion 5.5.0 -Scope CurrentUser
Invoke-Pester ./tests -Output Detailed
```

---

## EDR Live Response Notes & Limitations

- **Execution Context (`SYSTEM` vs. User):** CrowdStrike Falcon RTR and Microsoft Defender Live Response execute scripts as `NT AUTHORITY\SYSTEM`. While `HKLM` Run keys, services, and scheduled tasks are collected system-wide, `HKCU` Run keys reflect the active hive of the account running the script unless user hives under `HKEY_USERS` are explicitly mounted.
- **Binary Hashing Timeouts (`-HashBinaries`):** Computing SHA256 hashes and Authenticode signatures across all running binaries adds I/O overhead (mitigated by per-path caching). In EDR consoles with strict command timeouts (for example, 10-minute default RTR session limits), run without `-HashBinaries` first for rapid triage.
- **Heuristic False Positives:** Third-party enterprise agents installed under `C:\ProgramData\` (such as EDR, RMM, or backup helpers) are only flagged as `IsSuspiciousService = true` when the binary is **unsigned** or executes from a user-writable profile directory (`\AppData\`, `\Temp\`, `\Users\Public\`).

---

## Planned Enhancements

- WMI event subscriptions (`__EventFilter` / `CommandLineEventConsumer`) and Startup folder persistence
- DNS client cache and ARP table snapshots
- Interactive logon sessions (`Win32_LogonSession`)
- Optional CSV/HTML summary report for analyst review

See [CHANGELOG.md](CHANGELOG.md) for completed features and release history.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
