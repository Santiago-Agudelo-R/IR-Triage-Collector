# IR-Triage-Collector

Enterprise live-response forensic triage collector for Windows endpoints during incident response and threat hunting operations.

[![PSScriptAnalyzer](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector/actions/workflows/psscriptanalyzer.yml/badge.svg)](https://github.com/Santiago-Agudelo-R/IR-Triage-Collector/actions)
[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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

4. **Security Posture:**
   - Microsoft Defender engine status (RealTimeProtection, BehaviorMonitoring, signature freshness).
   - Local `Administrators` group enumeration.

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
Triage_WKSTN-SEC-01_20261005_162000.json
Triage_WKSTN-SEC-01_20261005_162000.json.sha256
```

```text
Status             : Completed
HostName           : WKSTN-SEC-01
ArtifactPath       : C:\IR_Output\Triage_WKSTN-SEC-01_20261005_162000.json
SHA256             : 3A7BD3E2360A3D29EEA436FCFB7E44C735D117C42D1C1835420B6B9942DD4F1B
HashFile           : C:\IR_Output\Triage_WKSTN-SEC-01_20261005_162000.json.sha256
ProcessCount       : 214
ConnectionCount    : 38
PersistenceEntries : 7
```

Verify the artifact later with:

```powershell
(Get-FileHash .\Triage_WKSTN-SEC-01_20261005_162000.json -Algorithm SHA256).Hash
```

---

## Sample JSON Output Structure

```json
{
  "Metadata": {
    "CollectorVersion": "1.0.1",
    "HostName": "WKSTN-SEC-01",
    "TimestampUtc": "2026-10-05T16:20:00.1234567Z",
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
      "CreationDateUtc": "2026-10-05T16:15:30.0000000Z"
    }
  ],
  "NetworkConnections": [
    {
      "LocalAddress": "192.168.1.15",
      "LocalPort": 49832,
      "RemoteAddress": "198.51.100.24",
      "RemotePort": 443,
      "State": "Established",
      "OwningProcess": 4820
    }
  ],
  "PersistenceRegistry": [],
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

## Roadmap

- [ ] Scheduled tasks and auto-start services (persistence)
- [ ] DNS client cache and ARP table
- [ ] Logged-on users and recent logon sessions
- [ ] Optional CSV/HTML summary for quick analyst review
- [ ] Packaging as a PowerShell module

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
