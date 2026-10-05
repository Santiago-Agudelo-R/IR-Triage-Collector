# IR-Triage-Collector

Enterprise live-response forensic triage collector for Windows endpoints during incident response and threat hunting operations.

[![PowerShell 5.1 / 7+](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-blue.svg)](https://microsoft.com/PowerShell)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Titaaron/IR-Triage-Collector?color=success)](https://github.com/Titaaron/IR-Triage-Collector/releases)

---

## Overview

During active endpoint investigations, rapidly acquiring volatile state is required to detect lateral movement, malicious child processes, and unauthorized persistence. `IR-Triage-Collector` is a modular, standalone PowerShell tool designed to execute locally, via WinRM, or directly through EDR live response consoles (such as CrowdStrike Falcon Real Time Response [RTR] and Microsoft Defender for Endpoint Live Response).

All extracted dates are strictly normalized to ISO 8601 UTC format. Output reports are structured in JSON and validated with a SHA256 integrity hash upon generation.

---

## Collected Telemetry

1. **Running Processes:**
   - Process ID (PID) and Parent Process ID (PPID) mapping.
   - Command-line arguments and execution context.
   - Executable path verification.
   - High-risk path detection (flags binaries executed from `\AppData\`, `\Temp\`, `\Users\Public\`).
   - Authenticode digital signature validation and optional SHA256 binary hashing.

2. **Network State:**
   - Active TCP connections (`Established`, `Listen`, `SynSent`) mapped to owning PIDs and remote endpoints.

3. **Persistence Mechanisms:**
   - Registry run keys across `HKLM` and `HKCU` (`Run`, `RunOnce`, and 32-bit `WOW6432Node` paths).
   - Active Scheduled Tasks, highlighting script engine invocations (PowerShell, WScript, MSHTA).
   - Windows Services auditing (running and auto-start services, highlighting non-standard binaries outside `System32`).

4. **Security Posture:**
   - Microsoft Defender engine status (RealTimeProtection, BehaviorMonitoring, signature freshness).
   - Local `Administrators` group enumeration.

---

## Requirements

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7+
- Administrative privileges recommended for full low-level system access.

Clone the repository:
```powershell
git clone https://github.com/Titaaron/IR-Triage-Collector.git
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
# Upload or paste Invoke-IRTriage.ps1 into the RTR / Live Response session
run Invoke-IRTriage.ps1 -HashBinaries -OutputDirectory "C:\Windows\Temp\Triage"
```

---

## Sample JSON Output Structure

```json
{
  "Metadata": {
    "CollectorVersion": "1.1.0",
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
  "ScheduledTasks": [],
  "Services": [],
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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
