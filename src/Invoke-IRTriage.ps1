<#
.SYNOPSIS
    Gathers volatile endpoint forensic triage data for live incident response.

.DESCRIPTION
    Invoke-IRTriage collects running process metadata, active network connections,
    common persistence registry keys, and local security configurations.
    Designed for incident response execution via CrowdStrike Real Time Response (RTR),
    Microsoft Defender Live Response, WinRM, or local administrative sessions.
    All timestamps are recorded in UTC (ISO 8601). Output is exported to
    a cryptographically hashed JSON artifact.

.PARAMETER OutputDirectory
    Directory where the triage JSON report will be saved. Defaults to "$PSScriptRoot\TriageOutput".

.PARAMETER HashBinaries
    Switch parameter. When enabled, computes SHA256 hashes of running executable binaries.
    Executables inaccessible due to system locking or permission restrictions are safely handled.

.EXAMPLE
    .\Invoke-IRTriage.ps1 -HashBinaries

.EXAMPLE
    .\Invoke-IRTriage.ps1 -OutputDirectory "C:\IncidentResponse\Artifacts" -HashBinaries

.NOTES
    Author: Santiago Agudelo
    License: MIT
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = "$PSScriptRoot\TriageOutput",

    [Parameter(Mandatory = $false)]
    [switch]$HashBinaries
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ProcessTriage {
    [CmdletBinding()]
    param ([switch]$ComputeHash)

    Write-Verbose "Collecting running process telemetry..."
    $processList = [System.Collections.Generic.List[PSObject]]::new()
    $processes = Get-CimInstance -ClassName Win32_Process

    foreach ($proc in $processes) {
        $binaryPath = $proc.ExecutablePath
        $sha256 = "N/A"
        $isSigned = $null

        if ($ComputeHash -and [string]::IsNullOrWhiteSpace($binaryPath) -eq $false -and (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
            try {
                $hashResult = Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop
                $sha256 = $hashResult.Hash
            }
            catch {
                $sha256 = "AccessDeniedOrLocked"
            }

            try {
                $sig = Get-AuthenticodeSignature -LiteralPath $binaryPath -ErrorAction Stop
                $isSigned = ($sig.Status -eq [System.Management.Automation.SignatureStatus]::Valid)
            }
            catch {
                $isSigned = $false
            }
        }

        $isHighRiskLocation = $false
        if ($binaryPath) {
            $highRiskPatterns = @('\\AppData\\', '\\Temp\\', '\\Users\\Public\\', '\\ProgramData\\[^\\]+\.exe$')
            foreach ($pattern in $highRiskPatterns) {
                if ($binaryPath -match $pattern) {
                    $isHighRiskLocation = $true
                    break
                }
            }
        }

        $processList.Add([PSCustomObject]@{
            ProcessId            = $proc.ProcessId
            ParentProcessId      = $proc.ParentProcessId
            Name                 = $proc.Name
            CommandLine          = $proc.CommandLine
            ExecutablePath       = $binaryPath
            SHA256               = $sha256
            IsAuthenticodeSigned = $isSigned
            IsHighRiskLocation   = $isHighRiskLocation
            CreationDateUtc      = if ($proc.CreationDate) { [DateTime]::Parse($proc.CreationDate).ToUniversalTime().ToString("o") } else { $null }
        })
    }

    return $processList
}

function Get-NetworkConnectionsTriage {
    Write-Verbose "Collecting network connection telemetry..."
    $connectionList = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $tcpConns = Get-NetTCPConnection -State Established, Listen, SynSent -ErrorAction Stop
        foreach ($conn in $tcpConns) {
            $connectionList.Add([PSCustomObject]@{
                LocalAddress  = $conn.LocalAddress
                LocalPort     = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort    = $conn.RemotePort
                State         = $conn.State.ToString()
                OwningProcess = $conn.OwningProcess
            })
        }
    }
    catch {
        Write-Warning "Get-NetTCPConnection query failed: $_"
    }

    return $connectionList
}

function Get-PersistenceRegistry {
    Write-Verbose "Collecting run-key persistence entries..."
    $entries = [System.Collections.Generic.List[PSObject]]::new()

    $targets = @(
        @{ Hive = "LocalMachine"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "LocalMachine"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = "CurrentUser";  Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "CurrentUser";  Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = "LocalMachine"; Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" }
    )

    foreach ($target in $targets) {
        try {
            $baseKey = if ($target.Hive -eq "LocalMachine") {
                [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($target.Path)
            } else {
                [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($target.Path)
            }

            if ($baseKey) {
                $valueNames = $baseKey.GetValueNames()
                foreach ($name in $valueNames) {
                    $entries.Add([PSCustomObject]@{
                        Hive      = $target.Hive
                        KeyPath   = $target.Path
                        ValueName = $name
                        ValueData = $baseKey.GetValue($name).ToString()
                    })
                }
                $baseKey.Close()
            }
        }
        catch {
            Write-Verbose "Could not read key $($target.Path): $_"
        }
    }

    return $entries
}

function Get-SecurityPosture {
    Write-Verbose "Auditing baseline host security configuration..."
    $defenderState = $null
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop
        $defenderState = [PSCustomObject]@{
            RealTimeProtectionEnabled        = $mp.RealTimeProtectionEnabled
            AntivirusEnabled                 = $mp.AntivirusEnabled
            BehaviorMonitorEnabled           = $mp.BehaviorMonitorEnabled
            IoavProtectionEnabled            = $mp.IoavProtectionEnabled
            NISSignatureVersion              = $mp.NISSignatureVersion
            AntivirusSignatureLastUpdatedUtc = if ($mp.AntivirusSignatureLastUpdated) { $mp.AntivirusSignatureLastUpdated.ToUniversalTime().ToString("o") } else { $null }
        }
    }
    catch {
        $defenderState = "UnavailableOrNotInstalled"
    }

    $localAdmins = [System.Collections.Generic.List[string]]::new()
    try {
        $members = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        foreach ($m in $members) {
            $localAdmins.Add($m.Name)
        }
    }
    catch {
        Write-Verbose "Unable to query local administrators: $_"
    }

    return [PSCustomObject]@{
        DefenderStatus    = $defenderState
        LocalAdminMembers = $localAdmins
    }
}

if (-not (Test-IsAdministrator)) {
    Write-Warning "Running in non-elevated context. Some low-level system artifacts may be restricted."
}

$executionTimestampUtc = [DateTime]::UtcNow.ToString("o")
$hostName = [System.Environment]::MachineName

Write-Host "[+] Initializing IR Triage on host: $hostName (UTC: $executionTimestampUtc)" -ForegroundColor Cyan

$triagePayload = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        CollectorVersion  = "1.0.0"
        HostName          = $hostName
        TimestampUtc      = $executionTimestampUtc
        OperatingSystem   = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        IsElevatedSession = (Test-IsAdministrator)
    }
    Processes           = Get-ProcessTriage -ComputeHash:$HashBinaries
    NetworkConnections  = Get-NetworkConnectionsTriage
    PersistenceRegistry = Get-PersistenceRegistry
    SecurityPosture     = Get-SecurityPosture
}

if (-not (Test-Path -LiteralPath $OutputDirectory)) {
    $null = New-Item -ItemType Directory -Path $OutputDirectory -Force
}

$safeHostName = $hostName -replace '[^a-zA-Z0-9_\-]', '_'
$timestampFileStr = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss")
$outputFileName = "Triage_${safeHostName}_${timestampFileStr}.json"
$destinationPath = Join-Path -Path $OutputDirectory -ChildPath $outputFileName

$jsonContent = $triagePayload | ConvertTo-Json -Depth 6
[System.IO.File]::WriteAllText($destinationPath, $jsonContent, [System.Text.Encoding]::UTF8)

$reportHash = (Get-FileHash -LiteralPath $destinationPath -Algorithm SHA256).Hash

Write-Host "[+] Triage collection completed successfully." -ForegroundColor Green
Write-Host "    Artifact Path : $destinationPath"
Write-Host "    SHA256 Hash   : $reportHash"
