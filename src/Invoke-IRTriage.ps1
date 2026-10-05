<#
.SYNOPSIS
    Gathers volatile endpoint forensic triage data for live incident response.

.DESCRIPTION
    Invoke-IRTriage collects running process metadata, active network connections,
    common persistence registry keys, active scheduled tasks, running and auto-start
    services, and local security configurations.
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
    [OutputType([object[]])]
    param ([switch]$ComputeHash)

    Write-Verbose "Collecting running process telemetry..."
    $processList = [System.Collections.Generic.List[PSObject]]::new()
    $processes = Get-CimInstance -ClassName Win32_Process
    $highRiskPatterns = @('\\AppData\\', '\\Temp\\', '\\Users\\Public\\', '\\ProgramData\\[^\\]+\.exe$')

    # Cache per binary path: many processes share the same image (svchost.exe, chrome.exe...),
    # so each file is hashed and signature-checked only once.
    $binaryCache = @{}

    foreach ($proc in $processes) {
        $binaryPath = $proc.ExecutablePath
        $sha256 = "N/A"
        $isSigned = $null

        if (-not [string]::IsNullOrWhiteSpace($binaryPath) -and (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
            if (-not $binaryCache.ContainsKey($binaryPath)) {
                $entry = @{ SHA256 = "N/A"; IsSigned = $false }

                # Signature validation always runs: it is the main signal for unsigned binaries.
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $binaryPath -ErrorAction Stop
                    $entry.IsSigned = ($sig.Status -eq [System.Management.Automation.SignatureStatus]::Valid)
                }
                catch {
                    $entry.IsSigned = $false
                }

                if ($ComputeHash) {
                    try {
                        $entry.SHA256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash
                    }
                    catch {
                        $entry.SHA256 = "AccessDeniedOrLocked"
                    }
                }

                $binaryCache[$binaryPath] = $entry
            }

            $sha256 = $binaryCache[$binaryPath].SHA256
            $isSigned = $binaryCache[$binaryPath].IsSigned
        }

        $isHighRiskLocation = $false
        if ($binaryPath) {
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
            # CIM already returns a [DateTime]. Re-parsing it as text breaks on non-US locales
            # (es-CO, es-ES...): the script crashed or swapped day/month.
            CreationDateUtc      = if ($proc.CreationDate) { ([DateTime]$proc.CreationDate).ToUniversalTime().ToString("o") } else { $null }
        })
    }

    return , $processList.ToArray()
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

    return , $connectionList.ToArray()
}

function Get-PersistenceRegistry {
    Write-Verbose "Collecting run-key persistence entries..."
    $entries = [System.Collections.Generic.List[PSObject]]::new()

    $targets = @(
        @{ Hive = "LocalMachine"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "LocalMachine"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = "CurrentUser";  Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "CurrentUser";  Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = "LocalMachine"; Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "LocalMachine"; Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" }
    )

    foreach ($target in $targets) {
        $baseKey = $null
        try {
            $baseKey = if ($target.Hive -eq "LocalMachine") {
                [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($target.Path)
            } else {
                [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($target.Path)
            }

            if ($baseKey) {
                foreach ($name in $baseKey.GetValueNames()) {
                    # A value can be empty/null; calling .ToString() on it used to abort
                    # the whole key and silently drop the remaining entries.
                    $rawValue = $baseKey.GetValue($name)
                    $entries.Add([PSCustomObject]@{
                        Hive      = $target.Hive
                        KeyPath   = $target.Path
                        ValueName = $name
                        ValueData = if ($null -ne $rawValue) { [string]$rawValue } else { $null }
                    })
                }
            }
        }
        catch {
            Write-Verbose "Could not read key $($target.Path): $_"
        }
        finally {
            if ($baseKey) { $baseKey.Close() }
        }
    }

    return , $entries.ToArray()
}

function Get-ScheduledTasksTriage {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ()

    Write-Verbose "Collecting active scheduled tasks..."
    $taskList = [System.Collections.Generic.List[PSObject]]::new()
    $suspiciousPattern = '(?i)(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin|\\AppData\\|\\Temp\\|\\Users\\Public\\)'

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }
    }
    catch {
        Write-Warning "Scheduled task enumeration failed: $_"
        return , $taskList.ToArray()
    }

    foreach ($t in $tasks) {
        # Tasks can hold exec actions (Execute/Arguments) or COM handler actions (ClassId).
        # Under StrictMode, reading a property that does not exist throws, which used to
        # abort the whole collection on the first COM-handler task.
        $actionParts = foreach ($action in @($t.Actions)) {
            $props = $action.PSObject.Properties
            if ($props['Execute'] -and $action.Execute) {
                $arguments = if ($props['Arguments']) { $action.Arguments } else { $null }
                "$($action.Execute) $arguments".Trim()
            }
            elseif ($props['ClassId'] -and $action.ClassId) {
                "COM:$($action.ClassId)"
            }
        }
        $actionsStr = @($actionParts) -join '; '

        $taskList.Add([PSCustomObject]@{
            TaskName           = $t.TaskName
            TaskPath           = $t.TaskPath
            State              = $t.State.ToString()
            Author             = if ($t.PSObject.Properties['Author']) { $t.Author } else { $null }
            Actions            = $actionsStr
            IsSuspiciousAction = [bool]($actionsStr -match $suspiciousPattern)
        })
    }

    return , $taskList.ToArray()
}

function Get-ServicesTriage {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ()

    Write-Verbose "Collecting running and auto-start service telemetry..."
    $serviceList = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $services = Get-CimInstance -ClassName Win32_Service -Filter "State = 'Running' OR StartMode = 'Auto'" -ErrorAction Stop
    }
    catch {
        Write-Warning "Get-CimInstance Win32_Service query failed: $_"
        return , $serviceList.ToArray()
    }

    foreach ($svc in $services) {
        $isNonStandardPath = [bool]($svc.PathName -and ($svc.PathName -notmatch '(?i)C:\\Windows\\(System32|SysWOW64|WinSxS)\\'))

        $serviceList.Add([PSCustomObject]@{
            Name              = $svc.Name
            DisplayName       = $svc.DisplayName
            State             = $svc.State
            StartMode         = $svc.StartMode
            PathName          = $svc.PathName
            StartName         = $svc.StartName
            ProcessId         = $svc.ProcessId
            IsNonStandardPath = $isNonStandardPath
        })
    }

    return , $serviceList.ToArray()
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
        LocalAdminMembers = $localAdmins.ToArray()
    }
}

$collectorVersion = "1.1.1"
$isElevated = Test-IsAdministrator

if (-not $isElevated) {
    Write-Warning "Running in non-elevated context. Some low-level system artifacts may be restricted."
}

$executionTimestampUtc = [DateTime]::UtcNow.ToString("o")
$hostName = [System.Environment]::MachineName

Write-Verbose "[+] Initializing IR Triage on host: $hostName (UTC: $executionTimestampUtc)"

$triagePayload = [PSCustomObject]@{
    Metadata = [PSCustomObject]@{
        CollectorVersion  = $collectorVersion
        HostName          = $hostName
        TimestampUtc      = $executionTimestampUtc
        OperatingSystem   = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
        IsElevatedSession = $isElevated
    }
    Processes           = Get-ProcessTriage -ComputeHash:$HashBinaries
    NetworkConnections  = Get-NetworkConnectionsTriage
    PersistenceRegistry = Get-PersistenceRegistry
    ScheduledTasks      = Get-ScheduledTasksTriage
    Services            = Get-ServicesTriage
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

# Sidecar hash file (sha256sum format) so the integrity value travels with the evidence
# instead of living only in the console scrollback.
$hashFilePath = "$destinationPath.sha256"
[System.IO.File]::WriteAllText($hashFilePath, "$($reportHash.ToLowerInvariant())  $outputFileName`n", [System.Text.Encoding]::ASCII)

# Emit a result object (visible in RTR / Live Response consoles and usable in the pipeline).
[PSCustomObject]@{
    Status             = "Completed"
    HostName           = $hostName
    ArtifactPath       = $destinationPath
    SHA256             = $reportHash
    HashFile           = $hashFilePath
    ProcessCount       = @($triagePayload.Processes).Count
    ConnectionCount    = @($triagePayload.NetworkConnections).Count
    PersistenceEntries = @($triagePayload.PersistenceRegistry).Count
    ScheduledTasks     = @($triagePayload.ScheduledTasks).Count
    Services           = @($triagePayload.Services).Count
}
