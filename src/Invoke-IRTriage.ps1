<#
.SYNOPSIS
    Gathers volatile endpoint forensic triage data for live incident response.

.DESCRIPTION
    Invoke-IRTriage collects running process metadata (including Authenticode signatures,
    optional SHA256 hashes, and system binary masquerading checks), active TCP and UDP network
    endpoints, registry Run/RunOnce persistence across HKLM, HKCU, and loaded HKEY_USERS user
    hives (with optional offline NTUSER.DAT mounting), active scheduled tasks, running and
    auto-start services, WMI event subscriptions, DNS/ARP caches, interactive logon sessions,
    and local security posture.

    Designed for incident response execution via CrowdStrike Real Time Response (RTR),
    Microsoft Defender Live Response, WinRM, or local administrative sessions.
    All timestamps are recorded in UTC (ISO 8601). Output is exported to a JSON artifact
    and the SHA256 digest is returned directly to the remote console stream for off-host
    chain-of-custody verification.

.PARAMETER OutputDirectory
    Directory where the triage JSON report will be saved. Defaults to "$PSScriptRoot\TriageOutput"
    when invoked from a file, or "$env:TEMP\IRTriageOutput" when pasted into an interactive console.

.PARAMETER HashBinaries
    Switch parameter. When enabled, computes SHA256 hashes of running executable binaries.

.PARAMETER MountOfflineUserHives
    Switch parameter. When enabled in an elevated session, copies the NTUSER.DAT (and .LOG1/.LOG2)
    of each local profile that is not currently loaded to a temporary folder, loads the COPY under
    HKEY_USERS to read its Run/RunOnce keys, then unloads and deletes it. The original hive files
    are never loaded, because 'reg load' opens a hive read-write. Copying still updates the source
    files' last-access time on volumes where that is enabled.

.NOTES
    Author: Santiago Agudelo
    License: MIT
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory = $(if ($PSScriptRoot) { Join-Path $PSScriptRoot 'TriageOutput' } elseif ($env:TEMP) { Join-Path $env:TEMP 'IRTriageOutput' } else { 'C:\Windows\Temp\IRTriageOutput' }),

    [Parameter(Mandatory = $false)]
    [switch]$HashBinaries,

    [Parameter(Mandatory = $false)]
    [switch]$MountOfflineUserHives
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-ServiceExecutablePath {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PathName
    )

    if ([string]::IsNullOrWhiteSpace($PathName)) {
        return $null
    }

    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"')) {
        $closingQuote = $trimmed.IndexOf('"', 1)
        if ($closingQuote -gt 1) {
            return $trimmed.Substring(1, $closingQuote - 1)
        }
    }

    if ($trimmed -match '^(?i)([a-z]:\\[^\r\n]+?\.(?:exe|sys|dll))\b') {
        return $Matches[1]
    }

    return ($trimmed -split '\s+')[0]
}

function Test-SystemBinaryMasquerading {
    <#
        Detects MITRE ATT&CK T1036.005 (Match Legitimate Name or Location):
        Flags processes named after core Windows system executables whose ExecutablePath
        resides outside standard %SystemRoot% system directories.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$ProcessName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$ExecutablePath
    )

    if ([string]::IsNullOrWhiteSpace($ProcessName) -or [string]::IsNullOrWhiteSpace($ExecutablePath)) {
        return $false
    }

    $coreSystemBinaries = @(
        'svchost.exe',
        'lsass.exe',
        'csrss.exe',
        'services.exe',
        'smss.exe',
        'wininit.exe',
        'winlogon.exe',
        'lsm.exe',
        'RuntimeBroker.exe',
        'taskhostw.exe',
        'dllhost.exe',
        'conhost.exe'
    )

    $sysRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
    $escapedRoot = [regex]::Escape($sysRoot)

    if ($ProcessName -ieq 'explorer.exe') {
        return ($ExecutablePath -notmatch "^(?i)${escapedRoot}\\(explorer\.exe|SysWOW64\\explorer\.exe)$")
    }

    if ($ProcessName -in $coreSystemBinaries) {
        return ($ExecutablePath -notmatch "^(?i)${escapedRoot}\\(System32|SysWOW64|WinSxS)\\")
    }

    return $false
}

function Get-ProcessTriage {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ([switch]$ComputeHash)

    Write-Verbose "Collecting running process telemetry..."
    $processList = [System.Collections.Generic.List[PSObject]]::new()
    $processes = Get-CimInstance -ClassName Win32_Process
    $highRiskPatterns = @('\\AppData\\', '\\Temp\\', '\\Users\\Public\\', '\\ProgramData\\[^\\]+\.exe$')

    $binaryCache = @{}

    foreach ($proc in $processes) {
        $binaryPath = $proc.ExecutablePath
        $sha256 = "N/A"
        $isSigned = $null

        if (-not [string]::IsNullOrWhiteSpace($binaryPath) -and (Test-Path -LiteralPath $binaryPath -PathType Leaf)) {
            if (-not $binaryCache.ContainsKey($binaryPath)) {
                $entry = @{ SHA256 = "N/A"; IsSigned = $false }

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

        $isMasquerading = Test-SystemBinaryMasquerading -ProcessName $proc.Name -ExecutablePath $binaryPath

        $processList.Add([PSCustomObject]@{
            ProcessId              = $proc.ProcessId
            ParentProcessId        = $proc.ParentProcessId
            Name                   = $proc.Name
            CommandLine            = $proc.CommandLine
            ExecutablePath         = $binaryPath
            SHA256                 = $sha256
            IsAuthenticodeSigned   = $isSigned
            IsHighRiskLocation     = $isHighRiskLocation
            IsMasqueradingSuspect  = $isMasquerading
            CreationDateUtc        = if ($proc.CreationDate) { ([DateTime]$proc.CreationDate).ToUniversalTime().ToString("o") } else { $null }
        })
    }

    return , $processList.ToArray()
}

function Get-NetworkConnectionsTriage {
    Write-Verbose "Collecting TCP and UDP network endpoint telemetry..."
    $connectionList = [System.Collections.Generic.List[PSObject]]::new()

    try {
        # Filter State post-query: passing -State SynSent with -ErrorAction Stop throws a CIM error
        # when zero sockets are currently in SynSent state, which would discard Established/Listen sockets.
        $tcpConns = Get-NetTCPConnection -ErrorAction Stop | Where-Object { $_.State -in @('Established', 'Listen', 'SynSent') }
        foreach ($conn in $tcpConns) {
            $connectionList.Add([PSCustomObject]@{
                Protocol      = 'TCP'
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

    if (Get-Command -Name Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        try {
            $udpEndpoints = Get-NetUDPEndpoint -ErrorAction Stop
            foreach ($udp in $udpEndpoints) {
                $connectionList.Add([PSCustomObject]@{
                    Protocol      = 'UDP'
                    LocalAddress  = $udp.LocalAddress
                    LocalPort     = $udp.LocalPort
                    RemoteAddress = '*'
                    RemotePort    = 0
                    State         = 'Listen'
                    OwningProcess = $udp.OwningProcess
                })
            }
        }
        catch {
            Write-Verbose "Get-NetUDPEndpoint query failed: $_"
        }
    }

    return , $connectionList.ToArray()
}

function Read-RegistryRunSubKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.Win32.RegistryKey]$RootKey,

        [Parameter(Mandatory = $true)]
        [string]$HiveLabel,

        [Parameter(Mandatory = $true)]
        [string]$SubKeyPath,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[PSObject]]$Collector
    )

    $subKey = $null
    try {
        $subKey = $RootKey.OpenSubKey($SubKeyPath)
        if ($subKey) {
            foreach ($name in $subKey.GetValueNames()) {
                $rawValue = $subKey.GetValue($name)
                $Collector.Add([PSCustomObject]@{
                    Hive      = $HiveLabel
                    KeyPath   = $SubKeyPath
                    ValueName = $name
                    ValueData = if ($null -ne $rawValue) { [string]$rawValue } else { $null }
                })
            }
        }
    }
    catch {
        Write-Verbose "Could not read key ${HiveLabel}\${SubKeyPath}: $_"
    }
    finally {
        if ($subKey) { $subKey.Close() }
    }
}

function Get-PersistenceRegistry {
    [CmdletBinding()]
    [OutputType([object[]])]
    param (
        [switch]$MountOfflineHives,
        [bool]$IsElevated = $false
    )

    Write-Verbose "Collecting run-key persistence across HKLM, HKCU, and loaded HKEY_USERS hives..."
    $entries = [System.Collections.Generic.List[PSObject]]::new()

    $runPaths = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($p in $runPaths) {
        Read-RegistryRunSubKey -RootKey ([Microsoft.Win32.Registry]::LocalMachine) -HiveLabel "LocalMachine" -SubKeyPath $p -Collector $entries
    }

    $userRunPaths = @(
        "Software\Microsoft\Windows\CurrentVersion\Run",
        "Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($p in $userRunPaths) {
        Read-RegistryRunSubKey -RootKey ([Microsoft.Win32.Registry]::CurrentUser) -HiveLabel "CurrentUser" -SubKeyPath $p -Collector $entries
    }

    # Enumerate all loaded user SIDs in HKEY_USERS so running as NT AUTHORITY\SYSTEM in
    # CrowdStrike RTR or Defender Live Response still captures logged-on user Run keys.
    $loadedSids = @{}
    try {
        $hkuNames = [Microsoft.Win32.Registry]::Users.GetSubKeyNames()
        foreach ($sid in $hkuNames) {
            if ($sid -match '^S-1-5-21-\d+-\d+-\d+-\d+$') {
                $loadedSids[$sid] = $true
                foreach ($p in $userRunPaths) {
                    Read-RegistryRunSubKey -RootKey ([Microsoft.Win32.Registry]::Users) -HiveLabel "HKEY_USERS\$sid" -SubKeyPath "$sid\$p" -Collector $entries
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not enumerate HKEY_USERS: $_"
    }

    # Optionally mount offline user profile NTUSER.DAT hives when running elevated
    if ($MountOfflineHives -and $IsElevated) {
        try {
            $profileListKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
            if ($profileListKey) {
                foreach ($sid in $profileListKey.GetSubKeyNames()) {
                    if ($sid -match '^S-1-5-21-\d+-\d+-\d+-\d+$' -and (-not $loadedSids.ContainsKey($sid))) {
                        $profSub = $profileListKey.OpenSubKey($sid)
                        $profPath = if ($profSub) { [string]$profSub.GetValue("ProfileImagePath") } else { $null }
                        if ($profSub) { $profSub.Close() }

                        if ($profPath) {
                            # ProfileImagePath is usually REG_EXPAND_SZ (%SystemDrive%\Users\...).
                            $profPath = [System.Environment]::ExpandEnvironmentVariables($profPath)
                            $ntUserDat = Join-Path $profPath "NTUSER.DAT"
                            if (Test-Path -LiteralPath $ntUserDat -PathType Leaf) {
                                # 'reg load' opens a hive read-write and can replay pending transaction logs
                                # into it. To leave the original evidence untouched, load a temporary copy of
                                # NTUSER.DAT (plus its .LOG1/.LOG2 files) instead of the file itself.
                                $copyDir = Join-Path ([System.IO.Path]::GetTempPath()) "IRTriageHive_$([guid]::NewGuid().ToString('N'))"
                                $tempMountName = "IR_Offline_$sid"
                                $mounted = $false
                                try {
                                    $null = New-Item -ItemType Directory -Path $copyDir -Force
                                    foreach ($hiveFile in @(Get-ChildItem -LiteralPath $profPath -Filter 'NTUSER.DAT*' -File -Force -ErrorAction Stop |
                                            Where-Object { $_.Name -match '^(?i)NTUSER\.DAT(\.LOG[12])?$' })) {
                                        Copy-Item -LiteralPath $hiveFile.FullName -Destination $copyDir -Force -ErrorAction Stop
                                    }

                                    $null = & reg.exe load "HKU\$tempMountName" (Join-Path $copyDir 'NTUSER.DAT') 2>$null
                                    $mounted = ($LASTEXITCODE -eq 0)
                                    if ($mounted) {
                                        foreach ($p in $userRunPaths) {
                                            Read-RegistryRunSubKey -RootKey ([Microsoft.Win32.Registry]::Users) -HiveLabel "OfflineHiveCopy\$sid" -SubKeyPath "$tempMountName\$p" -Collector $entries
                                        }
                                    }
                                }
                                catch {
                                    Write-Verbose "Could not inspect offline hive for ${sid}: $_"
                                }
                                finally {
                                    if ($mounted) {
                                        [System.GC]::Collect()
                                        [System.GC]::WaitForPendingFinalizers()
                                        $null = & reg.exe unload "HKU\$tempMountName" 2>$null
                                    }
                                    Remove-Item -LiteralPath $copyDir -Recurse -Force -ErrorAction SilentlyContinue
                                }
                            }
                        }
                    }
                }
                $profileListKey.Close()
            }
        }
        catch {
            Write-Verbose "Offline NTUSER.DAT inspection encountered an error: $_"
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
    $sigCache = @{}
    $userWritablePattern = '(?i)(\\AppData\\|\\Temp\\|\\Users\\Public\\)'
    $sysRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
    $escapedSysRoot = [regex]::Escape($sysRoot)

    try {
        $services = Get-CimInstance -ClassName Win32_Service -Filter "State = 'Running' OR StartMode = 'Auto'" -ErrorAction Stop
    }
    catch {
        Write-Warning "Get-CimInstance Win32_Service query failed: $_"
        return , $serviceList.ToArray()
    }

    foreach ($svc in $services) {
        $exePath = Resolve-ServiceExecutablePath -PathName $svc.PathName
        $isNonStandardPath = [bool]($svc.PathName -and ($svc.PathName -notmatch "(?i)${escapedSysRoot}\\(System32|SysWOW64|WinSxS)\\"))
        $isSigned = $null

        if (-not [string]::IsNullOrWhiteSpace($exePath) -and (Test-Path -LiteralPath $exePath -PathType Leaf)) {
            if (-not $sigCache.ContainsKey($exePath)) {
                try {
                    $sig = Get-AuthenticodeSignature -LiteralPath $exePath -ErrorAction Stop
                    $sigCache[$exePath] = ($sig.Status -eq [System.Management.Automation.SignatureStatus]::Valid)
                }
                catch {
                    $sigCache[$exePath] = $false
                }
            }
            $isSigned = $sigCache[$exePath]
        }

        $isUserWritablePath = [bool]($svc.PathName -and ($svc.PathName -match $userWritablePattern))
        $isSuspiciousService = [bool]($isUserWritablePath -or ($isNonStandardPath -and ($isSigned -eq $false)))

        $serviceList.Add([PSCustomObject]@{
            Name                 = $svc.Name
            DisplayName          = $svc.DisplayName
            State                = $svc.State
            StartMode            = $svc.StartMode
            PathName             = $svc.PathName
            ExecutablePath       = $exePath
            StartName            = $svc.StartName
            ProcessId            = $svc.ProcessId
            IsNonStandardPath    = $isNonStandardPath
            IsAuthenticodeSigned = $isSigned
            IsSuspiciousService  = $isSuspiciousService
        })
    }

    return , $serviceList.ToArray()
}

function Get-WmiPersistenceTriage {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ()

    Write-Verbose "Collecting WMI event subscription persistence (root\subscription)..."
    $wmiList = [System.Collections.Generic.List[PSObject]]::new()

    try {
        $filters = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop)
        $consumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventConsumer' -ErrorAction Stop)
        $bindings = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)

        foreach ($f in $filters) {
            $wmiList.Add([PSCustomObject]@{
                ArtifactType      = 'EventFilter'
                Name              = $f.Name
                Query             = $f.Query
                EventNamespace    = $f.EventNamespace
                CommandLineOrBody = $null
                IsSuspiciousWmi   = [bool]($f.Query -match '(?i)(Win32_ProcessStartTrace|Win32_LogonSession|powershell|cmd\.exe)')
            })
        }

        foreach ($c in $consumers) {
            $className = $c.CimClass.CimClassName
            $body = if ($c.PSObject.Properties['CommandLineTemplate']) {
                [string]$c.CommandLineTemplate
            }
            elseif ($c.PSObject.Properties['ScriptText']) {
                [string]$c.ScriptText
            }
            else {
                $null
            }
            $isStandardScm = ($className -eq 'NTEventLogEventConsumer' -and $c.Name -eq 'SCM Event Log Consumer')
            $wmiList.Add([PSCustomObject]@{
                ArtifactType      = $className
                Name              = $c.Name
                Query             = $null
                EventNamespace    = $null
                CommandLineOrBody = $body
                IsSuspiciousWmi   = (-not $isStandardScm)
            })
        }

        foreach ($b in $bindings) {
            $filterRef = [string]$b.Filter
            $consumerRef = [string]$b.Consumer
            $isStandardBinding = ($consumerRef -match 'SCM Event Log Consumer')
            $wmiList.Add([PSCustomObject]@{
                ArtifactType      = 'FilterToConsumerBinding'
                Name              = "$filterRef -> $consumerRef"
                Query             = $null
                EventNamespace    = $null
                CommandLineOrBody = $consumerRef
                IsSuspiciousWmi   = (-not $isStandardBinding)
            })
        }
    }
    catch {
        Write-Verbose "WMI subscription query encountered an error: $_"
    }

    return , $wmiList.ToArray()
}

function Get-DnsAndArpCacheTriage {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param ()

    Write-Verbose "Collecting DNS client cache and ARP neighbor snapshots..."
    $dnsEntries = [System.Collections.Generic.List[PSObject]]::new()
    $arpEntries = [System.Collections.Generic.List[PSObject]]::new()

    if (Get-Command -Name Get-DnsClientCache -ErrorAction SilentlyContinue) {
        try {
            $rawDns = Get-DnsClientCache -ErrorAction Stop | Select-Object -First 250
            foreach ($d in $rawDns) {
                $dnsEntries.Add([PSCustomObject]@{
                    Entry      = [string]$d.Entry
                    RecordName = [string]$d.Name
                    Data       = [string]$d.Data
                    TimeToLive = $d.TimeToLive
                })
            }
        }
        catch {
            Write-Verbose "Get-DnsClientCache query failed: $_"
        }
    }

    if (Get-Command -Name Get-NetNeighbor -ErrorAction SilentlyContinue) {
        try {
            $rawArp = Get-NetNeighbor -ErrorAction Stop | Where-Object { $_.State -in @('Reachable', 'Stale', 'Delay', 'Probe', 'Permanent') } | Select-Object -First 250
            foreach ($n in $rawArp) {
                $arpEntries.Add([PSCustomObject]@{
                    IPAddress        = [string]$n.IPAddress
                    LinkLayerAddress = [string]$n.LinkLayerAddress
                    State            = $n.State.ToString()
                    InterfaceAlias   = [string]$n.InterfaceAlias
                })
            }
        }
        catch {
            Write-Verbose "Get-NetNeighbor query failed: $_"
        }
    }

    return [PSCustomObject]@{
        DnsClientCache = $dnsEntries.ToArray()
        ArpNeighbors   = $arpEntries.ToArray()
    }
}

function Get-LogonSessionTriage {
    [CmdletBinding()]
    [OutputType([object[]])]
    param ()

    Write-Verbose "Collecting interactive and remote logon sessions..."
    $sessionList = [System.Collections.Generic.List[PSObject]]::new()

    try {
        # LogonType 2 = Interactive, 10 = RemoteInteractive (RDP), 11 = CachedInteractive
        $sessions = @(Get-CimInstance -ClassName Win32_LogonSession -Filter "LogonType = 2 OR LogonType = 10 OR LogonType = 11" -ErrorAction Stop)
        foreach ($s in $sessions) {
            # Win32_LoggedOnUser links each session to its account; without it a session has no owner.
            $account = $null
            try {
                $acct = Get-CimAssociatedInstance -InputObject $s -Association Win32_LoggedOnUser -ErrorAction Stop | Select-Object -First 1
                if ($acct) { $account = "$($acct.Domain)\$($acct.Name)" }
            }
            catch {
                Write-Verbose "Could not resolve account for logon session $($s.LogonId): $_"
            }

            $sessionList.Add([PSCustomObject]@{
                LogonId               = [string]$s.LogonId
                Account               = $account
                LogonType             = [int]$s.LogonType
                AuthenticationPackage = [string]$s.AuthenticationPackage
                StartTimeUtc          = if ($s.StartTime) { ([DateTime]$s.StartTime).ToUniversalTime().ToString("o") } else { $null }
            })
        }
    }
    catch {
        Write-Verbose "Win32_LogonSession query failed: $_"
    }

    return , $sessionList.ToArray()
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
        $members = Get-LocalGroupMember -SID "S-1-5-32-544" -ErrorAction Stop
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

$collectorVersion = "1.2.1"
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
    PersistenceRegistry = Get-PersistenceRegistry -MountOfflineHives:$MountOfflineUserHives -IsElevated $isElevated
    ScheduledTasks      = Get-ScheduledTasksTriage
    Services            = Get-ServicesTriage
    WmiPersistence      = Get-WmiPersistenceTriage
    DnsAndArpCache      = Get-DnsAndArpCacheTriage
    LogonSessions       = Get-LogonSessionTriage
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

$hashFilePath = "$destinationPath.sha256"
[System.IO.File]::WriteAllText($hashFilePath, "$($reportHash.ToLowerInvariant())  $outputFileName`n", [System.Text.Encoding]::ASCII)

# Emit a result object directly to the remote console / RTR stdout stream so the SHA256 digest
# is recorded off-host in the EDR audit log before artifact retrieval.
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
    WmiSubscriptions   = @($triagePayload.WmiPersistence).Count
    DnsCacheEntries    = @($triagePayload.DnsAndArpCache.DnsClientCache).Count
    LogonSessions      = @($triagePayload.LogonSessions).Count
}
