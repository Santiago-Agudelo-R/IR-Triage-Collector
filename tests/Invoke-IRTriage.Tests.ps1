#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\src\Invoke-IRTriage.ps1'
}

Describe 'Invoke-IRTriage' {

    Context 'Default run' {
        BeforeAll {
            $script:OutDir = Join-Path -Path $TestDrive -ChildPath 'out'
            $script:Result = & $script:ScriptPath -OutputDirectory $script:OutDir -WarningAction SilentlyContinue
            $script:RawJson = Get-Content -LiteralPath $script:Result.ArtifactPath -Raw
            $script:Report = $script:RawJson | ConvertFrom-Json
        }

        It 'returns a completed result object with valid semantic version metadata' {
            $script:Result.Status | Should -Be 'Completed'
            $script:Report.Metadata.CollectorVersion | Should -Match '^\d+\.\d+\.\d+$'
        }

        It 'writes the JSON artifact to the output directory' {
            Test-Path -LiteralPath $script:Result.ArtifactPath | Should -BeTrue
        }

        It 'contains every top-level section including WmiPersistence, DnsAndArpCache, and LogonSessions' {
            $script:Report.PSObject.Properties.Name |
                Should -Be @('Metadata', 'Processes', 'NetworkConnections', 'PersistenceRegistry', 'ScheduledTasks', 'Services', 'WmiPersistence', 'DnsAndArpCache', 'LogonSessions', 'SecurityPosture')
        }

        It 'collects processes and evaluates IsMasqueradingSuspect (T1036.005)' {
            @($script:Report.Processes).Count | Should -BeGreaterThan 0
            $firstProc = $script:Report.Processes[0]
            $firstProc.PSObject.Properties.Name | Should -Contain 'IsMasqueradingSuspect'
        }

        It 'collects active TCP/UDP network endpoints without failing when SynSent is empty' {
            @($script:Report.NetworkConnections).Count | Should -BeGreaterThan 0
            $firstConn = $script:Report.NetworkConnections[0]
            $firstConn.PSObject.Properties.Name | Should -Contain 'Protocol'
        }

        It 'collects scheduled tasks (Windows always has enabled built-in tasks)' {
            @($script:Report.ScheduledTasks).Count | Should -BeGreaterThan 0
        }

        It 'collects services and does not false-positive signed binaries in ProgramData (e.g. WinDefend)' {
            @($script:Report.Services).Count | Should -BeGreaterThan 0
            $firstSvc = $script:Report.Services[0]
            $firstSvc.PSObject.Properties.Name | Should -Contain 'ExecutablePath'
            $firstSvc.PSObject.Properties.Name | Should -Contain 'IsAuthenticodeSigned'
            $firstSvc.PSObject.Properties.Name | Should -Contain 'IsSuspiciousService'

            $signedProgramDataSvcs = @($script:Report.Services | Where-Object {
                $_.ExecutablePath -match '(?i)\\ProgramData\\' -and $_.IsAuthenticodeSigned -eq $true
            })
            foreach ($svc in $signedProgramDataSvcs) {
                $svc.IsSuspiciousService | Should -BeFalse
            }
        }

        It 'collects WMI persistence, DNS/ARP cache, and logon session sections with valid structure' {
            $script:Report.PSObject.Properties.Name | Should -Contain 'WmiPersistence'
            $script:Report.DnsAndArpCache.PSObject.Properties.Name | Should -Be @('DnsClientCache', 'DnsTotalEntries', 'DnsTruncated', 'ArpNeighbors', 'ArpTotalEntries', 'ArpTruncated')
            $script:Result.PSObject.Properties.Name | Should -Contain 'WmiSubscriptions'
            $script:Result.PSObject.Properties.Name | Should -Contain 'DnsCacheEntries'
            $script:Result.PSObject.Properties.Name | Should -Contain 'LogonSessions'
        }

        It 'writes a sidecar hash file that matches the artifact' {
            $expected = (Get-FileHash -LiteralPath $script:Result.ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            (Get-Content -LiteralPath $script:Result.HashFile -Raw) | Should -Match "^$expected\s"
        }

        It 'reports DNS and ARP totals and whether each snapshot was truncated' {
            $cache = $script:Report.DnsAndArpCache
            $cache.PSObject.Properties.Name | Should -Contain 'DnsTruncated'
            $cache.PSObject.Properties.Name | Should -Contain 'ArpTruncated'
            $cache.DnsTotalEntries | Should -BeGreaterOrEqual @($cache.DnsClientCache).Count
            $cache.ArpTotalEntries | Should -BeGreaterOrEqual @($cache.ArpNeighbors).Count
        }

        It 'stores the run timestamp as ISO 8601 UTC' {
            $script:RawJson | Should -Match '"TimestampUtc":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"'
        }
    }

    Context 'Test-SystemBinaryMasquerading (T1036.005 unit tests)' {
        BeforeAll {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$null)
            $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Test-SystemBinaryMasquerading' }, $true)
            . ([scriptblock]::Create($fn.Extent.Text))
        }

        It 'returns false for legitimate System32 svchost.exe and explorer.exe in SystemRoot' {
            $sysRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
            Test-SystemBinaryMasquerading -ProcessName 'svchost.exe' -ExecutablePath "$sysRoot\System32\svchost.exe" | Should -BeFalse
            Test-SystemBinaryMasquerading -ProcessName 'explorer.exe' -ExecutablePath "$sysRoot\explorer.exe" | Should -BeFalse
        }

        It 'returns true when svchost.exe or lsass.exe executes from a non-system directory' {
            Test-SystemBinaryMasquerading -ProcessName 'svchost.exe' -ExecutablePath 'C:\Users\Public\svchost.exe' | Should -BeTrue
            Test-SystemBinaryMasquerading -ProcessName 'lsass.exe' -ExecutablePath 'C:\ProgramData\lsass.exe' | Should -BeTrue
        }
    }

    Context 'Non-US locale (regression: es-CO date parsing)' {
        It 'does not fail and keeps process dates in ISO 8601 UTC' {
            $original = [System.Globalization.CultureInfo]::CurrentCulture
            try {
                [System.Globalization.CultureInfo]::CurrentCulture = 'es-CO'
                $outDir = Join-Path -Path $TestDrive -ChildPath 'es-CO'
                $result = & $script:ScriptPath -OutputDirectory $outDir -WarningAction SilentlyContinue
            }
            finally {
                [System.Globalization.CultureInfo]::CurrentCulture = $original
            }

            $raw = Get-Content -LiteralPath $result.ArtifactPath -Raw
            $dates = [regex]::Matches($raw, '"CreationDateUtc":\s*"([^"]+)"')
            $dates.Count | Should -BeGreaterThan 0
            foreach ($d in $dates) {
                $d.Groups[1].Value | Should -Match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z$'
            }
        }
    }

    Context 'Offline user hives (-MountOfflineUserHives)' {
        It 'completes and leaves no temporary hive mounted or copied' {
            $outDir = Join-Path -Path $TestDrive -ChildPath 'offline'
            $result = & $script:ScriptPath -OutputDirectory $outDir -MountOfflineUserHives -WarningAction SilentlyContinue
            $result.Status | Should -Be 'Completed'

            @([Microsoft.Win32.Registry]::Users.GetSubKeyNames() | Where-Object { $_ -like 'IR_Offline_*' }).Count | Should -Be 0
            @(Get-ChildItem -LiteralPath ([System.IO.Path]::GetTempPath()) -Directory -Filter 'IRTriageHive_*' -ErrorAction SilentlyContinue).Count | Should -Be 0
        }
    }
}
