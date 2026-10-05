#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

BeforeAll {
    $script:ScriptPath = Join-Path -Path $PSScriptRoot -ChildPath '..\src\Invoke-IRTriage.ps1'
}

Describe 'Invoke-IRTriage' {

    Context 'Default run' {
        BeforeAll {
            $script:OutDir = Join-Path -Path $TestDrive -ChildPath 'out'
            $script:Result = & $script:ScriptPath -OutputDirectory $script:OutDir -WarningAction SilentlyContinue
            # Keep the raw text too: ConvertFrom-Json in PowerShell 7 turns ISO dates into [DateTime].
            $script:RawJson = Get-Content -LiteralPath $script:Result.ArtifactPath -Raw
            $script:Report = $script:RawJson | ConvertFrom-Json
        }

        It 'returns a completed result object' {
            $script:Result.Status | Should -Be 'Completed'
        }

        It 'writes the JSON artifact to the output directory' {
            Test-Path -LiteralPath $script:Result.ArtifactPath | Should -BeTrue
        }

        It 'contains every top-level section' {
            $script:Report.PSObject.Properties.Name |
                Should -Be @('Metadata', 'Processes', 'NetworkConnections', 'PersistenceRegistry', 'SecurityPosture')
        }

        It 'collects at least one process' {
            @($script:Report.Processes).Count | Should -BeGreaterThan 0
        }

        It 'writes a sidecar hash file that matches the artifact' {
            $expected = (Get-FileHash -LiteralPath $script:Result.ArtifactPath -Algorithm SHA256).Hash.ToLowerInvariant()
            (Get-Content -LiteralPath $script:Result.HashFile -Raw) | Should -Match "^$expected\s"
        }

        It 'stores the run timestamp as ISO 8601 UTC' {
            $script:RawJson | Should -Match '"TimestampUtc":\s*"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z"'
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
}
