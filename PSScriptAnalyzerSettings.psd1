@{
    Severity     = @('Error', 'Warning', 'Information')

    ExcludeRules = @(
        # Pester test files set variables in BeforeAll and read them in It blocks,
        # which this rule reports as false positives.
        'PSUseDeclaredVarsMoreThanAssignments'
    )

    Rules        = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.4')
        }
    }
}
