<#
.SYNOPSIS
Runs lightweight validation checks for the deployment scripts in this folder.

.DATE
2026-03-18

.AUTHOR
DCODEV1702 & GPT-5.4

.DESCRIPTION
This script performs a lightweight validation pass for the deployment scripts by checking PowerShell parse errors, exercising the ACL hardening workflow on a disposable test folder, and validating the resulting permissions with acl_validation.ps1.

.PARAMETER TestPath
Disposable folder to create and harden during validation.

.PARAMETER BackupFolder
Disposable backup folder used while validating ACL backup and restore prerequisites.

.PARAMETER KeepArtifacts
Retains the test folder and backup folder after validation completes.

.EXAMPLE
.\Invoke-DeploymentValidation.ps1
Parses the deployment scripts and validates the ACL hardening workflow on a disposable folder.
#>
[CmdletBinding()]
param(
    [string]$TestPath = 'C:\Temp\AppLockerAclValidation',
    [string]$BackupFolder = 'C:\Temp\AppLockerAclValidationBackup',
    [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $PSCommandPath
$hardeningScript = Join-Path $scriptDir 'acl_ntfs_hardening.ps1'
$validatorScript = Join-Path $scriptDir 'acl_validation.ps1'

function Remove-ValidationArtifacts {
    param(
        [string[]]$PathsToRemove
    )

    foreach ($item in $PathsToRemove) {
        if (Test-Path -LiteralPath $item) {
            Remove-Item -LiteralPath $item -Recurse -Force
        }
    }
}

$parseResults = foreach ($script in Get-ChildItem -LiteralPath $scriptDir -Filter *.ps1 -File | Sort-Object Name) {
    $tokens = $null
    $parseErrors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$parseErrors)

    [pscustomobject]@{
        Script     = $script.Name
        ParseOk    = $parseErrors.Count -eq 0
        ParseError = ($parseErrors | ForEach-Object { $_.Message }) -join '; '
    }
}

$syntaxFailures = @($parseResults | Where-Object { -not $_.ParseOk })
if ($syntaxFailures) {
    ($syntaxFailures | Format-Table -AutoSize | Out-String).TrimEnd() | Write-Host
    throw 'One or more deployment scripts contain PowerShell parse errors.'
}

try {
    Remove-ValidationArtifacts -PathsToRemove @($TestPath, $BackupFolder)

    & $hardeningScript -Paths $TestPath -BackupFolder $BackupFolder | Out-Null
    $validationResults = & $validatorScript -Paths $TestPath -PassThru
    $unsafeResults = @($validationResults | Where-Object { -not $_.SafeForPathRule })

    $summary = [pscustomobject]@{
        ScriptsParsed      = $parseResults.Count
        TestPath           = $TestPath
        BackupFolder       = $BackupFolder
        HardenedPathSafe   = $unsafeResults.Count -eq 0
        UnsafeFindingCount = $unsafeResults.Count
    }

    ($summary | Format-List | Out-String).TrimEnd() | Write-Host

    if ($unsafeResults) {
        ($unsafeResults | Format-Table -AutoSize | Out-String).TrimEnd() | Write-Host
        throw 'ACL validation reported unsafe findings after hardening the disposable test folder.'
    }

    $validationResults
}
finally {
    if (-not $KeepArtifacts) {
        Remove-ValidationArtifacts -PathsToRemove @($TestPath, $BackupFolder)
    }
}