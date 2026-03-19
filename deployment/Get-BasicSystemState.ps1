<#
.SYNOPSIS
Displays basic host, domain, and logon state for AppLocker testing.

.DESCRIPTION
Returns a small set of system details that make it easy to confirm who is signed in,
whether the device is domain joined, and what user sessions are active. This file is
intentionally left unsigned so it can be used to validate that unsigned scripts in
user-writable locations are blocked by AppLocker enforcement.
#>

[CmdletBinding()]
param()

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
$currentUser = whoami 2>$null
$languageMode = $ExecutionContext.SessionState.LanguageMode

if (-not $currentUser) {
    $currentUser = 'Unable to determine current user'
}

if ($languageMode -eq 'ConstrainedLanguage') {
    Write-Host 'Running in Constrained Language Mode (CLM)' -ForegroundColor Cyan
    Write-Host 'This is expected when AppLocker is enforcing and the script is untrusted.' -ForegroundColor DarkCyan
}
elseif ($languageMode -eq 'FullLanguage') {
    Write-Host 'Running in Full Language Mode' -ForegroundColor Gray
    Write-Host 'This can happen when the script is trusted by policy or script enforcement is not active.' -ForegroundColor DarkGray
}

$interactiveSessions = @(query user 2>$null | Select-Object -Skip 1)
if (-not $interactiveSessions) {
    $interactiveSessions = @('No interactive sessions reported by query user.')
}

$computerSystem |
    Select-Object -Property @(
        @{Name = 'ComputerName'; Expression = { $env:COMPUTERNAME }},
        @{Name = 'Domain'; Expression = { $_.Domain }},
        @{Name = 'PartOfDomain'; Expression = { $_.PartOfDomain }},
        @{Name = 'DomainRole'; Expression = { $_.DomainRole }},
        @{Name = 'Manufacturer'; Expression = { $_.Manufacturer }},
        @{Name = 'Model'; Expression = { $_.Model }},
        @{Name = 'LoggedOnUser'; Expression = { $_.UserName }},
        @{Name = 'CurrentUser'; Expression = { $currentUser }},
        @{Name = 'LanguageMode'; Expression = { $languageMode }},
        @{Name = 'OperatingSystem'; Expression = { $operatingSystem.Caption }},
        @{Name = 'BuildNumber'; Expression = { $operatingSystem.BuildNumber }},
        @{Name = 'LastBootUpTime'; Expression = { $operatingSystem.LastBootUpTime }},
        @{Name = 'InteractiveUsers'; Expression = { $interactiveSessions -join "`r`n" }}
    ) |
    Format-List
