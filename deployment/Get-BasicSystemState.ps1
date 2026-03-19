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

function Get-DomainRoleDisplay {
    param(
        [int]$DomainRole
    )

    $roleName = switch ($DomainRole) {
        0 { 'Standalone Workstation' }
        1 { 'Member Workstation' }
        2 { 'Standalone Server' }
        3 { 'Member Server' }
        4 { 'Backup Domain Controller' }
        5 { 'Primary Domain Controller' }
        default { 'Unknown Role' }
    }

    '{0} ({1})' -f $roleName, $DomainRole
}

function Get-DomainRoleSummary {
    param(
        [int]$DomainRole
    )

    switch ($DomainRole) {
        0 { 'This system is a local-only workstation and is not joined to a domain.' }
        1 { 'This system is a domain-joined workstation.' }
        2 { 'This system is a standalone server and is not joined to a domain.' }
        3 { 'This system is a domain-joined member server.' }
        4 { 'This system is a backup domain controller.' }
        5 { 'This system is the primary domain controller.' }
        default { 'The domain role could not be translated.' }
    }
}

function Get-ActiveInteractiveSession {
    param(
        [string[]]$InteractiveSessions
    )

    foreach ($session in $InteractiveSessions) {
        if ($session -match '^\s*>?(?<User>\S+)\s+(?<SessionName>(console|rdp\-tcp[^\s]*))\s+\d+\s+Active\b') {
            $sessionType = if ($matches.SessionName -ieq 'console') { 'Console' } else { 'RDP' }

            return [pscustomobject]@{
                User        = $matches.User
                SessionName = $matches.SessionName
                SessionType = $sessionType
            }
        }
    }

    return $null
}

function Resolve-LoggedOnUser {
    param(
        [string]$CurrentUser,
        [psobject]$ActiveSession,
        [string]$FallbackUser
    )

    if ($ActiveSession) {
        $sessionUser = $ActiveSession.User
        if ($CurrentUser -and $CurrentUser -match '\\' -and (($CurrentUser -split '\\')[-1]) -ieq $sessionUser) {
            return $CurrentUser
        }

        if ($FallbackUser -and $FallbackUser -match '\\' -and (($FallbackUser -split '\\')[-1]) -ieq $sessionUser) {
            return $FallbackUser
        }

        return $sessionUser
    }

    if ($FallbackUser) {
        return $FallbackUser
    }

    return $null
}

function Get-LoggedOnUserScope {
    param(
        [string]$LoggedOnUser,
        [string]$ComputerName,
        [string]$Domain,
        [bool]$PartOfDomain
    )

    if (-not $LoggedOnUser) {
        return 'Unknown'
    }

    if ($LoggedOnUser -notmatch '\\') {
        if ($PartOfDomain) {
            return 'Unknown'
        }

        return 'Local'
    }

    $accountDomain = ($LoggedOnUser -split '\\')[0]
    if ($accountDomain -eq '.' -or $accountDomain -ieq $ComputerName) {
        return 'Local'
    }

    if ($PartOfDomain -and $accountDomain -ieq $Domain) {
        return 'Domain'
    }

    return 'Domain'
}

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
$activeInteractiveSession = Get-ActiveInteractiveSession -InteractiveSessions $interactiveSessions
$loggedOnUser = Resolve-LoggedOnUser -CurrentUser $currentUser -ActiveSession $activeInteractiveSession -FallbackUser $computerSystem.UserName
$loggedOnUserScope = Get-LoggedOnUserScope -LoggedOnUser $loggedOnUser -ComputerName $env:COMPUTERNAME -Domain $computerSystem.Domain -PartOfDomain $computerSystem.PartOfDomain
$loggedOnSessionType = if ($activeInteractiveSession) { $activeInteractiveSession.SessionType } else { 'Unknown' }

if (-not $loggedOnUser) {
    $loggedOnUser = 'Unable to determine logged on user'
    $loggedOnUserScope = 'Unknown'
}

if (-not $interactiveSessions) {
    $interactiveSessions = @('No interactive sessions reported by query user.')
}

$computerSystem |
    Select-Object -Property @(
        @{Name = 'ComputerName'; Expression = { $env:COMPUTERNAME }},
        @{Name = 'Domain'; Expression = { $_.Domain }},
        @{Name = 'PartOfDomain'; Expression = { $_.PartOfDomain }},
        @{Name = 'DomainRole'; Expression = { Get-DomainRoleDisplay -DomainRole $_.DomainRole }},
        @{Name = 'DomainRoleSummary'; Expression = { Get-DomainRoleSummary -DomainRole $_.DomainRole }},
        @{Name = 'Manufacturer'; Expression = { $_.Manufacturer }},
        @{Name = 'Model'; Expression = { $_.Model }},
        @{Name = 'LoggedOnUser'; Expression = { $loggedOnUser }},
        @{Name = 'LoggedOnUserScope'; Expression = { $loggedOnUserScope }},
        @{Name = 'LoggedOnSessionType'; Expression = { $loggedOnSessionType }},
        @{Name = 'CurrentUser'; Expression = { $currentUser }},
        @{Name = 'LanguageMode'; Expression = { $languageMode }},
        @{Name = 'OperatingSystem'; Expression = { $operatingSystem.Caption }},
        @{Name = 'BuildNumber'; Expression = { $operatingSystem.BuildNumber }},
        @{Name = 'LastBootUpTime'; Expression = { $operatingSystem.LastBootUpTime }},
        @{Name = 'InteractiveUsers'; Expression = { $interactiveSessions -join "`r`n" }}
    ) |
    Format-List
