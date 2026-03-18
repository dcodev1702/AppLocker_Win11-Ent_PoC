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

$interactiveSessions = @(query user 2>$null | Select-Object -Skip 1)
if (-not $interactiveSessions) {
    $interactiveSessions = @('No interactive sessions reported by query user.')
}

[pscustomobject]@{
    ComputerName      = $env:COMPUTERNAME
    Domain            = $computerSystem.Domain
    PartOfDomain      = $computerSystem.PartOfDomain
    DomainRole        = $computerSystem.DomainRole
    Manufacturer      = $computerSystem.Manufacturer
    Model             = $computerSystem.Model
    LoggedOnUser      = $computerSystem.UserName
    CurrentUser       = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    OperatingSystem   = $operatingSystem.Caption
    BuildNumber       = $operatingSystem.BuildNumber
    LastBootUpTime    = $operatingSystem.LastBootUpTime
    InteractiveUsers  = ($interactiveSessions -join [Environment]::NewLine)
} | Format-List