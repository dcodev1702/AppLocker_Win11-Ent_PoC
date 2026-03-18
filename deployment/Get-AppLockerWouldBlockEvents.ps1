<#
.SYNOPSIS
Validates AppLocker audit-only events to identify applications, scripts, installers, or packaged apps that would be blocked if enforcement were enabled.

.DATE
2026-03-17

.AUTHOR
DCODEV1702 & GPT-5.4

.DESCRIPTION
This script queries AppLocker event logs on one or more computers and returns audit-only events that indicate an executable, DLL, MSI, script, or packaged app would have been blocked under an enforced AppLocker policy. It helps validate AppLocker policy impact before moving from audit mode to enforcement.

.NOTES
Intent: Review AppLocker audit results, identify potential enforcement impact, and optionally export findings for analysis or remediation planning.

.PARAMETER DaysBack
Number of days of AppLocker events to search. Default is 7.

.PARAMETER ComputerName
One or more target computer names to query. Default is the local computer.

.PARAMETER PathMatch
Optional text filter that limits results to events whose path or message contains the specified value.

.PARAMETER IncludeMessage
Includes the full event message in the output object.

.PARAMETER DetailedOutput
Displays each event as a formatted list so the blocked file or package is easier to read without table truncation.

.PARAMETER ExportCsv
Exports the collected results to a CSV file.

.PARAMETER CsvPath
Path to the CSV export file. Default is .\AppLocker-AuditWouldBlock.csv.

.EXAMPLE
.\Get-AppLockerWouldBlockEvents.ps1
Queries the local machine for the last 7 days of AppLocker audit-only would-block events.

.EXAMPLE
.\Get-AppLockerWouldBlockEvents.ps1 -DaysBack 3 -PathMatch 'C:\Fonsi' -IncludeMessage
Queries the last 3 days of events and returns only entries related to C:\Fonsi, including the full event message.

.EXAMPLE
.\Get-AppLockerWouldBlockEvents.ps1 -DaysBack 14 -ExportCsv -CsvPath .\AppLocker-Audit.csv
Queries the last 14 days of events and exports the results to a CSV file.

.EXAMPLE
.\Get-AppLockerWouldBlockEvents.ps1 -ComputerName SERVER01,SERVER02 -DaysBack 7
Queries multiple remote computers for AppLocker audit-only would-block events from the last 7 days.

.EXAMPLE
.\Get-AppLockerWouldBlockEvents.ps1 -DetailedOutput
Displays each event as a detailed list including the exact file path or package that would be blocked.

.USAGE
Run the script from PowerShell with any needed parameters to review AppLocker audit-only results before enforcement. Use -ComputerName for remote systems, -PathMatch to narrow results, -IncludeMessage for more detail, and -ExportCsv to save the output.
#>


[CmdletBinding()]
param(
    [int]$DaysBack = 7,
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [string]$PathMatch,
    [switch]$IncludeMessage,
    [switch]$DetailedOutput,
    [switch]$ExportCsv,
    [string]$CsvPath = ".\AppLocker-AuditWouldBlock.csv"
)

$AuditWouldBlockMap = @{
    8003 = 'EXE or DLL would be blocked if enforced'
    8006 = 'MSI or Script would be blocked if enforced'
    8021 = 'Packaged app would be blocked if enforced'
    8024 = 'Packaged app deployment would be blocked if enforced'
}

$Logs = @(
    'Microsoft-Windows-AppLocker/EXE and DLL'
    'Microsoft-Windows-AppLocker/MSI and Script'
    'Microsoft-Windows-AppLocker/Packaged app-Execution'
    'Microsoft-Windows-AppLocker/Packaged app-Deployment'
)

$StartTime = (Get-Date).AddDays(-1 * $DaysBack)

function Get-BlockedItemValue {
    param(
        [hashtable]$EventData,
        [System.Diagnostics.Eventing.Reader.EventRecord]$EventRecord
    )

    foreach ($candidate in @(
        'FilePath',
        'File Name',
        'FileName',
        'Path',
        'Package',
        'PackageFamilyName'
    )) {
        if ($EventData.ContainsKey($candidate) -and $EventData[$candidate]) {
            return $EventData[$candidate]
        }
    }

    $propertyValues = @($EventRecord.Properties | ForEach-Object { $_.Value })

    $stringValues = @(
        $propertyValues |
            Where-Object { $_ -is [string] -and -not [string]::IsNullOrWhiteSpace($_) } |
            Select-Object -Unique
    )

    [array]::Reverse($stringValues)

    foreach ($value in $stringValues) {
        if ($value -match '^(?:[A-Za-z]:\\|%[A-Za-z0-9_]+%\\|\\\\)') {
            return $value
        }

        if ($value -match '^[A-Za-z0-9][A-Za-z0-9._-]*_[A-Za-z0-9._-]+__[A-Za-z0-9]+$') {
            return $value
        }
    }

    return if ($stringValues.Count -gt 0) { $stringValues[0] } else { $null }
}

function Get-AppLockerWouldBlockEvents {
    param(
        [string]$TargetComputer,
        [datetime]$StartTime,
        [string[]]$Logs,
        [hashtable]$IdMap,
        [string]$PathMatch,
        [switch]$IncludeMessage
    )

    foreach ($Log in $Logs) {
        try {
            $Filter = @{
                LogName   = $Log
                Id        = @($IdMap.Keys)
                StartTime = $StartTime
            }

            Get-WinEvent -ComputerName $TargetComputer -FilterHashtable $Filter -ErrorAction Stop |
                ForEach-Object {
                    $xml = [xml]$_.ToXml()

                    $eventData = @{}
                    foreach ($node in $xml.Event.EventData.Data) {
                        if ($node.Name) {
                            $eventData[$node.Name] = $node.'#text'
                        }
                    }

                    $fileOrPackage = Get-BlockedItemValue -EventData $eventData -EventRecord $_

                    if ($PathMatch) {
                        $textToSearch = @(
                            $fileOrPackage
                            $_.Message
                        ) -join ' '

                        if ($textToSearch -notmatch [regex]::Escape($PathMatch)) {
                            return
                        }
                    }

                    [pscustomobject]@{
                        TimeCreated     = $_.TimeCreated
                        ComputerName    = $_.MachineName
                        EventId         = $_.Id
                        LogName         = $_.LogName
                        WouldBlockType  = $IdMap[$_.Id]
                        User            = if ($eventData.ContainsKey('User')) { $eventData['User'] } else { $null }
                        SID             = if ($eventData.ContainsKey('Sid')) { $eventData['Sid'] } else { $null }
                        RuleName        = if ($eventData.ContainsKey('RuleName')) { $eventData['RuleName'] } else { $null }
                        RuleId          = if ($eventData.ContainsKey('RuleId')) { $eventData['RuleId'] } else { $null }
                        BlockedItem     = $fileOrPackage
                        PolicyName      = if ($eventData.ContainsKey('PolicyName')) { $eventData['PolicyName'] } else { $null }
                        Message         = if ($IncludeMessage) { $_.Message } else { $null }
                    }
                }
        }
        catch {
            Write-Warning "[$TargetComputer] Failed to read log '$Log' : $($_.Exception.Message)"
        }
    }
}

$Results = foreach ($Computer in $ComputerName) {
    Get-AppLockerWouldBlockEvents -TargetComputer $Computer `
                                  -StartTime $StartTime `
                                  -Logs $Logs `
                                  -IdMap $AuditWouldBlockMap `
                                  -PathMatch $PathMatch `
                                  -IncludeMessage:$IncludeMessage
}

$Results = $Results |
    Sort-Object TimeCreated -Descending

if (-not $Results) {
    Write-Host "No AppLocker audit-only 'would be blocked if enforced' events found in the last $DaysBack day(s)." -ForegroundColor Yellow
    return
}

if ($DetailedOutput) {
    $Results |
        Select-Object TimeCreated, ComputerName, EventId, WouldBlockType, User, BlockedItem, RuleName, PolicyName, Message |
        Format-List
}
else {
    $Results |
        Select-Object TimeCreated, ComputerName, EventId, WouldBlockType, User, @{Name = 'WhatWouldBeBlocked'; Expression = { $_.BlockedItem } }, RuleName |
        Format-Table -Wrap -AutoSize
}

"`nSummary:`n"
$Results |
    Group-Object WouldBlockType |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize

if ($ExportCsv) {
    $Results | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
    Write-Host "CSV exported to: $CsvPath" -ForegroundColor Green
}
# SIG # Begin signature block
# MIIHogYJKoZIhvcNAQcCoIIHkzCCB48CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCB0Pf6y/UPrfu+K
# KrLpkPwu2oYLko+GF8Q4DTwFnfUY3qCCBGgwggRkMIICzKADAgECAhBVeo1yT3Ey
# oUNaMtF/B39gMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAlVTMRAwDgYDVQQK
# DAdYRFIgTGFiMSkwJwYDVQQDDCBYRFIgTGFiIEFwcExvY2tlciBTY3JpcHQgU2ln
# bmluZzAeFw0yNjAzMTgwNTUwMjhaFw0yODAzMTgwNjAwMjhaMEoxCzAJBgNVBAYT
# AlVTMRAwDgYDVQQKDAdYRFIgTGFiMSkwJwYDVQQDDCBYRFIgTGFiIEFwcExvY2tl
# ciBTY3JpcHQgU2lnbmluZzCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGB
# AMGYdxK8WA0bxBDZJMzgQ2VKR1+RFMLYCQavnqIagHvhf+tPx3a/POIJy7Gf32Me
# 150f/LJeYi8ypOu9kPp5VxdOPE029/pqXaVdUKwRb9zwkpfn3++dIw57s5EF0b7U
# 8w4lzuHCgzifilNl1MKIylOBD+PgnjK0VjAvgaQ8J8mPpqHWIsBEUY0lRkQoUT+K
# UGPoa0eQDnTTreok0GY1XDliS+xtDJbmXlQAQW6lv8HRsTT4siF6egJh2M9HA5h8
# 0VO/5vHJsiq71H0dW4mtgMu+rUBLdgj+cijO0KaauGhwqIyOl/nmol6api4cQomF
# ZxqMN1YSc66BU63PGlVWlctpDaNUW2whfA1WMgu9/Yn/IYCWzy0bLOzfDnCCrRAu
# qaZHnsBe0n3aFf7Rlq9J8U3YhWNKP38TcWktG52k1HsrVrw0z6xWxgzAbQgWerJV
# L75sF5ZN7iBeSCAtLHX1IU9gHYzh5EAx9cJ4LiZt3pCKmjb8tsWGKpizfwi7XMzT
# /QIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFMUgfqv67KkYKizqVxfgGABZ09kfMA0GCSqGSIb3DQEBCwUAA4IB
# gQBaRwDBixHFYBUwYMBn3dnKRb6fN0TKeJlEaHqfVqEMgOXJs4YFPfp/C5PK0f0G
# M9DFGlwH/7Q9ddIdMP2cMOYs3aKjQktFtfWjX5utvzAFwCYZuEoVKxB14hG52Plu
# 70+Pgel3i6SGvxn963boiwEOvAM5PFJfA7WLsW/fY4av9Lg+PyRaBxTRoy3I39CZ
# AYO7otTcPTDKiAGe1eM1uOYundkXvijH8qRuxtM148C+P2kg9vSHZCmdx9PcMg4+
# VcHY/CmaDExLbmuYODhXqKFE2IpTdv2fUc86xvrHq9Icc3c9dc0tQkr0NktbtCSv
# Oqp350wM4tUchM+JNVuQLsq+y5rE0meaUKLqXOYHhc9RFyd0vYYw1XL163yDsFW/
# lGcSjguua0dGEAwCPSEtYjFqBu2vS2OT1wh2lzWpY7X3VtCrIKSRfeBdVBU7Fj0N
# Mbtx9MjzIjllRaor19Uw/zqd4oEmdI6nruqYw4R7N1C2VUSdlGnbV6CccQ+EBXUc
# kNIxggKQMIICjAIBATBeMEoxCzAJBgNVBAYTAlVTMRAwDgYDVQQKDAdYRFIgTGFi
# MSkwJwYDVQQDDCBYRFIgTGFiIEFwcExvY2tlciBTY3JpcHQgU2lnbmluZwIQVXqN
# ck9xMqFDWjLRfwd/YDANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQow
# CKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDR8gITZmv7zxpSbSTi
# Lo4FGDuyv2Wqis/QIwalGAyxyzANBgkqhkiG9w0BAQEFAASCAYACapFJh2dXP1WD
# fC7i8xySQ26NONj/eSWy4r/tUUD84PeoeUNGylfWhxvJk06xwCS52WYQQA+Ndjqs
# z8fyUVJFDDt+tZ/oqS3r+PwoIL0vqk1gdzSst1MPw0Oz4N5rD7OMJd9Zvv8J7DXk
# xhakPTaK0Nlaa6aI7wBhAz6oMOxTmsU64GVydxh17pJimR50WdNZik20AjlVVwWS
# a4uro5BcoFdIK/v4WslmiVwLgjqLDo6gHK33HtT1qLut9zicRoYxgIqbOTs5Za3v
# ooM5pMW4Nvn+/V7Ls+fOFv+30GPD0UiR+o67lsSWdGvNEMbXFIHEOIlCYazg4qRm
# A9qK9XkEBhWqQe5CYCFD/RG87IVg6u1bWBSud4vpNzxcak7F38E+AW/3wrw8wFk/
# C6FJGxK6i0LzDKBk+JphmiKY0dYGFP6JDGu+uuxlj8FH/kftnThQiLbJk2ci+r79
# 9tJeeO0CPe6lG7Y4KZE2Y8rPPTl4S3AQyqR4DsxGL8+bJHGVCGk=
# SIG # End signature block
