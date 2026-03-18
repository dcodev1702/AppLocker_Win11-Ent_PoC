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