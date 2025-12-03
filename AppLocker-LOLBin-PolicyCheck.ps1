<#
.SYNOPSIS
    AppLocker LOLBin Block Validation Tests
    
.DESCRIPTION
    Tests to validate that AppLocker is properly blocking Microsoft-recommended
    LOLBins commonly abused by threat actors.
    
    These are SAFE, benign commands that simply test if the binaries can execute.
    If AppLocker is working correctly, each test should FAIL with an access denied error.
    
    Works in both Enforce and Audit modes by checking event IDs:
      8003 = Allowed (audit mode will log this for items that would be blocked)
      8004 = Blocked (enforce mode)
      8006 = Policy applied
      8007 = Policy not applied
    
.NOTES
    Author: DCODEV1702 & Claude Opus 4.5
    Date: 2 December 2025
    
    Run from a non-admin user account to properly test the policy.
    Administrators typically have a blanket allow rule.
#>

param(
    [switch]$Verbose
)

$ErrorActionPreference = "SilentlyContinue"

# AppLocker Event IDs to check
$AppLockerEventIDs = @(8003, 8004, 8006, 8007)

# Colors for output
function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Blocked,
        [string]$Details,
        [string]$EventInfo
    )
    
    if ($Blocked) {
        Write-Host "[PASS] " -ForegroundColor Green -NoNewline
        Write-Host "$TestName - " -NoNewline
        Write-Host "BLOCKED" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] " -ForegroundColor Red -NoNewline
        Write-Host "$TestName - " -NoNewline
        Write-Host "NOT BLOCKED - Policy may not be applied!" -ForegroundColor Red
    }
    
    if ($Verbose -and $Details) {
        Write-Host "        Details: $Details" -ForegroundColor Gray
    }
    if ($Verbose -and $EventInfo) {
        Write-Host "        Event: $EventInfo" -ForegroundColor DarkCyan
    }
}

function Get-AppLockerEvents {
    param(
        [string]$BinaryName,
        [int]$SecondsBack = 5
    )
    
    $events = @()
    $startTime = (Get-Date).AddSeconds(-$SecondsBack)
    
    # Check EXE and DLL log
    $exeEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'
        ID = $AppLockerEventIDs
    } -MaxEvents 10 -ErrorAction SilentlyContinue | 
    Where-Object { $_.TimeCreated -gt $startTime -and $_.Message -match $BinaryName }
    
    if ($exeEvents) { $events += $exeEvents }
    
    # Also check MSI and Script log for completeness
    $msiEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-AppLocker/MSI and Script'
        ID = $AppLockerEventIDs
    } -MaxEvents 10 -ErrorAction SilentlyContinue | 
    Where-Object { $_.TimeCreated -gt $startTime -and $_.Message -match $BinaryName }
    
    if ($msiEvents) { $events += $msiEvents }
    
    return $events
}

function Get-EventDescription {
    param([int]$EventId)
    
    switch ($EventId) {
        8003 { return "ALLOWED (Audit)" }
        8004 { return "BLOCKED (Enforce)" }
        8006 { return "Policy Applied" }
        8007 { return "Policy Not Applied" }
        default { return "Unknown ($EventId)" }
    }
}

function Find-MSBuildInstances {
    <#
    .SYNOPSIS
        Dynamically discovers all MSBuild.exe instances under .NET Framework directories
    #>
    
    $msbuildInstances = @()
    
    # Scan both Framework and Framework64 directories
    $frameworkPaths = @(
        "$env:SystemRoot\Microsoft.NET\Framework",
        "$env:SystemRoot\Microsoft.NET\Framework64"
    )
    
    foreach ($basePath in $frameworkPaths) {
        if (Test-Path $basePath) {
            # Find all MSBuild.exe files recursively
            $found = Get-ChildItem -Path $basePath -Filter "MSBuild.exe" -Recurse -ErrorAction SilentlyContinue
            foreach ($msbuild in $found) {
                # Get version info
                $versionInfo = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($msbuild.FullName)
                $msbuildInstances += [PSCustomObject]@{
                    Path = $msbuild.FullName
                    Version = $versionInfo.FileVersion
                    ProductVersion = $versionInfo.ProductVersion
                    Framework = ($msbuild.DirectoryName -replace '.*\\(v[\d\.]+).*', '$1')
                    Architecture = if ($basePath -match 'Framework64') { 'x64' } else { 'x86' }
                }
            }
        }
    }
    
    return $msbuildInstances | Sort-Object Version -Descending
}

Write-Host "`n" -NoNewline
Write-Host "╔══════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║       AppLocker LOLBin Block Validation Tests                    ║" -ForegroundColor Cyan
Write-Host "║       Testing Microsoft Recommended Block Rules                  ║" -ForegroundColor Cyan
Write-Host "╚══════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "`n"

Write-Host "Running as: $env:USERNAME" -ForegroundColor Yellow
Write-Host "Computer:   $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Date:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "`n"

# Check if running as admin (tests should be run as non-admin)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Host "⚠️  WARNING: Running as Administrator!" -ForegroundColor Yellow
    Write-Host "   AppLocker typically allows all executions for Administrators." -ForegroundColor Yellow
    Write-Host "   For accurate testing, run this script as a standard user." -ForegroundColor Yellow
    Write-Host "`n"
}

Write-Host "Checking Event IDs: $($AppLockerEventIDs -join ', ')" -ForegroundColor Gray
Write-Host "  8003 = Allowed (audit mode logs what would be blocked)" -ForegroundColor DarkGray
Write-Host "  8004 = Blocked (enforce mode)" -ForegroundColor DarkGray
Write-Host "  8006 = Policy applied" -ForegroundColor DarkGray
Write-Host "  8007 = Policy not applied" -ForegroundColor DarkGray
Write-Host "`n"

$testResults = @()

# ═══════════════════════════════════════════════════════════════════════════════
# TEST 1: CIPHER.EXE
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "TEST 1: cipher.exe" -ForegroundColor White
Write-Host "Threat Use: Data exfiltration, secure deletion, ransomware cleanup" -ForegroundColor DarkGray
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

$blocked = $false
$details = ""
$eventInfo = ""

try {
    # Benign test: just query EFS status (no changes made)
    $result = & cipher.exe /? 2>&1
    if ($LASTEXITCODE -eq 0 -or $result -match "Displays or alters") {
        $blocked = $false
        $details = "cipher.exe executed successfully"
    } else {
        $blocked = $true
        $details = "Execution blocked or failed"
    }
} catch {
    $blocked = $true
    $details = $_.Exception.Message
}

# Check for AppLocker events (8003, 8004, 8006, 8007)
Start-Sleep -Milliseconds 500  # Brief pause to let events log
$applockerEvents = Get-AppLockerEvents -BinaryName "cipher"
if ($applockerEvents) {
    $latestEvent = $applockerEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $eventInfo = "ID $($latestEvent.Id) - $(Get-EventDescription $latestEvent.Id)"
    
    # 8004 = blocked in enforce mode, 8003 in audit mode means it would have been blocked
    if ($latestEvent.Id -eq 8004) {
        $blocked = $true
        $details = "Blocked by AppLocker (Enforce mode)"
    } elseif ($latestEvent.Id -eq 8003 -and $latestEvent.Message -match "would have been blocked") {
        $blocked = $false  # Actually ran, but audit logged it
        $details = "Allowed but logged (Audit mode) - WOULD be blocked in Enforce"
        $eventInfo += " [AUDIT MODE - Would block]"
    }
}

Write-TestResult -TestName "cipher.exe" -Blocked $blocked -Details $details -EventInfo $eventInfo
$testResults += @{Name="cipher.exe"; Blocked=$blocked; EventId=$latestEvent.Id}

Write-Host "`n"

# ═══════════════════════════════════════════════════════════════════════════════
# TEST 2: MSHTA.EXE
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "TEST 2: mshta.exe" -ForegroundColor White
Write-Host "Threat Use: Execute malicious HTA files, inline VBScript/JScript," -ForegroundColor DarkGray
Write-Host "           proxy execution, download cradles (very common in phishing)" -ForegroundColor DarkGray
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

$blocked = $false
$details = ""
$eventInfo = ""
$latestEvent = $null

try {
    # Benign test: attempt to run mshta with a simple inline script that just exits
    # This is completely harmless - just tests if mshta can execute at all
    $job = Start-Job -ScriptBlock {
        & mshta.exe "javascript:close();" 2>&1
    }
    $result = Wait-Job $job -Timeout 3 | Receive-Job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    
    # If we got here without error, it likely executed
    if ($result -match "blocked" -or $result -match "not recognized" -or $result -match "Access is denied") {
        $blocked = $true
        $details = "Execution was blocked"
    } else {
        $blocked = $false
        $details = "mshta.exe was able to start"
    }
} catch {
    $blocked = $true
    $details = $_.Exception.Message
}

# Check for AppLocker events (8003, 8004, 8006, 8007)
Start-Sleep -Milliseconds 500
$applockerEvents = Get-AppLockerEvents -BinaryName "mshta"
if ($applockerEvents) {
    $latestEvent = $applockerEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $eventInfo = "ID $($latestEvent.Id) - $(Get-EventDescription $latestEvent.Id)"
    
    if ($latestEvent.Id -eq 8004) {
        $blocked = $true
        $details = "Blocked by AppLocker (Enforce mode)"
    } elseif ($latestEvent.Id -eq 8003 -and $latestEvent.Message -match "would have been blocked") {
        $blocked = $false
        $details = "Allowed but logged (Audit mode) - WOULD be blocked in Enforce"
        $eventInfo += " [AUDIT MODE - Would block]"
    }
}

Write-TestResult -TestName "mshta.exe" -Blocked $blocked -Details $details -EventInfo $eventInfo
$testResults += @{Name="mshta.exe"; Blocked=$blocked; EventId=$latestEvent.Id}

Write-Host "`n"

# ═══════════════════════════════════════════════════════════════════════════════
# TEST 3: MSBUILD.EXE (Dynamic Discovery)
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "TEST 3: msbuild.exe (All Discovered Instances)" -ForegroundColor White
Write-Host "Threat Use: Execute arbitrary C#/VB code via inline tasks," -ForegroundColor DarkGray
Write-Host "           compile and run malicious code, bypass application control" -ForegroundColor DarkGray
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

# Discover all MSBuild instances
Write-Host "`nScanning for MSBuild.exe instances..." -ForegroundColor Gray
$msbuildInstances = Find-MSBuildInstances

if ($msbuildInstances.Count -eq 0) {
    Write-Host "  No MSBuild.exe instances found on this system." -ForegroundColor Yellow
    Write-Host "  (.NET Framework may not be installed)" -ForegroundColor Yellow
    $testResults += @{Name="msbuild.exe"; Blocked=$true; EventId=$null}
} else {
    Write-Host "  Found $($msbuildInstances.Count) MSBuild.exe instance(s):`n" -ForegroundColor Gray
    
    # Display discovered instances
    foreach ($instance in $msbuildInstances) {
        Write-Host "    [$($instance.Architecture)] " -ForegroundColor Cyan -NoNewline
        Write-Host "v$($instance.Version) " -ForegroundColor White -NoNewline
        Write-Host "($($instance.Framework))" -ForegroundColor DarkGray
        Write-Host "        $($instance.Path)" -ForegroundColor DarkGray
    }
    Write-Host ""
    
    # Test each discovered MSBuild instance
    $msbuildTestNum = 0
    foreach ($instance in $msbuildInstances) {
        $msbuildTestNum++
        $blocked = $false
        $details = ""
        $eventInfo = ""
        $latestEvent = $null
        
        Write-Host "  Testing instance $msbuildTestNum of $($msbuildInstances.Count): " -NoNewline
        Write-Host "$($instance.Architecture) v$($instance.Version)" -ForegroundColor Cyan
        
        try {
            # Benign test: just show version info (no build executed)
            $result = & $instance.Path /version 2>&1
            if ($result -match "Microsoft \(R\) Build Engine" -or $result -match "^\d+\.\d+") {
                $blocked = $false
                $details = "Executed successfully - returned version info"
            } else {
                $blocked = $true
                $details = "Execution blocked or failed"
            }
        } catch {
            $blocked = $true
            $details = $_.Exception.Message
        }
        
        # Check for AppLocker events (8003, 8004, 8006, 8007)
        Start-Sleep -Milliseconds 500
        $applockerEvents = Get-AppLockerEvents -BinaryName "msbuild"
        if ($applockerEvents) {
            $latestEvent = $applockerEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
            $eventInfo = "ID $($latestEvent.Id) - $(Get-EventDescription $latestEvent.Id)"
            
            if ($latestEvent.Id -eq 8004) {
                $blocked = $true
                $details = "Blocked by AppLocker (Enforce mode)"
            } elseif ($latestEvent.Id -eq 8003 -and $latestEvent.Message -match "would have been blocked") {
                $blocked = $false
                $details = "Allowed but logged (Audit mode) - WOULD be blocked in Enforce"
                $eventInfo += " [AUDIT MODE - Would block]"
            }
        }
        
        $testName = "msbuild.exe [$($instance.Architecture) v$($instance.Version)]"
        Write-TestResult -TestName $testName -Blocked $blocked -Details $details -EventInfo $eventInfo
        $testResults += @{Name=$testName; Blocked=$blocked; EventId=$latestEvent.Id; Path=$instance.Path}
    }
}

Write-Host "`n"

# ═══════════════════════════════════════════════════════════════════════════════
# TEST 4: CSCRIPT.EXE
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "TEST 4: cscript.exe" -ForegroundColor White
Write-Host "Threat Use: Execute malicious VBScript/JScript, download cradles," -ForegroundColor DarkGray
Write-Host "           COM object abuse, WMI access, very common in malware" -ForegroundColor DarkGray
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray

$blocked = $false
$details = ""
$eventInfo = ""
$latestEvent = $null

try {
    # Benign test: just show help (no script execution)
    $result = & cscript.exe //? 2>&1
    if ($LASTEXITCODE -eq 0 -or $result -match "Microsoft") {
        $blocked = $false
        $details = "cscript.exe executed and showed help"
    } else {
        $blocked = $true
        $details = "Execution blocked or failed"
    }
} catch {
    $blocked = $true
    $details = $_.Exception.Message
}

# Check for AppLocker events (8003, 8004, 8006, 8007)
Start-Sleep -Milliseconds 500
$applockerEvents = Get-AppLockerEvents -BinaryName "cscript"
if ($applockerEvents) {
    $latestEvent = $applockerEvents | Sort-Object TimeCreated -Descending | Select-Object -First 1
    $eventInfo = "ID $($latestEvent.Id) - $(Get-EventDescription $latestEvent.Id)"
    
    if ($latestEvent.Id -eq 8004) {
        $blocked = $true
        $details = "Blocked by AppLocker (Enforce mode)"
    } elseif ($latestEvent.Id -eq 8003 -and $latestEvent.Message -match "would have been blocked") {
        $blocked = $false
        $details = "Allowed but logged (Audit mode) - WOULD be blocked in Enforce"
        $eventInfo += " [AUDIT MODE - Would block]"
    }
}

Write-TestResult -TestName "cscript.exe" -Blocked $blocked -Details $details -EventInfo $eventInfo
$testResults += @{Name="cscript.exe"; Blocked=$blocked; EventId=$latestEvent.Id}

Write-Host "`n"

# ═══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "                         TEST SUMMARY                              " -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$passed = ($testResults | Where-Object { $_.Blocked -eq $true }).Count
$failed = ($testResults | Where-Object { $_.Blocked -eq $false }).Count
$total = $testResults.Count

Write-Host "Tests Passed (Blocked): " -NoNewline
Write-Host "$passed/$total" -ForegroundColor $(if ($passed -eq $total) { "Green" } else { "Yellow" })

Write-Host "Tests Failed (Not Blocked): " -NoNewline
Write-Host "$failed/$total" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

Write-Host ""

# Show individual results
Write-Host "Individual Results:" -ForegroundColor White
foreach ($result in $testResults) {
    $statusColor = if ($result.Blocked) { "Green" } else { "Red" }
    $status = if ($result.Blocked) { "BLOCKED" } else { "NOT BLOCKED" }
    Write-Host "  • $($result.Name): " -NoNewline
    Write-Host $status -ForegroundColor $statusColor
}

Write-Host ""

if ($failed -gt 0) {
    Write-Host "⚠️  Some LOLBins are NOT blocked!" -ForegroundColor Red
    Write-Host "   Verify that:" -ForegroundColor Yellow
    Write-Host "   1. The AppLocker policy has been applied (gpupdate /force)" -ForegroundColor Yellow
    Write-Host "   2. The Application Identity service is running" -ForegroundColor Yellow
    Write-Host "   3. You are running as a non-admin user" -ForegroundColor Yellow
    Write-Host "   4. The policy is in Enforce mode, not Audit mode" -ForegroundColor Yellow
} else {
    Write-Host "✅ All tested LOLBins are properly blocked!" -ForegroundColor Green
}

Write-Host ""
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "Recent AppLocker Events (last 30 seconds):" -ForegroundColor White
Write-Host ""

# Show recent events for all tested binaries
$recentEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-AppLocker/EXE and DLL'
    ID = $AppLockerEventIDs
} -MaxEvents 20 -ErrorAction SilentlyContinue | 
Where-Object { $_.TimeCreated -gt (Get-Date).AddSeconds(-30) } |
Sort-Object TimeCreated -Descending |
Select-Object -First 10

if ($recentEvents) {
    foreach ($event in $recentEvents) {
        $color = switch ($event.Id) {
            8003 { "Yellow" }   # Allowed/Audit
            8004 { "Green" }    # Blocked
            8006 { "Cyan" }     # Policy applied
            8007 { "Red" }      # Policy not applied
            default { "Gray" }
        }
        
        # Extract filename from message
        $filename = if ($event.Message -match '\\([^\\]+\.exe)') { $matches[1] } else { "Unknown" }
        
        Write-Host "  $($event.TimeCreated.ToString('HH:mm:ss')) " -NoNewline
        Write-Host "[$($event.Id)] " -ForegroundColor $color -NoNewline
        Write-Host "$(Get-EventDescription $event.Id) " -ForegroundColor $color -NoNewline
        Write-Host "- $filename" -ForegroundColor Gray
    }
} else {
    Write-Host "  No AppLocker events found in the last 30 seconds." -ForegroundColor Gray
    Write-Host "  This could mean:" -ForegroundColor Gray
    Write-Host "    - AppLocker policy is not applied" -ForegroundColor Gray
    Write-Host "    - Application Identity service is not running" -ForegroundColor Gray
    Write-Host "    - You are running as Administrator (bypasses policy)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "Event Log Location:" -ForegroundColor Gray
Write-Host "  Event Viewer > Applications and Services Logs > Microsoft >" -ForegroundColor Gray
Write-Host "  Windows > AppLocker > EXE and DLL" -ForegroundColor Gray
Write-Host ""
Write-Host "Event IDs:" -ForegroundColor Gray
Write-Host "  8003 = Allowed (in audit mode, shows what WOULD be blocked)" -ForegroundColor Yellow
Write-Host "  8004 = Blocked (enforce mode - rule is working!)" -ForegroundColor Green
Write-Host "  8006 = Policy applied successfully" -ForegroundColor Cyan
Write-Host "  8007 = Policy not applied (check Application Identity service)" -ForegroundColor Red
Write-Host "─────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
