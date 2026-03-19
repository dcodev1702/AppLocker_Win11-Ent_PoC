<#
.SYNOPSIS
    AppLocker LOLBin Block Validation Tests
    
.DESCRIPTION
    Tests to validate that AppLocker is properly blocking Microsoft-recommended
    LOLBins commonly abused by threat actors.
    
    These are SAFE, benign commands that simply test if the binaries can execute.
    If AppLocker is working correctly, each test should FAIL with an access denied error.
    
        Works in both Enforce and Audit modes by checking event IDs:
            8003 = EXE or DLL allowed in audit mode (would be blocked if enforced)
            8004 = EXE or DLL blocked in enforce mode
            8006 = MSI or Script allowed in audit mode (would be blocked if enforced)
            8007 = MSI or Script blocked in enforce mode
            8021 = Packaged app allowed in audit mode (would be blocked if enforced)
            8024 = Packaged app deployment allowed in audit mode (would be blocked if enforced)
    
.NOTES
    Author: DCODEV1702 & Claude Opus 4.5
    Date: December 2025
    
    Run from a non-admin user account to properly test the policy.
    Administrators typically have a blanket allow rule.
#>

param(
    [switch]$Verbose
)

$ErrorActionPreference = "SilentlyContinue"

# -----------------------------------------------------------------------------
# CLM (Constrained Language Mode) Detection
# When AppLocker is in Enforce mode, PowerShell runs in CLM which blocks .NET types
# -----------------------------------------------------------------------------
$languageMode = $ExecutionContext.SessionState.LanguageMode
if ($languageMode -eq "ConstrainedLanguage") {
    Write-Host "ℹ️  Running in Constrained Language Mode (CLM)" -ForegroundColor Cyan
    Write-Host "   This is expected when AppLocker is enforcing. Interactive PowerShell is constrained, while trusted script files can still run in Full Language mode.`n" -ForegroundColor DarkCyan
} elseif ($languageMode -eq "FullLanguage") {
    Write-Host "ℹ️  Running in Full Language Mode" -ForegroundColor Gray
    Write-Host "   This can happen when the script is trusted by policy, AppLocker script enforcement is not active for this file, or you are running elevated.`n" -ForegroundColor DarkGray
}

# AppLocker Event IDs to check
$AppLockerEventIDs = @(8003, 8004, 8006, 8007, 8021, 8024)
$AppLockerLogs = @(
    'Microsoft-Windows-AppLocker/EXE and DLL'
    'Microsoft-Windows-AppLocker/MSI and Script'
    'Microsoft-Windows-AppLocker/Packaged app-Execution'
    'Microsoft-Windows-AppLocker/Packaged app-Deployment'
)

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
    
    foreach ($logName in $AppLockerLogs) {
        $matchingEvents = Get-WinEvent -FilterHashtable @{
            LogName = $logName
            ID = $AppLockerEventIDs
        } -MaxEvents 10 -ErrorAction SilentlyContinue |
        Where-Object { $_.TimeCreated -gt $startTime -and $_.Message -match $BinaryName }

        if ($matchingEvents) { $events += $matchingEvents }
    }
    
    return $events
}

function Get-EventDescription {
    param(
        [int]$EventId,
        [string]$LogName
    )
    
    switch ($LogName) {
        'Microsoft-Windows-AppLocker/EXE and DLL' {
            switch ($EventId) {
                8003 { return 'EXE or DLL would be blocked (Audit)' }
                8004 { return 'EXE or DLL blocked (Enforce)' }
            }
        }
        'Microsoft-Windows-AppLocker/MSI and Script' {
            switch ($EventId) {
                8006 { return 'MSI or Script would be blocked (Audit)' }
                8007 { return 'MSI or Script blocked (Enforce)' }
            }
        }
        'Microsoft-Windows-AppLocker/Packaged app-Execution' {
            switch ($EventId) {
                8021 { return 'Packaged app would be blocked (Audit)' }
            }
        }
        'Microsoft-Windows-AppLocker/Packaged app-Deployment' {
            switch ($EventId) {
                8024 { return 'Packaged app deployment would be blocked (Audit)' }
            }
        }
    }

    return "Unknown ($EventId)"
}

function Find-MSBuildInstances {
    <#
    .SYNOPSIS
        Dynamically discovers all MSBuild.exe instances under .NET Framework directories
        CLM-COMPATIBLE: Uses only PowerShell cmdlets, no .NET type access
    #>
    
    # Use simple array - CLM compatible
    $msbuildInstances = @()
    
    # Known .NET Framework versions that typically contain MSBuild.exe
    $knownPaths = @(
        "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe",
        "C:\Windows\Microsoft.NET\Framework64\v3.5\MSBuild.exe",
        "C:\Windows\Microsoft.NET\Framework\v3.5\MSBuild.exe",
        "C:\Windows\Microsoft.NET\Framework64\v2.0.50727\MSBuild.exe",
        "C:\Windows\Microsoft.NET\Framework\v2.0.50727\MSBuild.exe"
    )
    
    Write-Host "    Checking known MSBuild paths..." -ForegroundColor DarkGray
    
    foreach ($pathToCheck in $knownPaths) {
        # Parse architecture and framework from path
        if ($pathToCheck -match 'Framework64') {
            $arch = "x64"
        } else {
            $arch = "x86"
        }
        
        if ($pathToCheck -match '\\(v[\d\.]+)\\') {
            $framework = $matches[1]
        } else {
            $framework = "Unknown"
        }
        
        Write-Host "    $framework [$arch]: " -ForegroundColor DarkGray -NoNewline
        
        # Use Test-Path only - CLM compatible
        if (Test-Path -Path $pathToCheck -PathType Leaf) {
            Write-Host "FOUND" -ForegroundColor Green
            
            # Version info is nice-to-have, not required
            # Skip version lookup entirely in CLM - it uses .NET objects
            $fileVersion = "Installed"
            
            # Add as hashtable - CLM compatible
            $msbuildInstances += @{
                Path = $pathToCheck
                Version = $fileVersion
                Framework = $framework
                Architecture = $arch
            }
        } else {
            Write-Host "not found" -ForegroundColor DarkGray
        }
    }
    
    Write-Host "    Total instances found: $($msbuildInstances.Count)" -ForegroundColor DarkGray
    
    return $msbuildInstances
}

Write-Host "`n" -NoNewline
Write-Host "+------------------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "|       AppLocker LOLBin Block Validation Tests                    |" -ForegroundColor Cyan
Write-Host "|       Testing Microsoft Recommended Block Rules                  |" -ForegroundColor Cyan
Write-Host "+------------------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "`n"

Write-Host "Running as: $env:USERNAME" -ForegroundColor Yellow
Write-Host "Computer:   $env:COMPUTERNAME" -ForegroundColor Yellow
Write-Host "Date:       $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Yellow
Write-Host "`n"

# Check if running as admin (tests should be run as non-admin)
# CLM-compatible: use whoami /groups instead of .NET types
$isAdmin = $false
try {
    $groups = whoami /groups 2>$null
    if ($groups -match "S-1-16-12288" -or $groups -match "High Mandatory Level") {
        $isAdmin = $true
    }
} catch {
    # If whoami fails, assume not admin
}
if ($isAdmin) {
    Write-Host "⚠️  WARNING: Running as Administrator!" -ForegroundColor Yellow
    Write-Host "   AppLocker typically allows all executions for Administrators." -ForegroundColor Yellow
    Write-Host "   For accurate testing, run this script as a standard user." -ForegroundColor Yellow
    Write-Host "`n"
}

Write-Host "Checking Event IDs: $($AppLockerEventIDs -join ', ')" -ForegroundColor Gray
Write-Host "  8003 = EXE or DLL would be blocked (audit mode)" -ForegroundColor DarkGray
Write-Host "  8004 = EXE or DLL blocked (enforce mode)" -ForegroundColor DarkGray
Write-Host "  8006 = MSI or Script would be blocked (audit mode)" -ForegroundColor DarkGray
Write-Host "  8007 = MSI or Script blocked (enforce mode)" -ForegroundColor DarkGray
Write-Host "  8021 = Packaged app would be blocked (audit mode)" -ForegroundColor DarkGray
Write-Host "  8024 = Packaged app deployment would be blocked (audit mode)" -ForegroundColor DarkGray
Write-Host "`n"

$testResults = @()

# -----------------------------------------------------------------------------
# TEST 1: CIPHER.EXE
# -----------------------------------------------------------------------------
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "TEST 1: cipher.exe" -ForegroundColor White
Write-Host "Threat Use: Data exfiltration, secure deletion, ransomware cleanup" -ForegroundColor DarkGray
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray

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
    $eventInfo = "ID $($latestEvent.Id) - $(Get-EventDescription -EventId $latestEvent.Id -LogName $latestEvent.LogName)"
    
    if ($latestEvent.Id -in @(8004, 8007)) {
        $blocked = $true
        $details = "Blocked by AppLocker (Enforce mode)"
    } elseif ($latestEvent.Id -in @(8003, 8006, 8021, 8024) -and $latestEvent.Message -match "would have been blocked") {
        $blocked = $false  # Actually ran, but audit logged it
        $details = "Allowed but logged (Audit mode) - WOULD be blocked in Enforce"
        $eventInfo += " [AUDIT MODE - Would block]"
    }
}

Write-TestResult -TestName "cipher.exe" -Blocked $blocked -Details $details -EventInfo $eventInfo
$testResults += @{Name="cipher.exe"; Blocked=$blocked; EventId=$latestEvent.Id}

Write-Host "`n"

# -----------------------------------------------------------------------------
# TEST 2: MSHTA.EXE
# -----------------------------------------------------------------------------
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "TEST 2: mshta.exe" -ForegroundColor White
Write-Host "Threat Use: Execute malicious HTA files, inline VBScript/JScript," -ForegroundColor DarkGray
Write-Host "           proxy execution, download cradles (very common in phishing)" -ForegroundColor DarkGray
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray

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
    $eventInfo = "ID $($latestEvent.Id) - $(Get-EventDescription -EventId $latestEvent.Id -LogName $latestEvent.LogName)"
    
    if ($latestEvent.Id -in @(8004, 8007)) {
        $blocked = $true
        $details = "Blocked by AppLocker (Enforce mode)"
    } elseif ($latestEvent.Id -in @(8003, 8006, 8021, 8024) -and $latestEvent.Message -match "would have been blocked") {
        $blocked = $false
        $details = "Allowed but logged (Audit mode) - WOULD be blocked in Enforce"
        $eventInfo += " [AUDIT MODE - Would block]"
    }
}

Write-TestResult -TestName "mshta.exe" -Blocked $blocked -Details $details -EventInfo $eventInfo
$testResults += @{Name="mshta.exe"; Blocked=$blocked; EventId=$latestEvent.Id}

Write-Host "`n"

# -----------------------------------------------------------------------------
# TEST 3: MSBUILD.EXE (Dynamic Discovery)
# -----------------------------------------------------------------------------
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "TEST 3: msbuild.exe (All Discovered Instances)" -ForegroundColor White
Write-Host "Threat Use: Execute arbitrary C#/VB code via inline tasks," -ForegroundColor DarkGray
Write-Host "           compile and run malicious code, bypass application control" -ForegroundColor DarkGray
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray

# Discover all MSBuild instances
Write-Host "`nScanning for MSBuild.exe instances..." -ForegroundColor Gray
$msbuildInstances = @(Find-MSBuildInstances)

Write-Host "    Received $($msbuildInstances.Count) instance(s) from discovery function" -ForegroundColor DarkGray

if ($null -eq $msbuildInstances -or $msbuildInstances.Count -eq 0) {
    Write-Host "  [SKIP] " -ForegroundColor Yellow -NoNewline
    Write-Host "No MSBuild.exe instances found on this system." -ForegroundColor Yellow
    Write-Host "         (.NET Framework may not be installed)" -ForegroundColor DarkGray
    # Don't add to testResults as blocked - this is a SKIP, not a pass
    $testResults += @{Name="msbuild.exe"; Blocked=$null; EventId=$null; Skipped=$true}
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
            $eventInfo = "ID $($latestEvent.Id) - $(Get-EventDescription -EventId $latestEvent.Id -LogName $latestEvent.LogName)"
            
            if ($latestEvent.Id -in @(8004, 8007)) {
                $blocked = $true
                $details = "Blocked by AppLocker (Enforce mode)"
            } elseif ($latestEvent.Id -in @(8003, 8006, 8021, 8024) -and $latestEvent.Message -match "would have been blocked") {
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

# -----------------------------------------------------------------------------
# TEST 4: CSCRIPT.EXE
# -----------------------------------------------------------------------------
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "TEST 4: cscript.exe" -ForegroundColor White
Write-Host "Threat Use: Execute malicious VBScript/JScript, download cradles," -ForegroundColor DarkGray
Write-Host "           COM object abuse, WMI access, very common in malware" -ForegroundColor DarkGray
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray

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
    $eventInfo = "ID $($latestEvent.Id) - $(Get-EventDescription -EventId $latestEvent.Id -LogName $latestEvent.LogName)"
    
    if ($latestEvent.Id -in @(8004, 8007)) {
        $blocked = $true
        $details = "Blocked by AppLocker (Enforce mode)"
    } elseif ($latestEvent.Id -in @(8003, 8006, 8021, 8024) -and $latestEvent.Message -match "would have been blocked") {
        $blocked = $false
        $details = "Allowed but logged (Audit mode) - WOULD be blocked in Enforce"
        $eventInfo += " [AUDIT MODE - Would block]"
    }
}

Write-TestResult -TestName "cscript.exe" -Blocked $blocked -Details $details -EventInfo $eventInfo
$testResults += @{Name="cscript.exe"; Blocked=$blocked; EventId=$latestEvent.Id}

Write-Host "`n"

# -----------------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------------
Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host "                         TEST SUMMARY                              " -ForegroundColor Cyan
Write-Host "-------------------------------------------------------------------" -ForegroundColor Cyan
Write-Host ""

$passed = ($testResults | Where-Object { $_.Blocked -eq $true }).Count
$failed = ($testResults | Where-Object { $_.Blocked -eq $false }).Count
$skipped = ($testResults | Where-Object { $_.Skipped -eq $true }).Count
$total = $testResults.Count

Write-Host "Tests Passed (Blocked): " -NoNewline
Write-Host "$passed/$total" -ForegroundColor $(if ($passed -eq ($total - $skipped)) { "Green" } else { "Yellow" })

Write-Host "Tests Failed (Not Blocked): " -NoNewline
Write-Host "$failed/$total" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })

if ($skipped -gt 0) {
    Write-Host "Tests Skipped (Not Found): " -NoNewline
    Write-Host "$skipped/$total" -ForegroundColor "Yellow"
}

Write-Host ""

# Show individual results
Write-Host "Individual Results:" -ForegroundColor White
foreach ($result in $testResults) {
    if ($result.Skipped -eq $true) {
        Write-Host "  - $($result.Name): " -NoNewline
        Write-Host "SKIPPED (not installed)" -ForegroundColor Yellow
    } else {
        $statusColor = if ($result.Blocked) { "Green" } else { "Red" }
        $status = if ($result.Blocked) { "BLOCKED" } else { "NOT BLOCKED" }
        Write-Host "  - $($result.Name): " -NoNewline
        Write-Host $status -ForegroundColor $statusColor
    }
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
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Recent AppLocker Events (last 30 seconds):" -ForegroundColor White
Write-Host ""

# Show recent events for all tested binaries
$recentEvents = foreach ($logName in $AppLockerLogs) {
    Get-WinEvent -FilterHashtable @{
        LogName = $logName
        ID = $AppLockerEventIDs
    } -MaxEvents 20 -ErrorAction SilentlyContinue |
    Where-Object { $_.TimeCreated -gt (Get-Date).AddSeconds(-30) }
}

$recentEvents = $recentEvents |
Sort-Object TimeCreated -Descending |
Select-Object -First 10

if ($recentEvents) {
    foreach ($recentRecord in $recentEvents) {
        $color = switch ($recentRecord.Id) {
            8003 { "Yellow" }
            8004 { "Green" }
            8006 { "Yellow" }
            8007 { "Green" }
            8021 { "Yellow" }
            8024 { "Yellow" }
            default { "Gray" }
        }
        
        # Extract filename from message
        $filename = if ($recentRecord.Message -match '\\([^\\]+\.exe)') { $matches[1] } else { "Unknown" }
        
        Write-Host "  $($recentRecord.TimeCreated.ToString('HH:mm:ss')) " -NoNewline
        Write-Host "[$($recentRecord.Id)] " -ForegroundColor $color -NoNewline
        Write-Host "$(Get-EventDescription -EventId $recentRecord.Id -LogName $recentRecord.LogName) " -ForegroundColor $color -NoNewline
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
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Write-Host "Event Log Location:" -ForegroundColor Gray
Write-Host "  Event Viewer > Applications and Services Logs > Microsoft >" -ForegroundColor Gray
Write-Host "  Windows > AppLocker > EXE and DLL / MSI and Script / Packaged app-*" -ForegroundColor Gray
Write-Host ""
Write-Host "Event IDs:" -ForegroundColor Gray
Write-Host "  8003 = EXE or DLL would be blocked (audit mode)" -ForegroundColor Yellow
Write-Host "  8004 = EXE or DLL blocked (enforce mode - rule is working)" -ForegroundColor Green
Write-Host "  8006 = MSI or Script would be blocked (audit mode)" -ForegroundColor Yellow
Write-Host "  8007 = MSI or Script blocked (enforce mode - rule is working)" -ForegroundColor Green
Write-Host "  8021 = Packaged app would be blocked (audit mode)" -ForegroundColor Yellow
Write-Host "  8024 = Packaged app deployment would be blocked (audit mode)" -ForegroundColor Yellow
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
