<#
.SYNOPSIS
    Runs the V-253262 AppLocker check and feeds the result into the SCC
    autoanswer file, then optionally kicks off an SCC scan.

.DESCRIPTION
    1. Executes Check-V253262.ps1 to determine compliance.
    2. Updates Question 4 (V-253262) in the SCC autoanswer template file,
       placing [X] on the appropriate answer line.
    3. Saves the completed file to SCC's Completed_Files directory.
    4. Optionally runs cscc.exe to perform the full scan.

.PARAMETER SccPath
    Path to the SCC installation directory.
    Default: "C:\Users\Lorenzo.SKYNET\Downloads\WIN11 STIG\scc-5.14_Windows_bundle\scc-5.14_Windows\scc-5.14_Windows\scc_5.14"

.PARAMETER RunScan
    If specified, launches cscc.exe after updating the answer file.

.EXAMPLE
    .\Run-STIGScan.ps1
    .\Run-STIGScan.ps1 -RunScan
#>

[CmdletBinding()]
param(
    [string]$SccPath = "C:\Users\Lorenzo.SKYNET\Downloads\WIN11 STIG\scc-5.14_Windows_bundle\scc-5.14_Windows\scc-5.14_Windows\scc_5.14",
    [switch]$RunScan
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition

$templateDir   = Join-Path $SccPath "Resources\Content\Manual_Questions\Templates"
$completedDir  = Join-Path $SccPath "Resources\Content\Manual_Questions\Completed_Files"
$templateFile  = Join-Path $templateDir "Microsoft_Windows_11_STIG_002.007.016_Autoanswer.txt"
$completedFile = Join-Path $completedDir "Microsoft_Windows_11_STIG_002.007.016_Autoanswer.txt"

# ---------------------------------------------------------------------------
# 1. Run the AppLocker check
# ---------------------------------------------------------------------------
Write-Host "`n=== Running V-253262 AppLocker Check ===" -ForegroundColor Cyan

$checkScript = Join-Path $scriptDir "Check-V253262.ps1"
if (-not (Test-Path $checkScript)) {
    Write-Error "Check-V253262.ps1 not found in $scriptDir"
}

$output = & powershell.exe -ExecutionPolicy Bypass -File $checkScript 2>&1
$exitCode = $LASTEXITCODE

$output | ForEach-Object { Write-Host "  $_" }

if ($exitCode -eq 0) {
    $isCompliant = $true
    Write-Host "`n  --> COMPLIANT (will mark: Not a Finding)" -ForegroundColor Green
}
else {
    $isCompliant = $false
    Write-Host "`n  --> NON-COMPLIANT (will mark: Finding)" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# 2. Load the autoanswer template (or existing completed file)
# ---------------------------------------------------------------------------
if (Test-Path $completedFile) {
    $sourceFile = $completedFile
    Write-Host "`n=== Using existing completed file ===" -ForegroundColor Cyan
}
elseif (Test-Path $templateFile) {
    $sourceFile = $templateFile
    Write-Host "`n=== Using template file ===" -ForegroundColor Cyan
}
else {
    Write-Error "Autoanswer template not found at: $templateFile"
}

Write-Host "  Source: $sourceFile"
$lines = Get-Content $sourceFile

# ---------------------------------------------------------------------------
# 3. Find Question 4 (V-253262) and update the answer selection
# ---------------------------------------------------------------------------
# The format uses [X] to mark the selected answer and [ ] for unselected.
# We need to find the answer block for V-253262 and set the right one.

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$comment   = "Automated: Check-V253262.ps1 ran $timestamp. " +
             "AppLocker Exe/Msi/Script/Appx enforcement mode evaluated."

$inV253262Block = $false
$answerBlockFound = $false
$updated = $false

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]

    # Detect the start of the V-253262 question block
    if ($line -match "V-253262") {
        $inV253262Block = $true
        continue
    }

    # Detect end of V-253262 block
    if ($inV253262Block -and $line -match "^\*+\s*end of question") {
        $inV253262Block = $false
        continue
    }

    if (-not $inV253262Block) { continue }

    # Detect the answer selection lines within the block
    if ($line -match "^\s+\[.\]\s+Finding\s*$") {
        if (-not $isCompliant) {
            $lines[$i] = $line -replace '\[.\]', '[X]'
        } else {
            $lines[$i] = $line -replace '\[.\]', '[ ]'
        }
        $answerBlockFound = $true
    }
    elseif ($line -match "^\s+\[.\]\s+Not a Finding\s*$") {
        if ($isCompliant) {
            $lines[$i] = $line -replace '\[.\]', '[X]'
        } else {
            $lines[$i] = $line -replace '\[.\]', '[ ]'
        }
        $answerBlockFound = $true
    }
    elseif ($line -match "^\s+\[.\]\s+Not Applicable\s*$") {
        $lines[$i] = $line -replace '\[.\]', '[ ]'
        $answerBlockFound = $true
    }
    elseif ($line -match "^\s+\[.\]\s+Not Reviewed\s*$") {
        $lines[$i] = $line -replace '\[.\]', '[ ]'
        $answerBlockFound = $true
    }
    elseif ($line -match "^\s+Enter any comments\s*:") {
        $lines[$i] = "     Enter any comments : $comment"
        $updated = $true
    }
}

if (-not $answerBlockFound) {
    Write-Error "Could not find the answer block for V-253262 in the autoanswer file."
}

if (-not $updated) {
    Write-Warning "Answer block was updated but comment line was not found."
}

# ---------------------------------------------------------------------------
# 4. Save to the Completed_Files directory
# ---------------------------------------------------------------------------
if (-not (Test-Path $completedDir)) {
    New-Item -ItemType Directory -Path $completedDir -Force | Out-Null
}

$lines | Set-Content -Path $completedFile
Write-Host "`n=== Answer file saved ===" -ForegroundColor Cyan
Write-Host "  Path: $completedFile"

$result = if ($isCompliant) { "Not a Finding" } else { "Finding" }
Write-Host "  V-253262 marked as: $result"

# ---------------------------------------------------------------------------
# 5. Optionally run the SCC scan
# ---------------------------------------------------------------------------
if ($RunScan) {
    $cscc = Join-Path $SccPath "cscc.exe"
    if (Test-Path $cscc) {
        Write-Host "`n=== Launching SCC Scan ===" -ForegroundColor Cyan
        & $cscc
    }
    else {
        Write-Error "cscc.exe not found at: $cscc"
    }
}
else {
    Write-Host "`n=== Done ===" -ForegroundColor Cyan
    Write-Host "  Run SCC GUI or use: .\Run-STIGScan.ps1 -RunScan"
    Write-Host "  SCC will pick up the completed answer file automatically."
}

Write-Host ""
