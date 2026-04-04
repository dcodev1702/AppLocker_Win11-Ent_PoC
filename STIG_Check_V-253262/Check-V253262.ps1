<#
.SYNOPSIS
    Automated STIG check for V-253262 (WN11-00-000035).

.DESCRIPTION
    Checks whether AppLocker is configured with enforcement mode ("Enabled")
    on the required rule collections. If any collection is set to "AuditOnly"
    or "NotConfigured", or if no rules exist, the result is an Open Finding.

    STIG Requirement: The OS must employ a deny-all, permit-by-exception policy
    to allow the execution of authorized software programs.

.NOTES
    STIG ID    : V-253262
    Rule ID    : WN11-00-000035
    Severity   : CAT II (Medium)
    Requires   : Run as Administrator for full policy visibility
#>

[CmdletBinding()]
param(
    # Rule collection types required to be in Enforce mode.
    # Default: all four AppLocker categories per STIG guidance.
    [string[]]$RequiredCollections = @("Exe", "Msi", "Script", "Appx")
)

$stigId = "V-253262"
$ruleId = "WN11-00-000035"

# --- 1. Check that the Application Identity service is running (AppLocker depends on it) ---
$appIdSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
if (-not $appIdSvc) {
    Write-Output "[$stigId] OPEN FINDING - Application Identity (AppIDSvc) service not found."
    exit 1
}

if ($appIdSvc.Status -ne "Running") {
    Write-Output "[$stigId] OPEN FINDING - Application Identity service is not running (Status: $($appIdSvc.Status))."
    Write-Output "  AppLocker cannot enforce rules without this service."
    exit 1
}

# --- 2. Retrieve the effective AppLocker policy as XML ---
try {
    [xml]$policyXml = Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop
}
catch {
    Write-Output "[$stigId] OPEN FINDING - Unable to retrieve AppLocker policy: $($_.Exception.Message)"
    exit 1
}

# --- 3. Evaluate each required RuleCollection ---
$findings   = @()
$passes     = @()

foreach ($collection in $RequiredCollections) {
    $node = $policyXml.AppLockerPolicy.RuleCollection | Where-Object { $_.Type -eq $collection }

    if (-not $node) {
        $findings += "  - $collection : No RuleCollection found (not configured)."
        continue
    }

    $mode      = $node.EnforcementMode
    $ruleCount = ($node.ChildNodes | Where-Object { $_.LocalName -ne "#whitespace" }).Count

    switch ($mode) {
        "Enabled" {
            if ($ruleCount -eq 0) {
                $findings += "  - $collection : Enforcement mode is Enabled but contains 0 rules."
            }
            else {
                $passes += "  - $collection : Enforce Rules ($ruleCount rule(s))."
            }
        }
        "AuditOnly" {
            $findings += "  - $collection : Set to Audit Only (not enforcing). Rules are logged but not blocked."
        }
        "NotConfigured" {
            $findings += "  - $collection : Not Configured."
        }
        default {
            $findings += "  - $collection : Unknown EnforcementMode '$mode'."
        }
    }
}

# --- 4. Report result ---
Write-Output ""
Write-Output "STIG Check: $stigId ($ruleId)"
Write-Output "Title     : AppLocker must employ deny-all, permit-by-exception policy"
Write-Output "==========================================================="

if ($passes.Count -gt 0) {
    Write-Output ""
    Write-Output "Compliant collections:"
    $passes | ForEach-Object { Write-Output $_ }
}

if ($findings.Count -gt 0) {
    Write-Output ""
    Write-Output "Non-compliant collections:"
    $findings | ForEach-Object { Write-Output $_ }
    Write-Output ""
    Write-Output "RESULT: ** OPEN FINDING **"
    Write-Output ""
    Write-Output "Remediation: Set AppLocker rule collections to 'Enforce Rules' via:"
    Write-Output "  Computer Configuration > Windows Settings > Security Settings >"
    Write-Output "  Application Control Policies > AppLocker"
    exit 1
}
else {
    Write-Output ""
    Write-Output "RESULT: NOT A FINDING"
    Write-Output "  All required AppLocker rule collections are in Enforce mode."
    exit 0
}
