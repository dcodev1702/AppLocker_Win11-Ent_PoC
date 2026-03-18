<#
.SYNOPSIS
Validates folder NTFS permissions for AppLocker path rule safety by checking for write-capable access granted to non-admin principals.

.DATE
2026-03-18

.AUTHOR
DCODEV1702 & GPT-5.4

.DESCRIPTION
This script reviews NTFS access control lists on a set of folders and flags permissions that may make an AppLocker path rule unsafe. It looks for allow rules that grant write-capable access to broad or non-admin principals such as Everyone, Users, Authenticated Users, Domain Users, or Interactive users. It also flags folders whose owner is not BUILTIN\Administrators or NT AUTHORITY\SYSTEM because ownership can still permit ACL changes even when write ACEs appear restricted.

.NOTES
Intent: Assess whether target folders are safe candidates for AppLocker path rules by identifying potentially risky write permissions and unsafe ownership.

.PARAMETER Paths
One or more folder paths to validate.

.PARAMETER PassThru
Returns validation objects instead of formatting a table.

.EXAMPLE
.\acl_validation.ps1
Validates the default folder list and reports whether any risky write-capable ACEs or unsafe owners are present.

.EXAMPLE
.\acl_validation.ps1 -Paths 'C:\Fonsi' -PassThru
Validates a specific folder and returns structured objects for automation.

.USAGE
Run the script in PowerShell to review the configured folder list. Use -Paths to target the directories you want to assess and -PassThru when you want structured results for another script.
#>
[CmdletBinding()]
param(
    [string[]]$Paths = @(
        'C:\Fonsi'
    ),
    [switch]$PassThru
)

$RiskPrincipalSids = @(
    'S-1-1-0',
    'S-1-5-32-545',
    'S-1-5-11',
    'S-1-5-4'
) | Sort-Object -Unique

$SafeOwnerSids = @(
    'S-1-5-32-544',
    'S-1-5-18'
)

function ConvertTo-SidValue {
    param(
        [Parameter(Mandatory)]
        [object]$Identity
    )

    try {
        return $Identity.Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        return $null
    }
}

$WriteIndicators = @(
    'Write',
    'Modify',
    'FullControl',
    'CreateFiles',
    'CreateDirectories',
    'WriteData',
    'AppendData',
    'WriteAttributes',
    'WriteExtendedAttributes',
    'Delete',
    'DeleteSubdirectoriesAndFiles',
    'ChangePermissions',
    'TakeOwnership'
)

$Findings = foreach ($Path in $Paths) {
    if (-not (Test-Path -LiteralPath $Path)) {
        [pscustomobject]@{
            Path              = $Path
            Exists            = $false
            SafeForPathRule   = $false
            Owner             = ''
            IdentityReference = '<path not found>'
            AccessType        = ''
            Rights            = ''
            Inherited         = ''
            Notes             = 'Folder does not exist'
        }
        continue
    }

    $Acl = Get-Acl -LiteralPath $Path
    $OwnerFinding = $null
    $OwnerSid = $null

    try {
        $OwnerSid = ([System.Security.Principal.NTAccount]$Acl.Owner).Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        $OwnerSid = $null
    }

    if ($OwnerSid -notin $SafeOwnerSids) {
        $OwnerFinding = [pscustomobject]@{
            Path              = $Path
            Exists            = $true
            SafeForPathRule   = $false
            Owner             = $Acl.Owner
            IdentityReference = '<owner>'
            AccessType        = 'Owner'
            Rights            = ''
            Inherited         = $false
            Notes             = 'Folder owner is not BUILTIN\Administrators or NT AUTHORITY\SYSTEM'
        }
    }

    $SuspiciousRules = foreach ($Ace in $Acl.Access) {
        $Identity = $Ace.IdentityReference.Value
        $IdentitySid = ConvertTo-SidValue -Identity $Ace.IdentityReference
        $RightNames = @($Ace.FileSystemRights.ToString().Split(',') | ForEach-Object { $_.Trim() })
        $HasWriteLikeRight = @($RightNames | Where-Object { $_ -in $WriteIndicators }).Count -gt 0

        $PrincipalMatch =
            $IdentitySid -in $RiskPrincipalSids -or
            $IdentitySid -match '-513$' -or
            $Identity -match '(^|\\)Users$' -or
            $Identity -match 'Authenticated Users$' -or
            $Identity -match 'Everyone$' -or
            $Identity -match 'Domain Users$'

        if ($PrincipalMatch -and
            $Ace.AccessControlType -eq 'Allow' -and
            $HasWriteLikeRight) {
            [pscustomobject]@{
                Path              = $Path
                Exists            = $true
                SafeForPathRule   = $false
                Owner             = $Acl.Owner
                IdentityReference = $Identity
                AccessType        = $Ace.AccessControlType
                Rights            = $Ace.FileSystemRights
                Inherited         = $Ace.IsInherited
                Notes             = 'Non-admin principal appears to have write-capable access'
            }
        }
    }

    $PathFindings = @(
        $OwnerFinding
        $SuspiciousRules
    ) | Where-Object { $null -ne $_ }

    if ($PathFindings) {
        $PathFindings
    }
    else {
        [pscustomobject]@{
            Path              = $Path
            Exists            = $true
            SafeForPathRule   = $true
            Owner             = $Acl.Owner
            IdentityReference = ''
            AccessType        = ''
            Rights            = ''
            Inherited         = ''
            Notes             = 'No obvious non-admin write-capable ACEs or unsafe ownership detected'
        }
    }
}

if ($PassThru) {
    $Findings
}
else {
    $Findings | Format-Table -AutoSize
}