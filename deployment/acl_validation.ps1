<#
.SYNOPSIS
Validates folder NTFS permissions for AppLocker path rule safety by checking for write-capable access granted to non-admin principals.

.DATE
2026-03-17

.AUTHOR
DCODEV1702 & GPT-5.4

.DESCRIPTION
This script reviews NTFS access control lists on a set of folders and flags permissions that may make an AppLocker path rule unsafe. It looks for allow rules that grant write-capable access to broad or non-admin principals such as Everyone, Users, Authenticated Users, Domain Users, or Interactive users. The output highlights findings for review before relying on path-based AppLocker controls.

.NOTES
Intent: Assess whether target folders are safe candidates for AppLocker path rules by identifying potentially risky write permissions.

.EXAMPLE
.\acl_validation.ps1
Validates the default folder list and reports whether any risky write-capable ACEs are present.

.EXAMPLE
Edit the $PathsToValidate array, then run .\acl_validation.ps1
Checks the updated folder list for risky non-admin write access.

.USAGE
Run the script in PowerShell to review the configured folder list. Update the $PathsToValidate array to match the directories you want to assess, then inspect the output to determine whether each path appears safe for AppLocker path rule use.
#>
$PathsToValidate = @(
    'C:\Foo',
    'C:\Baz',
    'C:\Bar',
    'C:\Gah'
)

$RiskPrincipals = @(
    'Everyone',
    'BUILTIN\Users',
    "$env:USERDOMAIN\Domain Users",
    'NT AUTHORITY\Authenticated Users',
    'NT AUTHORITY\INTERACTIVE'
) | Sort-Object -Unique

$WriteIndicators = @(
    [System.Security.AccessControl.FileSystemRights]::Write,
    [System.Security.AccessControl.FileSystemRights]::Modify,
    [System.Security.AccessControl.FileSystemRights]::FullControl,
    [System.Security.AccessControl.FileSystemRights]::CreateFiles,
    [System.Security.AccessControl.FileSystemRights]::CreateDirectories,
    [System.Security.AccessControl.FileSystemRights]::WriteData,
    [System.Security.AccessControl.FileSystemRights]::AppendData,
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes,
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
    [System.Security.AccessControl.FileSystemRights]::Delete,
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
)

$Findings = foreach ($Path in $PathsToValidate) {
    if (-not (Test-Path -LiteralPath $Path)) {
        [pscustomobject]@{
            Path              = $Path
            Exists            = $false
            SafeForPathRule   = $false
            IdentityReference = '<path not found>'
            AccessType        = ''
            Rights            = ''
            Inherited         = ''
            Notes             = 'Folder does not exist'
        }
        continue
    }

    $Acl = Get-Acl -LiteralPath $Path

    $SuspiciousRules = foreach ($Ace in $Acl.Access) {
        $Identity = $Ace.IdentityReference.Value
        $HasWriteLikeRight = $false

        foreach ($Right in $WriteIndicators) {
            if (($Ace.FileSystemRights -band $Right) -ne 0) {
                $HasWriteLikeRight = $true
                break
            }
        }

        $PrincipalMatch =
            $Identity -in $RiskPrincipals -or
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
                IdentityReference = $Identity
                AccessType        = $Ace.AccessControlType
                Rights            = $Ace.FileSystemRights
                Inherited         = $Ace.IsInherited
                Notes             = 'Non-admin principal appears to have write-capable access'
            }
        }
    }

    if ($SuspiciousRules) {
        $SuspiciousRules
    }
    else {
        [pscustomobject]@{
            Path              = $Path
            Exists            = $true
            SafeForPathRule   = $true
            IdentityReference = ''
            AccessType        = ''
            Rights            = ''
            Inherited         = ''
            Notes             = 'No obvious non-admin write-capable ACEs detected'
        }
    }
}

$Findings | Format-Table -AutoSize