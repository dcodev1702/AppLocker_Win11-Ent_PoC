<#
.SYNOPSIS
Backs up and hardens NTFS permissions on specified folders used with AppLocker path rule protection.

.DATE
2026-03-17

.AUTHOR
DCODEV1702 & GPT-5.4

.DESCRIPTION
This script backs up the current NTFS access control lists for one or more target folders and then applies a hardened ACL configuration. It removes inherited and existing access rules, grants full control to SYSTEM and Administrators, and limits standard user access to read and execute permissions. The script is intended to reduce the risk of writable paths being abused in AppLocker-protected environments.

.NOTES
Intent: Prepare selected directories for safer AppLocker path rule usage by backing up existing ACLs and applying a restrictive NTFS permission model.

.PARAMETER Paths
One or more folder paths to create if missing, back up, and harden.

.PARAMETER BackupFolder
Folder where ACL backup files will be stored before changes are applied.

.EXAMPLE
.\acl_ntfs_hardening.ps1
Backs up and hardens the default folder list using the default backup folder.

.EXAMPLE
.\acl_ntfs_hardening.ps1 -Paths 'C:\Foo','C:\Bar'
Backs up and hardens the ACLs on C:\Foo and C:\Bar.

.EXAMPLE
.\acl_ntfs_hardening.ps1 -BackupFolder 'C:\Temp\AclBackup'
Stores ACL backup files in C:\Temp\AclBackup before applying hardened permissions.

.EXAMPLE
.\acl_ntfs_hardening.ps1 -WhatIf
Shows what ACL backup and hardening actions would run without making changes.

.USAGE
Run the script from an elevated PowerShell session. Use -Paths to target specific folders, -BackupFolder to control where ACL backups are written, and -WhatIf to preview changes before applying them.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$Paths = @(
        'C:\Foo',
        'C:\Baz',
        'C:\Bar',
        'C:\Gah'
    ),
    [string]$BackupFolder = "C:\Temp\AppLockerAclBackup"
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $BackupFolder)) {
    New-Item -Path $BackupFolder -ItemType Directory -Force | Out-Null
}

function Backup-Acl {
    param(
        [string]$Path,
        [string]$BackupFolder
    )

    $safeName = ($Path -replace '[:\\]', '_').Trim('_')
    $backupFile = Join-Path $BackupFolder "$safeName.acl.txt"

    & icacls $Path /save $backupFile /t /c | Out-Null
    return $backupFile
}

function Set-HardenedAcl {
    param(
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }

    $acl = Get-Acl -LiteralPath $Path

    $acl.SetAccessRuleProtection($true, $false)

    foreach ($ace in @($acl.Access)) {
        [void]$acl.RemoveAccessRule($ace)
    }

    $inheritFlags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    $propFlags    = [System.Security.AccessControl.PropagationFlags]::None
    $allow        = [System.Security.AccessControl.AccessControlType]::Allow

    $rules = @(
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\SYSTEM',
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritFlags,
            $propFlags,
            $allow
        ),
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Administrators',
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            $inheritFlags,
            $propFlags,
            $allow
        ),
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            'BUILTIN\Users',
            ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute `
             -bor [System.Security.AccessControl.FileSystemRights]::Synchronize),
            $inheritFlags,
            $propFlags,
            $allow
        ),
        New-Object System.Security.AccessControl.FileSystemAccessRule(
            'NT AUTHORITY\Authenticated Users',
            ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute `
             -bor [System.Security.AccessControl.FileSystemRights]::Synchronize),
            $inheritFlags,
            $propFlags,
            $allow
        )
    )

    foreach ($rule in $rules) {
        $acl.AddAccessRule($rule)
    }

    Set-Acl -LiteralPath $Path -AclObject $acl

    & icacls $Path /inheritance:d | Out-Null
    & icacls $Path /grant:r "SYSTEM:(OI)(CI)(F)" | Out-Null
    & icacls $Path /grant:r "Administrators:(OI)(CI)(F)" | Out-Null
    & icacls $Path /grant:r "Users:(OI)(CI)(RX)" | Out-Null
    & icacls $Path /grant:r "Authenticated Users:(OI)(CI)(RX)" | Out-Null

    & icacls $Path /remove:g "Everyone" 2>$null | Out-Null
    & icacls $Path /remove:g "$env:USERDOMAIN\Domain Users" 2>$null | Out-Null

    return Get-Acl -LiteralPath $Path
}

$results = foreach ($path in $Paths) {
    if ($PSCmdlet.ShouldProcess($path, 'Backup and harden NTFS ACL')) {
        $backup = Backup-Acl -Path $path -BackupFolder $BackupFolder
        $newAcl = Set-HardenedAcl -Path $path

        [pscustomobject]@{
            Path       = $path
            BackupFile = $backup
            Owner      = $newAcl.Owner
            Access     = ($newAcl.Access | ForEach-Object {
                "$($_.IdentityReference) :: $($_.FileSystemRights) :: $($_.AccessControlType) :: Inherited=$($_.IsInherited)"
            }) -join ' | '
        }
    }
}

$results | Format-List