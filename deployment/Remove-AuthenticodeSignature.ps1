<#
.SYNOPSIS
Removes Authenticode signature blocks from PowerShell script files.

.DESCRIPTION
Strips the signature block delimited by '# SIG # Begin signature block' and
'# SIG # End signature block' from each specified file. The script preserves
the original content except for the removed signature block and rewrites the
file as UTF-8 without BOM.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [Alias('FullName')]
    [string[]]$Path
)

function Remove-AuthenticodeSignature {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$LiteralPath
    )

    if (-not (Test-Path -LiteralPath $LiteralPath -PathType Leaf)) {
        throw "File not found: $LiteralPath"
    }

    $content = Get-Content -LiteralPath $LiteralPath -Raw
    $updated = [regex]::Replace(
        $content,
        '(?s)\r?\n# SIG # Begin signature block.*# SIG # End signature block\r?\n?$',
        "`r`n"
    )

    if ($content -eq $updated) {
        return [pscustomobject]@{
            Path = $LiteralPath
            Changed = $false
            Status = 'No signature block found'
        }
    }

    if ($PSCmdlet.ShouldProcess($LiteralPath, 'Remove Authenticode signature block')) {
        [System.IO.File]::WriteAllText($LiteralPath, $updated, [System.Text.UTF8Encoding]::new($false))
    }

    [pscustomobject]@{
        Path = $LiteralPath
        Changed = $true
        Status = 'Signature block removed'
    }
}

foreach ($item in $Path) {
    Remove-AuthenticodeSignature -LiteralPath $item
}