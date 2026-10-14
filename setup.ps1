<#
    nxstudio-ncas-forge - one time setup
      * locate Python + cryptography
      * generate a local CA and leaf certificate (certs/)
      * trust the CA for the current user only (Cert:\CurrentUser\Root)
      * build rules.json (forged NCAS responses)

    Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File setup.ps1
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [switch]$SkipTrust
)
$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = $PSScriptRoot }
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $RepoRoot 'lib\common.ps1')

Show-Banner 'nxstudio-ncas-forge setup'
Write-Host ("repo     : {0}" -f $RepoRoot)

$py = Find-Python
if (-not $py) {
    Write-Host 'ERROR: Python 3 not found. Install it from https://www.python.org/downloads/ and re-run.' -ForegroundColor Red
    exit 1
}
Write-Host ("python   : {0}" -f $py.Exe)

$ver = Test-Cryptography -Py $py
if (-not $ver) {
    Write-Host 'cryptography is missing - installing it now ...'
    $r = Invoke-Python -Py $py -PyArgs @('-m', 'pip', 'install', '-r', (Join-Path $RepoRoot 'requirements.txt'))
    $ver = Test-Cryptography -Py $py
    if (-not $ver) {
        Write-Host 'ERROR: could not install the cryptography package. Run this by hand:' -ForegroundColor Red
        Write-Host ("    `"{0}`" -m pip install cryptography" -f $py.Exe)
        exit 1
    }
}
Write-Host ("crypto   : {0}" -f $ver)

Show-Banner 'certificates'
$certDir = Join-Path $RepoRoot 'certs'
if ((Test-Path (Join-Path $certDir 'leaf.key.pem')) -and -not $PSBoundParameters.ContainsKey('Force')) {
    Write-Host 'certs/ already exists - reusing it (delete certs/ to rotate).'
} else {
    Invoke-Python -Py $py -PyArgs @((Join-Path $RepoRoot 'scripts\mkcerts.py'), '--out', $certDir)
}

Show-Banner 'trust the local CA (current user only)'
$caCer = Join-Path $certDir 'ca.cer'
if (-not (Test-Path $caCer)) { Write-Host ("ERROR: missing {0}" -f $caCer) -ForegroundColor Red; exit 1 }
$thirdParty = @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'NX-Forge-CA' })
if ($thirdParty.Count -gt 0 -and -not $SkipTrust) {
    Write-Host ("already trusted: {0}" -f $thirdParty[0].Thumbprint)
} elseif ($SkipTrust) {
    Write-Host 'skipped (-SkipTrust)'
} else {
    $imported = Import-Certificate -FilePath $caCer -CertStoreLocation Cert:\CurrentUser\Root
    Write-Host ("trusted: {0}" -f $imported.Thumbprint)
}

Show-Banner 'forged responses (rules.json)'
Invoke-Python -Py $py -PyArgs @((Join-Path $RepoRoot 'scripts\mkforge.py'), '--cert-dir', $certDir, '--out', (Join-Path $RepoRoot 'rules.json'))

Show-Banner 'done'
Write-Host 'Next:'
Write-Host '  * run check.ps1                     - environment self test'
Write-Host '  * run start-nxstudio.ps1            - start NX Studio without the sign in dialog'
Write-Host '  * run make-shortcut.ps1             - put a double clickable icon on the desktop'
Write-Host '  * run uninstall.ps1                 - remove the CA, the proxy and generated files'