<#
    Remove everything this project installed on this machine:
      * stop the MITM and turn the proxy off
      * remove the local CA from Cert:\CurrentUser\Root
      * delete certs/, rules.json and logs/   (-KeepFiles to keep them)

    Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File uninstall.ps1
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [switch]$KeepFiles
)
$ErrorActionPreference = 'Continue'
if (-not $RepoRoot) { $RepoRoot = $PSScriptRoot }
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $RepoRoot 'lib\common.ps1')

Show-Banner 'stop proxy + MITM'
$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty -Path $k -Name ProxyEnable -Value 0 -Force
foreach ($p in Stop-ForgeMitm) { Write-Host ("stopped MITM pid={0}" -f $p) }

Show-Banner 'remove the local CA'
$roots = @(Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -match 'NX-Forge-CA' })
if ($roots.Count -eq 0) { Write-Host 'no NX-Forge-CA in the current user root store' }
foreach ($c in $roots) {
    try {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'CurrentUser')
        $store.Open('ReadWrite')
        $store.Remove($c)
        $store.Close()
        Write-Host ("removed {0}" -f $c.Thumbprint)
    } catch {
        Write-Host ("failed to remove {0}: {1}" -f $c.Thumbprint, $_.Exception.Message)
    }
}

if (-not $KeepFiles) {
    Show-Banner 'delete generated files'
    foreach ($rel in 'certs', 'logs', 'rules.json') {
        $p = Join-Path $RepoRoot $rel
        if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue; Write-Host ("deleted {0}" -f $rel) }
    }
} else {
    Write-Host 'generated files kept (-KeepFiles)'
}
Write-Host ''
Write-Host 'uninstalled. The app will ask you to sign in again.'