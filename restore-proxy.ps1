<#
    Emergency / manual restore: turn the Windows proxy back off and stop any MITM
    process started by this project.

    Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File restore-proxy.ps1
#>
[CmdletBinding()]
param([string]$RepoRoot)
$ErrorActionPreference = 'Continue'
if (-not $RepoRoot) { $RepoRoot = $PSScriptRoot }
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $RepoRoot 'lib\common.ps1')

$before = Get-SystemProxy
Write-Host ("before: ProxyEnable={0} ProxyServer={1}" -f $before.Enable, $before.Server)
$k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Set-ItemProperty -Path $k -Name ProxyEnable -Value 0 -Force
foreach ($p in Stop-ForgeMitm) { Write-Host ("stopped MITM pid={0}" -f $p) }
$after = Get-SystemProxy
Write-Host ("after : ProxyEnable={0} ProxyServer={1}" -f $after.Enable, $after.Server)
Write-Host 'ok'