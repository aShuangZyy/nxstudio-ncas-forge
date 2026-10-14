<#
    Put double clickable icons on the desktop.

    Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File make-shortcut.ps1
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [switch]$StartupFolder
)
$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = $PSScriptRoot }
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $RepoRoot 'lib\common.ps1')

$psExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$desktop = [Environment]::GetFolderPath('Desktop')
$targets = @(
    @{ Dir = $desktop; Name = 'NX Studio (no sign in).lnk'
       Arg = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $RepoRoot 'start-nxstudio.ps1') + '"'
       Desc = 'Start NX Studio with the local forged NCAS session (proxy restored on exit)' }
    @{ Dir = $desktop; Name = 'Restore network proxy.lnk'
       Arg = '-NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $RepoRoot 'restore-proxy.ps1') + '"'
       Desc = 'Turn the forged proxy off and stop the local MITM' }
)
if ($StartupFolder) {
    $startup = [Environment]::GetFolderPath('Startup')
    $targets += @{ Dir = $startup; Name = 'NX Studio (no sign in).lnk'
                   Arg = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $RepoRoot 'start-nxstudio.ps1') + '"'
                   Desc = 'Start NX Studio with the local forged NCAS session at logon' }
}
$ws = New-Object -ComObject WScript.Shell
$nx = Get-NxStudioPath
foreach ($t in $targets) {
    if (-not (Test-Path $t.Dir)) { continue }
    $path = Join-Path $t.Dir $t.Name
    $lnk = $ws.CreateShortcut($path)
    $lnk.TargetPath = $psExe
    $lnk.Arguments = $t.Arg
    $lnk.WorkingDirectory = $RepoRoot
    $lnk.Description = $t.Desc
    if ($nx) { $lnk.IconLocation = $nx }
    $lnk.Save()
    Write-Host ("created {0}" -f $path)
}