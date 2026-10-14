<#
    nxstudio-ncas-forge - start NX Studio without the sign in dialog.

      1. start the local MITM (unless something already listens on the port)
      2. point the Windows proxy at it
      3. launch NX Studio
      4. when NX Studio exits: restore the previous proxy settings, stop the MITM

    Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File start-nxstudio.ps1
            powershell ... -File start-nxstudio.ps1 -App "D:\Nikon\NXStudio\NXStudio.exe"
            powershell ... -File start-nxstudio.ps1 -KeepProxy      (do not restore the proxy)
            powershell ... -File start-nxstudio.ps1 -NoSetup -SkipCheck    (raw launch)

    On the first run setup.ps1 (certificates + rules.json + CA trust) and a
    quick check.ps1 self test happen automatically, so one command is enough.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$App,
    [int]$Port = 8899,
    [int]$Timeout = 3600,
    [switch]$KeepProxy,
    [switch]$NoSetup,
    [switch]$SkipCheck
)
$ErrorActionPreference = 'Stop'
if (-not $RepoRoot) { $RepoRoot = $PSScriptRoot }
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $RepoRoot 'lib\common.ps1')

$py = Find-Python
if (-not $py) { Write-Host 'ERROR: Python 3 not found.' -ForegroundColor Red; exit 1 }

# ---- preflight: one time setup + a quick self test (skip with the switches) ----
$missing = @('rules.json', 'certs\leaf.pem', 'certs\leaf.key.pem') |
    Where-Object { -not (Test-Path (Join-Path $RepoRoot $_)) }
$caTrusted = @(Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue |
    Where-Object { $_.Subject -match 'NX-Forge-CA' }).Count -gt 0

if ((@($missing).Count -gt 0) -or (-not $caTrusted)) {
    if ($NoSetup) {
        Write-Host ("ERROR: not set up yet - missing {0} (run setup.ps1, or drop -NoSetup)." -f ((@($missing) + @('CA trust')) -join ', ')) -ForegroundColor Red
        exit 1
    }
    Write-Host 'first run - creating certificates, trusting the CA and building rules.json ...'
    & (Join-Path $RepoRoot 'setup.ps1') -RepoRoot $RepoRoot
    if ($LASTEXITCODE -ne 0) { Write-Host 'ERROR: setup.ps1 failed.' -ForegroundColor Red; exit 1 }
}

if (-not $SkipCheck) {
    & (Join-Path $RepoRoot 'check.ps1') -RepoRoot $RepoRoot -Port $Port -Quick
    if ($LASTEXITCODE -ne 0) { Write-Host 'ERROR: check.ps1 reported a problem.' -ForegroundColor Red; exit 1 }
}
$exe = Get-NxStudioPath -Hint $App
if (-not $exe) {
    Write-Host 'ERROR: NXStudio.exe not found. Pass it with -App.' -ForegroundColor Red
    exit 1
}
$ver = (Get-Item $exe).VersionInfo.FileVersion
Write-Host ("NX Studio : {0}  ({1})" -f $exe, $ver)

$logDir = Join-Path $env:TEMP 'nxstudio-ncas-forge'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$log = Join-Path $logDir ("mitm-{0}.log" -f $stamp)

$already = Test-Listening -Port $Port
if (-not $already) {
    $so = Join-Path $logDir 'mitm_stdout.txt'
    $se = Join-Path $logDir 'mitm_stderr.txt'
    $argList = @((Join-Path $RepoRoot 'scripts\mitm.py'), '--listen', "$Port",
                 '--cert', (Join-Path $RepoRoot 'certs\leaf.pem'), '--key', (Join-Path $RepoRoot 'certs\leaf.key.pem'),
                 '--log', $log, '--rules', (Join-Path $RepoRoot 'rules.json'), '--timeout', "$Timeout")
    Start-Process -FilePath $py.Exe -ArgumentList (@($py.Prefix) + $argList) -WindowStyle Hidden -RedirectStandardOutput $so -RedirectStandardError $se | Out-Null
    $up = $false
    for ($i = 0; $i -lt 25; $i++) {
        Start-Sleep -Milliseconds 400
        if (Test-Listening -Port $Port) { $up = $true; break }
    }
    if (-not $up) {
        Write-Host 'ERROR: the local MITM did not start. stderr:' -ForegroundColor Red
        Get-Content $se -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object { Write-Host "    $_" }
        exit 1
    }
    $script:MitmStartedByScript = $true
    Write-Host ("MITM      : started on 127.0.0.1:{0}" -f $Port)
} else {
    Write-Host ("MITM      : reusing the listener already on port {0}" -f $Port)
}

$before = Get-SystemProxy
Set-SystemProxy -Port $Port
Write-Host ("proxy     : {0} -> 127.0.0.1:{1}   (was Enable={2} Server={3})" -f $before.Enable, $Port, $before.Enable, $before.Server)
Write-Host ("log       : {0}" -f $log)

try {
    $p = Start-Process -FilePath $exe -PassThru
    Write-Host 'NX Studio is running - the sign in dialog should not appear. Press Ctrl+C here to stop early.'
    Wait-Process -Id $p.Id -ErrorAction SilentlyContinue
} finally {
    if (-not $KeepProxy) {
        Restore-SystemProxy -State $before
        Write-Host ("proxy     : restored (Enable={0} Server={1})" -f $before.Enable, $before.Server)
    } else {
        Write-Host 'proxy     : kept (-KeepProxy)'
    }
    if ($script:MitmStartedByScript) {
        foreach ($proc in Get-ForgeMitmProcess) { Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue }
        Write-Host 'MITM      : stopped'
    } else {
        Write-Host 'MITM      : left running (not started by this script)'
    }
    $hits = 0
    if (Test-Path $log) { $hits = @(Select-String -Path $log -Pattern 'forged|rule=' -ErrorAction SilentlyContinue).Count }
    Write-Host ("log hits  : {0} forged response(s) in {1}" -f $hits, $log)
}