<#
    nxstudio-ncas-forge - environment self test.
    Does not change your system proxy: the forged request is sent with an
    explicit -Proxy argument only.

    Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File check.ps1
            powershell ... -File check.ps1 -Quick      (skip the proxy round trip)

    Exit code: 0 = everything is fine, 2 = something failed.
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [int]$Port = 8899,
    [switch]$Quick
)
$ErrorActionPreference = 'Continue'
if (-not $RepoRoot) { $RepoRoot = $PSScriptRoot }
if (-not $RepoRoot) { $RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
. (Join-Path $RepoRoot 'lib\common.ps1')

$fails = 0
function Report([string]$name, [bool]$ok, [string]$detail) {
    if ($ok) { Write-Host ("[ ok ] {0,-26} {1}" -f $name, $detail) }
    else { Write-Host ("[FAIL] {0,-26} {1}" -f $name, $detail) -ForegroundColor Red; $script:fails++ }
}

Show-Banner 'nxstudio-ncas-forge check'

$py = Find-Python
Report 'python' ($null -ne $py) ($(if ($py) { $py.Exe } else { 'not found' }))
if (-not $py) { exit 1 }
$ver = Test-Cryptography -Py $py
Report 'cryptography' ($null -ne $ver) ($(if ($ver) { $ver } else { 'pip install cryptography' }))

$certDir = Join-Path $RepoRoot 'certs'
Report 'certs/leaf.pem' (Test-Path (Join-Path $certDir 'leaf.pem')) $certDir
Report 'certs/leaf.key.pem' (Test-Path (Join-Path $certDir 'leaf.key.pem')) 'private key, local only'
$trusted = @(Get-ChildItem Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match 'NX-Forge-CA' })
Report 'CA trusted (CurrentUser)' ($trusted.Count -gt 0) ($(if ($trusted.Count) { $trusted[0].Thumbprint } else { 'run setup.ps1' }))

$rules = Join-Path $RepoRoot 'rules.json'
$rulesOk = $false
$rulesDetail = 'run setup.ps1'
if (Test-Path $rules) {
    # Any response_code that starts with "E" is treated as a failure by the
    # application (see docs/how-it-works.md), so every rule body must use a
    # non-E code such as "0000".
    $codes = @()
    try {
        $json = (Get-Content $rules -Raw) | ConvertFrom-Json
        foreach ($r in $json.rules) {
            try { $b = $r.body | ConvertFrom-Json } catch { continue }
            if ($b.response_code) { $codes += [string]$b.response_code }
        }
    } catch { }
    $bad = @($codes | Where-Object { $_ -match '^E' })
    $rulesOk = ($codes.Count -gt 0) -and ($bad.Count -eq 0)
    $rulesDetail = $(if ($rulesOk) { 'success codes: ' + (($codes | Select-Object -Unique) -join ', ') }
                     elseif ($bad.Count) { 'failure code(s) in rules.json: ' + (($bad | Select-Object -Unique) -join ', ') }
                     else { 'no response_code found (setup.ps1 rebuilds it)' })
}
Report 'rules.json' $rulesOk $rulesDetail

$nx = Get-NxStudioPath
$nxVer = ''
if ($nx) { $nxVer = (Get-Item $nx).VersionInfo.FileVersion }
Report 'NX Studio' ($null -ne $nx) ($(if ($nx) { "{0}  ({1})" -f $nx, $nxVer } else { 'not found - pass -App to start-nxstudio.ps1' }))

$busy = Test-Listening -Port $Port
if ($busy) { Write-Host ("[info] port {0} is already in use - start-nxstudio.ps1 will reuse it" -f $Port) }

if ($Quick) {
    Show-Banner 'functional test'
    Write-Host '[skip] the proxy round trip (-Quick)' -ForegroundColor DarkGray
} else {
Show-Banner 'functional test (through the proxy, system settings untouched)'
$started = $false
if (-not $busy) {
    $logDir = Join-Path $env:TEMP 'nxstudio-ncas-forge'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$log = Join-Path $logDir ('check-' + (Get-Date -Format 'HHmmss') + '.log')
    $so = Join-Path $logDir 'check_stdout.txt'
    $se = Join-Path $logDir 'check_stderr.txt'
    $argList = @((Join-Path $RepoRoot 'scripts\mitm.py'), '--listen', "$Port",
                 '--cert', (Join-Path $certDir 'leaf.pem'), '--key', (Join-Path $certDir 'leaf.key.pem'),
                 '--log', $log, '--rules', $rules)
    Start-Process -FilePath $py.Exe -ArgumentList (@($py.Prefix) + $argList) -WindowStyle Hidden -RedirectStandardOutput $so -RedirectStandardError $se | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 400
        if (Test-Listening -Port $Port) { $started = $true; break }
    }
    if (-not $started) {
        Write-Host '[FAIL] the MITM could not start:' -ForegroundColor Red
        Get-Content $se -ErrorAction SilentlyContinue | Select-Object -First 10 | ForEach-Object { Write-Host "    $_" }
        $script:fails++
    }
} else {
    $started = $true
}
if ($started) {
    try {
        $r = Invoke-WebRequest 'https://faapi.www.accounts.cld.nikon.com/nxs/refresh_token' -Proxy ("http://127.0.0.1:" + $Port) -UseBasicParsing -Method POST -Body 'check=1' -TimeoutSec 25
        $ok = ($r.StatusCode -eq 200) -and ($r.Content -match '"response_code"\s*:\s*"0000"')
        Report 'forged response' $ok ("HTTP {0} {1}" -f $r.StatusCode, $r.Content.Substring(0, [Math]::Min(60, $r.Content.Length)))
    } catch {
        Report 'forged response' $false $_.Exception.Message
    }
    try {
        $r2 = Invoke-WebRequest 'https://example.com/' -Proxy ("http://127.0.0.1:" + $Port) -UseBasicParsing -TimeoutSec 25
        Report 'other hosts tunneled' ($r2.StatusCode -eq 200) ("HTTP {0} (not intercepted)" -f $r2.StatusCode)
    } catch {
        Report 'other hosts tunneled' $false $_.Exception.Message
    }
}
if ($started -and -not $busy) {
    foreach ($p in Get-ForgeMitmProcess) { Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Host '[info] test MITM stopped'
}}


Show-Banner 'summary'
if ($fails -eq 0) { Write-Host 'all checks passed.' -ForegroundColor Green; exit 0 }
Write-Host ("{0} check(s) failed." -f $fails) -ForegroundColor Red
exit 2