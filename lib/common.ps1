# Shared helpers for nxstudio-ncas-forge.
# ASCII only on purpose: Windows PowerShell 5.1 reads a .ps1 without BOM as ANSI,
# so non-ASCII characters in source would break the parser.

$script:ForgePort = 8899
$script:ForgeCaCn = 'NX-Forge-CA'
$script:MitmStartedByScript = $false

function Find-Python {
    if ($env:PYTHON -and (Test-Path $env:PYTHON)) { return @{ Exe = $env:PYTHON; Prefix = @() } }

    foreach ($name in @('py.exe', 'python.exe', 'python3.exe')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $cmd -or -not $cmd.Source -or -not (Test-Path $cmd.Source)) { continue }
        if ($cmd.Source -match 'WindowsApps') { continue }   # Microsoft Store stub, not a real interpreter
        if ($name -ieq 'py.exe') { return @{ Exe = $cmd.Source; Prefix = @('-3') } }
        return @{ Exe = $cmd.Source; Prefix = @() }
    }

    $found = @()
    foreach ($root in 'HKLM:\SOFTWARE\Python\PythonCore', 'HKCU:\SOFTWARE\Python\PythonCore') {
        foreach ($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)) {
            foreach ($sub in 'InstallPath', 'InstallPath\InstallPath') {
                $ip = (Get-ItemProperty (Join-Path $k.PSPath $sub) -ErrorAction SilentlyContinue).'(default)'
                if ($ip) { $found += (Join-Path $ip 'python.exe') }
            }
        }
    }
    foreach ($pat in @((Join-Path $env:LOCALAPPDATA 'Programs\Python\Python3*\python.exe'), 'C:\Python3*\python.exe')) {
        $hit = Get-ChildItem $pat -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($hit) { $found += $hit.FullName }
    }
    foreach ($c in $found) {
        if ($c -and (Test-Path $c)) { return @{ Exe = (Resolve-Path $c).Path; Prefix = @() } }
    }
    return $null
}

function Invoke-Python {
    param([hashtable]$Py, [string[]]$PyArgs, [switch]$Quiet)
    $all = @($Py.Prefix) + $PyArgs
    if (@($all).Count -le @($Py.Prefix).Count) { throw 'Invoke-Python: no arguments supplied' }
    # A native command writing to stderr must not become a terminating error
    # just because the caller runs with $ErrorActionPreference = 'Stop'.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $out = & $Py.Exe @all 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    if (-not $Quiet) { $out | ForEach-Object { Write-Host "    $_" } }
    return @{ Code = $code; Output = ($out -join "`n") }
}

function Test-Cryptography {
    param([hashtable]$Py)
    $r = Invoke-Python -Py $Py -PyArgs @('-c', 'import cryptography;print(cryptography.__version__)') -Quiet
    if ($r.Code -eq 0) { return $r.Output.Trim() }
    return $null
}

function Test-Listening {
    param([int]$Port)
    $c = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    return (@($c).Count -gt 0)
}

function Get-SystemProxy {
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $p = Get-ItemProperty $k
    return @{ Enable = $p.ProxyEnable; Server = $p.ProxyServer; AutoConfig = $p.AutoConfigURL }
}

function Set-SystemProxy {
    param([int]$Port)
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    Set-ItemProperty -Path $k -Name ProxyEnable -Value 1 -Force
    Set-ItemProperty -Path $k -Name ProxyServer -Value ("127.0.0.1:" + $Port) -Force
}

function Restore-SystemProxy {
    param([hashtable]$State)
    $k = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    Set-ItemProperty -Path $k -Name ProxyServer -Value $State.Server -Force
    Set-ItemProperty -Path $k -Name ProxyEnable -Value $State.Enable -Force
}

function Get-ForgeMitmProcess {
    $procs = Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='py.exe'" -ErrorAction SilentlyContinue
    return @($procs | Where-Object { $_.CommandLine -and ($_.CommandLine -match 'mitm\.py') })
}

function Stop-ForgeMitm {
    $killed = @()
    foreach ($p in Get-ForgeMitmProcess) {
        Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
        $killed += $p.ProcessId
    }
    return $killed
}

function Get-NxStudioPath {
    param([string]$Hint)
    $cands = @()
    if ($Hint) { $cands += $Hint }
    $cands += @(
        'C:\Program Files\Nikon\NXStudio\NXStudio.exe',
        'C:\Program Files (x86)\Nikon\NXStudio\NXStudio.exe',
        (Join-Path $env:LOCALAPPDATA 'Nikon\NXStudio\NXStudio.exe')
    )
    foreach ($p in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\NXStudio.exe',
                     'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\NXStudio.exe')) {
        $v = (Get-ItemProperty -Path $p -ErrorAction SilentlyContinue).'(default)'
        if ($v) { $cands += $v }
    }
    foreach ($c in $cands) {
        if ($c -and (Test-Path $c)) { return (Resolve-Path $c).Path }
    }
    return $null
}

function Show-Banner {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=== ' + $Text + ' ===')
}