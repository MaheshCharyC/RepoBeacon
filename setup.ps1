# Works with Windows PowerShell 5.1 and PowerShell 7. Use .\setup.cmd from PS or CMD.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "$Program failed (exit status $LASTEXITCODE). Review its output above."
    }
}

function Update-SessionPath {
    $env:Path = @($env:Path, [Environment]::GetEnvironmentVariable('Path', 'Machine'), [Environment]::GetEnvironmentVariable('Path', 'User'), "$env:LOCALAPPDATA\Microsoft\WindowsApps", "$env:LOCALAPPDATA\Microsoft\WinGet\Links") -join ';'
}

function Test-Python {
    param([string]$Program, [switch]$VirtualEnvironment)
    if (-not $Program -or -not (Test-Path -LiteralPath $Program -PathType Leaf)) { return $false }
    $probe = 'import sys, tarfile, struct; assert sys.version_info >= (3,10); assert hasattr(tarfile,"data_filter"); assert struct.calcsize("P") == 8'
    if ($VirtualEnvironment) { $probe += '; assert sys.prefix != sys.base_prefix' }
    try {
        & $Program -c $probe 2>$null | Out-Null
        return $LASTEXITCODE -eq 0
    } catch { return $false }
}

function Find-Python {
    $candidates = @("$env:LOCALAPPDATA\Programs\Python\Python312\python.exe", "$env:ProgramFiles\Python312\python.exe")
    $launcher = Get-Command py.exe -ErrorAction SilentlyContinue
    if ($launcher) {
        try {
            $located = & $launcher.Source -3.12 -c 'import sys; print(sys.executable)' 2>$null
            if ($LASTEXITCODE -eq 0) { $candidates += $located }
        } catch { }
    }
    foreach ($command in @(Get-Command python.exe -All -ErrorAction SilentlyContinue)) {
        # Do not invoke the Store alias, which can open a GUI instead of running Python.
        if ($command.Source -notlike '*\Microsoft\WindowsApps\*') { $candidates += $command.Source }
    }
    foreach ($candidate in $candidates) {
        if (Test-Python $candidate) { return $candidate }
    }
    return $null
}

function Start-RepoBeaconSetup {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Invoke-Checked 'bash' @((Join-Path $PSScriptRoot 'setup.sh'))
        return
    }
    $wowArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
    $architecture = if ($wowArchitecture) { $wowArchitecture } else { [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
    if ($architecture -ne 'AMD64') { throw 'The complete Windows scanner stack currently requires x64 Windows. ARM64 and 32-bit Windows are not supported by this setup.' }
    if ([Environment]::OSVersion.Version.Build -lt 17763) { throw 'Setup requires Windows 10 version 1809 or newer, or Windows 11.' }

    Write-Host "RepoBeacon setup: Windows x64, $($PSVersionTable.PSEdition) PowerShell $($PSVersionTable.PSVersion)."
    Write-Host 'Keep this terminal open and follow installer prompts. Downloads require several GB of disk space.'
    Push-Location -LiteralPath $PSScriptRoot
    try {
        Write-Host '[1/3] Checking WinGet and Python...'
        Update-SessionPath
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) {
            Write-Host 'Installing WinGet using the official Microsoft.WinGet.Client module...'
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            if ($PSVersionTable.PSVersion.Major -le 5) {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force | Out-Null
            }
            Install-Module -Name Microsoft.WinGet.Client -Repository PSGallery -Scope CurrentUser -Force
            Import-Module Microsoft.WinGet.Client
            Repair-WinGetPackageManager
            Update-SessionPath
        }
        if (-not (Get-Command winget.exe -ErrorAction SilentlyContinue)) { throw 'WinGet is still unavailable. Install/update Microsoft App Installer, then rerun .\setup.cmd.' }

        $venv = Join-Path $PSScriptRoot '.venv'
        $venvPython = Join-Path $venv 'Scripts\python.exe'
        if ((Test-Path -LiteralPath $venv) -and ((Get-Item -LiteralPath $venv -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'The .venv folder is a link or junction. Move it aside before running setup.'
        }
        if (-not (Test-Python $venvPython -VirtualEnvironment)) {
            $python = Find-Python
            if (-not $python) {
                Invoke-Checked 'winget.exe' @('install', '--id', 'Python.Python.3.12', '--exact', '--source', 'winget', '--scope', 'user', '--architecture', 'x64', '--accept-source-agreements', '--accept-package-agreements')
                Update-SessionPath
                $python = Find-Python
            }
            if (-not $python) { throw 'A working 64-bit Python 3.10+ was not found after installation. Review the installer output and rerun .\setup.cmd.' }
            if (Test-Path -LiteralPath $venv) {
                $backup = Join-Path $PSScriptRoot ('.venv-backup.' + [Guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $backup | Out-Null
                Move-Item -LiteralPath $venv -Destination (Join-Path $backup 'venv')
                Write-Host "Saved the old or broken environment to $backup\venv"
            }
            Invoke-Checked $python @('-m', 'venv', $venv)
        }
        Write-Host '[2/3] Installing RepoBeacon in its private Python environment...'
        Invoke-Checked $venvPython @('-m', 'pip', 'install', '--upgrade', 'pip')
        Invoke-Checked $venvPython @('-m', 'pip', 'install', '-e', '.')
        Write-Host '[3/3] Installing and verifying all four scanners...'
        Invoke-Checked $venvPython @('-m', 'repobeacon', 'setup')
        Write-Host ''
        Write-Host 'Next, from the RepoBeacon folder, run:'
        Write-Host '.\.venv\Scripts\repobeacon.exe scan "C:\path\to\your-project"'
        Write-Host 'The report opens in your default browser when the scan finishes.'
    } finally { Pop-Location }
}

# Dot-sourcing loads functions for installer tests without changing the machine.
if ($MyInvocation.InvocationName -ne '.') {
    try { Start-RepoBeaconSetup } catch {
        [Console]::Error.WriteLine("Setup stopped: $($_.Exception.Message)")
        [Console]::Error.WriteLine('Fix the error above, then rerun .\setup.cmd. Managed Windows policies may require your IT administrator.')
        exit 1
    }
}
