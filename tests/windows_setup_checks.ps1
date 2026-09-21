# No external packages, real installers, downloads, or administrator rights required.
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('repobeacon setup ' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
Copy-Item (Join-Path $PSScriptRoot '..\setup.ps1') (Join-Path $testRoot 'setup.ps1')
$initialPath = $env:Path
$initialArchitecture = $env:PROCESSOR_ARCHITECTURE
$initialWowArchitecture = $env:PROCESSOR_ARCHITEW6432
try {
    . (Join-Path $testRoot 'setup.ps1')
    $env:PROCESSOR_ARCHITECTURE = 'AMD64'
    $env:PROCESSOR_ARCHITEW6432 = 'AMD64'
    $script:calls = @()
    $script:hasPython = $false
    $script:validVenv = $false
    $script:failSetup = $false
    # Get-Command recognizes this function, avoiding any WinGet bootstrap changes.
    function winget.exe { throw 'Real installers must never run in this test.' }
    function Test-Python {
        param([string]$Program, [switch]$VirtualEnvironment)
        return $script:validVenv
    }
    function Find-Python {
        if ($script:hasPython) { return 'C:\fake python\python.exe' }
        return $null
    }
    function Invoke-Checked {
        param([string]$Program, [string[]]$Arguments)
        $script:calls += ,@($Program, ($Arguments -join '|'))
        if ($Program -eq 'winget.exe') { $script:hasPython = $true }
        if ($Arguments[0] -eq '-m' -and $Arguments[1] -eq 'venv') { $script:validVenv = $true }
        if ($script:failSetup -and ($Arguments -join '|') -eq '-m|repobeacon|setup') { throw 'synthetic installer failure' }
    }
    Start-RepoBeaconSetup
    if ($script:calls.Count -ne 5) { throw 'Fresh setup did not run Python installation, venv, pip, package installation, and scanner setup.' }
    if ($script:calls[0][1] -notlike '*Python.Python.3.12*') { throw 'Wrong Python package.' }
    if ($script:calls[-1][1] -ne '-m|repobeacon|setup') { throw 'Scanner verification was not run last.' }
    $script:calls = @()
    Start-RepoBeaconSetup
    if ($script:calls.Count -ne 3) { throw 'Repeat setup did not reuse the environment.' }
    $script:validVenv = $false
    $oldVenv = Join-Path $testRoot '.venv'
    New-Item -ItemType Directory -Path $oldVenv | Out-Null
    Set-Content -Path (Join-Path $oldVenv 'preserve-me') -Value 'old environment'
    Start-RepoBeaconSetup
    $backups = @(Get-ChildItem -Path $testRoot -Filter '.venv-backup.*' -Directory)
    if ($backups.Count -ne 1 -or -not (Test-Path (Join-Path $backups[0].FullName 'venv\preserve-me'))) { throw 'Old environment was not backed up.' }
    $script:failSetup = $true
    $caught = $false
    try { Start-RepoBeaconSetup } catch {
        if ($_.Exception.Message -ne 'synthetic installer failure') { throw }
        $caught = $true
    }
    if (-not $caught) { throw 'Installer failure was swallowed.' }
    Write-Host 'Windows bootstrap checks passed.'
} finally {
    $env:Path = $initialPath
    $env:PROCESSOR_ARCHITECTURE = $initialArchitecture
    $env:PROCESSOR_ARCHITEW6432 = $initialWowArchitecture
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
