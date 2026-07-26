<#
.SYNOPSIS
  Visual Studio (full IDE) preLaunch helper for the in-house VMM —
  the duetos-vmm analogue of tools/debug/vs-start-qemu.sh.

.DESCRIPTION
  WHAT
    Brings up everything the "Attach (in-house VMM, tcp:NNNN)"
    launch.vs.json config needs, then RETURNS (does not block) so
    Visual Studio proceeds to attach:

      1. (optional) build the freestanding kernel in WSL
      2. configure+build duetos-vmm.exe natively (MSVC)
      3. reap any orphan VMM from a previous F5 cycle
      4. launch duetos-vmm.exe detached with --gdb <port>
      5. block ONLY until the GDB port is listening, then exit 0

  WHY A WINDOWS SCRIPT (vs the bash QEMU starter)
    The VMM links WinHvPlatform and MUST run as a native Windows
    process — it cannot run inside WSL2 (no hypervisor API there).
    So, unlike the QEMU flow, the VMM + the gdb that attaches to it
    are Windows-side: point the launch config's miDebuggerPath at a
    Windows/MSYS2 gdb.exe and miDebuggerServerAddress at
    localhost:<port>. The kernel ELF is still produced by the WSL
    clang build (VS cannot build the freestanding kernel).

  USAGE (manual)
    powershell.exe -NoProfile -File tools\vmm\vs-start-vmm.ps1
  Wired one-button: see the tasks.vs.json snippet documented at the
  top of launch.vs.json.

.PARAMETER Port        GDB stub TCP port (default 1234).
.PARAMETER Preset      Kernel CMake preset (default x86_64-debug).
.PARAMETER Mem         Guest RAM in MiB (default 2048).
.PARAMETER BuildKernel Also build the kernel via WSL first.
.PARAMETER WslPath     Repo path as seen inside WSL (for -BuildKernel;
                        default derives from the Windows repo root).
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]    $Port        = 1234,
    [ValidatePattern('^[A-Za-z0-9_.-]+$')]
    [string] $Preset      = "x86_64-debug",
    [ValidateRange(256, 65536)]
    [int]    $Mem         = 2048,
    [switch] $BuildKernel,
    [string] $WslPath     = ""
)

$ErrorActionPreference = "Stop"

# Repo root = two levels up from this script (tools/vmm/..).
$RepoRoot  = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$KernelElf = Join-Path $RepoRoot "build\$Preset\kernel\duetos-kernel.elf"
$VmmBuild  = Join-Path $PSScriptRoot "build"
$VmmExe    = Join-Path $VmmBuild "Debug\duetos-vmm.exe"
$repoHashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
    [System.Text.Encoding]::UTF8.GetBytes($RepoRoot.ToLowerInvariant()))
$repoHash = ([BitConverter]::ToString($repoHashBytes) -replace '-', '').Substring(0, 12)
$PidFile = Join-Path $env:TEMP "duetos-vmm-$repoHash-$Port.pid"

function Say($m) { Write-Host "[duetos-vmm] $m" }

# 1. Optional kernel build (WSL clang — VS can't build it).
if ($BuildKernel) {
    if (-not $WslPath) {
        # Best-effort Windows->WSL path mapping for the common case
        # of a repo on a drive (C:\foo -> /mnt/c/foo). Written for
        # Windows PowerShell 5.1 (no scriptblock -replace there).
        if ($RepoRoot -match '^([A-Za-z]):(.*)$') {
            $WslPath = "/mnt/" + $Matches[1].ToLower() +
                       ($Matches[2] -replace '\\','/')
        } else {
            $WslPath = $RepoRoot -replace '\\','/'
        }
    }
    Say "building kernel in WSL ($WslPath, preset=$Preset)"
    wsl.exe -- bash -lc "cd '$WslPath' && cmake --preset '$Preset' && cmake --build 'build/$Preset' --target duetos-kernel"
    if ($LASTEXITCODE -ne 0) { throw "WSL kernel build failed" }
}

if (-not (Test-Path $KernelElf)) {
    throw "kernel ELF not found: $KernelElf`n" +
          "Build it first in WSL: cmake --preset $Preset && " +
          "cmake --build build/$Preset  (or pass -BuildKernel)."
}

# 2. Configure + build the VMM (native MSVC).
if (-not (Test-Path (Join-Path $VmmBuild "CMakeCache.txt"))) {
    Say "configuring VMM (VS 2022 / x64)"
    cmake -S $PSScriptRoot -B $VmmBuild -G "Visual Studio 17 2022" -A x64
    if ($LASTEXITCODE -ne 0) { throw "VMM configure failed" }
}
Say "building VMM"
cmake --build $VmmBuild --config Debug
if ($LASTEXITCODE -ne 0) { throw "VMM build failed" }

# 3. Reap an orphan VMM from a previous F5 cycle.
if (Test-Path $PidFile) {
    $old = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($old -and ($old -match '^\d+$')) {
        $oldProcess = Get-Process -Id ([int]$old) -ErrorAction SilentlyContinue
        $oldPath = if ($oldProcess) {
            try { $oldProcess.Path } catch { $null }
        }
        if ($oldPath -and
            ([IO.Path]::GetFullPath($oldPath) -eq [IO.Path]::GetFullPath($VmmExe))) {
            Say "stopping prior VMM pid $old"
            $oldProcess | Stop-Process -Force -ErrorAction SilentlyContinue
        } elseif ($oldProcess) {
            Say "ignoring stale pid file; pid $old is not this VMM"
        }
    }
    Remove-Item $PidFile -ErrorAction SilentlyContinue
}

# 4. Launch the VMM detached; it parks on accept() until VS attaches.
Say "starting $VmmExe --gdb $Port"
$quotedKernelElf = '"' + $KernelElf + '"'
$vmmArguments = "--kernel $quotedKernelElf --mem $Mem --gdb $Port"
$p = Start-Process -FilePath $VmmExe `
        -ArgumentList $vmmArguments `
        -PassThru `
        -WindowStyle Hidden
Set-Content -Path $PidFile -Value $p.Id

# 5. Return only once the stub owns a LISTEN socket without connecting.
#    A connection probe would consume the GDB server's only client slot.
#    Do not wait on the process — VS needs control back after readiness.
if (-not (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue)) {
    throw "Get-NetTCPConnection is required for a non-consuming GDB readiness check"
}
$listenDeadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $listenDeadline) {
    if ($p.HasExited) { throw "VMM exited early (code $($p.ExitCode))" }
    $listener = Get-NetTCPConnection -State Listen -LocalPort $Port `
                    -OwningProcess $p.Id -ErrorAction SilentlyContinue |
                Select-Object -First 1
    if ($listener) {
        Say "tcp:$Port listening - Visual Studio may attach"
        exit 0
    }
    Start-Sleep -Milliseconds 250
}
throw "VMM did not reach LISTEN on tcp:$Port within 15 seconds (PID $($p.Id))"
