<#
.SYNOPSIS
  Launches the DuetOS VMM with the GDB stub enabled and spawns gdb
  pre-attached to it. Replaces the broken launch.vs.json one-click flow.

.DESCRIPTION
  WHY THIS EXISTS
    Visual Studio 2022's launch.vs.json integration for CMake-Open-Folder
    projects is fragile and was silently invalidating our kernel-debug
    config (entries flashed into the dropdown during startup, then VS's
    post-CMake validation step removed them — root cause never pinned
    down across cppdbg variants tried). This script bypasses VS's launch
    dropdown entirely.

  WHAT IT DOES
    1. Resolves duetos-vmm.exe (Windows MSVC build under
       tools/vmm/out/build/x64-Debug/) and duetos-kernel.elf (WSL clang
       build under build/x86_64-debug/kernel/).
    2. Launches the VMM with --gdb 1234 (no --break — this script is not
       a native-attach workflow; gdb is the debugger).
    3. Polls the VMM's redirected stdout for the gdb-stub-ready sentinel
       printed by gdb_server.cpp's WaitForConnection.
    4. Spawns gdb.exe in a NEW console window, pre-driven with:
         set substitute-path /root/source/DuetOS         <repo-root>
         set substitute-path /root/source/repos/DuetOS   <repo-root>
         symbol-file <duetos-kernel.elf>
         target remote localhost:1234
       so kernel symbols + DWARF source paths are resolved and the guest
       halts pre-first-instruction (matches the stopAtConnect:true
       behaviour the original launch.vs.json was trying to provide).
    5. Returns. The VMM and gdb each own their own console window.

  ONE CLICK FROM WINDOWS
    Drop a shortcut on the desktop pointing at this script:
      Target:   powershell.exe -NoProfile -ExecutionPolicy Bypass -File
                C:\Users\natew\source\repos\DuetOS\tools\vmm\debug-kernel.ps1
      Run in:   C:\Users\natew\source\repos\DuetOS
    Double-clicking that shortcut is the one-click experience.

  ALSO USABLE FROM A POWERSHELL PROMPT
    PS> tools\vmm\debug-kernel.ps1
    PS> tools\vmm\debug-kernel.ps1 -NoGdb       # launch VMM only
    PS> tools\vmm\debug-kernel.ps1 -GdbPort 5555

.PARAMETER NoGdb
  Launch the VMM with --gdb but don't auto-spawn gdb. Useful when you
  want to attach a different debugger (VS Code, Eclipse, cli gdb) by
  hand.

.PARAMETER GdbPort
  TCP port the VMM's gdb stub listens on. Defaults to 1234.

.PARAMETER NoWindow
  Pass --no-window to the VMM (headless mode, no framebuffer window).

.PARAMETER MemMB
  Guest memory size in MiB. Defaults to 2048.
#>
[CmdletBinding()]
param(
  [switch]$NoGdb,
  [int]$GdbPort = 1234,
  [switch]$NoWindow,
  [int]$MemMB = 2048
)

$ErrorActionPreference = 'Stop'

# ----- Path resolution ---------------------------------------------------
# This script lives at tools/vmm/debug-kernel.ps1, so repo root is two
# levels up. Resolve to absolute paths so the user can invoke from any
# CWD without breaking.
$scriptDir = $PSScriptRoot
$repoRoot  = (Resolve-Path (Join-Path $scriptDir '..\..')).Path

$vmmExe    = Join-Path $scriptDir 'out\build\x64-Debug\duetos-vmm.exe'
$kernelElf = Join-Path $repoRoot  'build\x86_64-debug\kernel\duetos-kernel.elf'

if (-not (Test-Path -LiteralPath $vmmExe)) {
  Write-Host ""
  Write-Error @"
duetos-vmm.exe not found at:
  $vmmExe

Build it first via Visual Studio (Open Folder tools/vmm/ → build the
duetos-vmm CMake target), or from a Dev Cmd Prompt:
  cmake --build $scriptDir\out\build\x64-Debug --target duetos-vmm
"@
  exit 1
}

if (-not (Test-Path -LiteralPath $kernelElf)) {
  Write-Host ""
  Write-Error @"
duetos-kernel.elf not found at:
  $kernelElf

Build it in WSL (the freestanding kernel is not MSVC-buildable):
  cmake --preset x86_64-debug
  cmake --build build/x86_64-debug
"@
  exit 1
}

# ----- Launch the VMM ---------------------------------------------------
# We need the VMM's stdout to detect the gdb-stub-ready line, so redirect
# to a temp log we can poll. Start-Process is async by default.
$vmmStdoutLog = Join-Path $env:TEMP "duetos-vmm-$PID.stdout.log"
$vmmStderrLog = Join-Path $env:TEMP "duetos-vmm-$PID.stderr.log"
foreach ($f in @($vmmStdoutLog, $vmmStderrLog)) {
  if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force }
}

$vmmArgs = @(
  '--kernel', $kernelElf,
  '--mem',    $MemMB,
  '--gdb',    $GdbPort
)
if ($NoWindow) { $vmmArgs += '--no-window' }

Write-Host "[debug-kernel] Starting VMM..." -ForegroundColor Cyan
Write-Host "  exe:    $vmmExe"
Write-Host "  kernel: $kernelElf"
Write-Host "  args:   $($vmmArgs -join ' ')"

$vmmProc = Start-Process -FilePath $vmmExe `
                         -ArgumentList $vmmArgs `
                         -WorkingDirectory $repoRoot `
                         -RedirectStandardOutput $vmmStdoutLog `
                         -RedirectStandardError  $vmmStderrLog `
                         -PassThru `
                         -WindowStyle Hidden

if ($NoGdb) {
  Write-Host ""
  Write-Host "[debug-kernel] VMM running, no gdb attached." -ForegroundColor Green
  Write-Host "  PID:    $($vmmProc.Id)"
  Write-Host "  gdb:    localhost:$GdbPort"
  Write-Host "  stdout: $vmmStdoutLog"
  Write-Host "  stderr: $vmmStderrLog"
  exit 0
}

# ----- Wait for the gdb stub to advertise readiness ---------------------
# gdb_server.cpp's WaitForConnection prints exactly this line right
# before accept(). Poll the log (Start-Process doesn't expose live
# stdout) with a generous timeout — large kernels and slow disks can
# push first-line emit past a second.
$readyPattern = '\[vmm\] gdb: waiting for a client on tcp:'
$deadline     = (Get-Date).AddSeconds(30)
$ready        = $false

Write-Host ""
Write-Host "[debug-kernel] Waiting for VMM gdb stub..." -ForegroundColor Cyan
while ((Get-Date) -lt $deadline) {
  if ($vmmProc.HasExited) {
    $stderr = if (Test-Path -LiteralPath $vmmStderrLog) {
      Get-Content -LiteralPath $vmmStderrLog -Raw
    } else { '<no stderr captured>' }
    Write-Host ""
    Write-Error @"
VMM exited before the gdb stub opened (exit code $($vmmProc.ExitCode)).
stderr:
$stderr
stdout was logged to: $vmmStdoutLog
"@
    exit 1
  }
  if (Test-Path -LiteralPath $vmmStdoutLog) {
    $content = Get-Content -LiteralPath $vmmStdoutLog -Raw -ErrorAction SilentlyContinue
    if ($content -and ($content -match $readyPattern)) {
      $ready = $true
      break
    }
  }
  Start-Sleep -Milliseconds 200
}

if (-not $ready) {
  Write-Host ""
  Write-Error "Timed out (30s) waiting for VMM gdb stub. Killing VMM."
  Stop-Process -Id $vmmProc.Id -Force -ErrorAction SilentlyContinue
  exit 1
}

Write-Host "[debug-kernel] gdb stub up on localhost:$GdbPort" -ForegroundColor Green

# ----- Spawn gdb in a new console window --------------------------------
# Convert backslashes to forward slashes in paths we pass to gdb — gdb
# tolerates both on Windows but forward slashes avoid escaping headaches
# inside the -ex arguments.
$repoRootFwd  = $repoRoot.Replace('\','/')
$kernelElfFwd = $kernelElf.Replace('\','/')

# Pre-driven gdb commands. We write these to a script file and invoke
# `gdb -x <file>` instead of passing each one as a `-ex` argument —
# PowerShell's Start-Process -ArgumentList does not quote array elements
# containing spaces, so `-ex "set confirm off"` would get flattened to
# four separate gdb-side args (`-ex`, `set`, `confirm`, `off`) and every
# multi-word `set` / `target remote …` / `file …` would fire wrong.
$gdbScript = Join-Path $env:TEMP "duetos-vmm-$PID.gdb"
$gdbCmds = @(
  'set confirm off',
  'set pagination off',
  'set print pretty on',
  'set disable-randomization off',
  "set substitute-path /root/source/DuetOS $repoRootFwd",
  "set substitute-path /root/source/repos/DuetOS $repoRootFwd",
  "directory $repoRootFwd",
  "file `"$kernelElfFwd`"",
  "target remote localhost:$GdbPort",
  'echo \n*** Connected to DuetOS VMM. Common commands:\n',
  'echo \  b <symbol>        set breakpoint   (e.g. b kernel_main)\n',
  'echo \  c                 continue\n',
  'echo \  bt                backtrace\n',
  'echo \  info reg          dump registers\n',
  'echo \  monitor help      VMM-side introspection (sym, lookup, read, rip, trace)\n',
  'echo \  detach            disconnect (leaves VMM running)\n',
  'echo \  q                 quit gdb (kills the VMM)\n***\n'
)
# gdb is picky about CRLF in command files on Windows — write with LF
# endings explicitly via [IO.File]::WriteAllText (Set-Content would
# emit CRLF which can confuse gdb's command parser in older builds).
[System.IO.File]::WriteAllText(
  $gdbScript,
  ($gdbCmds -join "`n") + "`n",
  [System.Text.UTF8Encoding]::new($false)
)

Write-Host "[debug-kernel] Launching gdb in a new console..." -ForegroundColor Cyan

# Start-Process with -WindowStyle Normal opens a new console window when
# the target is a console application. gdb.exe (winlibs build) is a
# console app, so this gets us a dedicated gdb TUI window.
# -x loads commands from the script we just wrote — single argument,
# no array-splat / quoting issues.
$gdbProc = Start-Process -FilePath 'gdb.exe' `
                         -ArgumentList @('-x', "`"$gdbScript`"") `
                         -WorkingDirectory $repoRoot `
                         -PassThru

Write-Host ""
Write-Host "[debug-kernel] Session live." -ForegroundColor Green
Write-Host "  VMM PID:  $($vmmProc.Id)  (stdout: $vmmStdoutLog)"
Write-Host "  gdb PID:  $($gdbProc.Id)  (new console window)"
Write-Host ""
Write-Host "Set breakpoints in the gdb window, then 'c' to start the kernel."
Write-Host "Quit gdb with 'q' to also kill the VMM; or 'detach' to leave VMM running."
