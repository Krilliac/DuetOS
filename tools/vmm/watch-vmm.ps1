<#
.SYNOPSIS
  Foreground duetos-vmm launcher that STREAMS the guest serial
  bring-up live to this console (and tees it to a timestamped log),
  so you can watch every boot phase scroll and spot a hang/fault as
  it happens. The graphical framebuffer opens in its own window
  alongside (blank until the desktop paints — the text you watch
  here is the kernel serial console, COM1).

.DESCRIPTION
  WHY
    The VMM window only presents the guest framebuffer; all boot
    progress goes to the kernel serial console (COM1 -> the VMM's
    stdout). Detached/redirected runs hide that. This script runs
    the VMM in the foreground with stdout teed to both the console
    and a log file, and bumps the kernel loglevel so bring-up shows
    maximum detail (driver probes, IRQ wiring, scheduler, init).

  WHAT IT DOES
    1. reap any orphan duetos-vmm from a previous run
    2. (optional) build duetos-vmm.exe (MSVC) with -Build
    3. run it foreground, cmdline "console=ttyS0 loglevel <L>"
    4. tee serial to console + tools\vmm\logs\vmm-<timestamp>.log

  Kernel ELF is produced by the WSL clang build (MSVC cannot build
  the freestanding kernel) — point -Kernel at a staged ELF.

.PARAMETER Kernel   Path to duetos-kernel.elf (default: the staged
                    x86_64-release kernel under build\).
.PARAMETER Mem      Guest RAM in MiB (default 1024).
.PARAMETER Res      Framebuffer WxH (default 1280x720).
.PARAMETER LogLevel Kernel verbosity: t=trace d=debug i=info w=warn
                    e=error (default d — full bring-up chatter;
                    use t for function entry/exit timing).
.PARAMETER Gdb      If non-zero, also expose the GDB stub on this
                    TCP port (default 0 = off).
.PARAMETER Build    Configure+build duetos-vmm.exe before running.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\vmm\watch-vmm.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tools\vmm\watch-vmm.ps1 -LogLevel t -Build
#>
[CmdletBinding()]
param(
    [string]$Kernel = "build\x86_64-release\kernel\duetos-kernel.elf",
    [int]$Mem       = 1024,
    [string]$Res    = "1280x720",
    [ValidateSet("t", "d", "i", "w", "e")]
    [string]$LogLevel = "d",
    [int]$Gdb       = 0,
    [switch]$Build
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repo

$exe = "tools\vmm\build\Debug\duetos-vmm.exe"

if ($Build)
{
    cmake -S tools\vmm -B tools\vmm\build -G "Visual Studio 17 2022" -A x64
    cmake --build tools\vmm\build --config Debug --target duetos-vmm
}

if (-not (Test-Path $exe))
{
    throw "duetos-vmm.exe not found at $exe - run with -Build first."
}
if (-not (Test-Path $Kernel))
{
    throw "kernel ELF not found at $Kernel - stage it from the WSL build first."
}

# Reap an orphan from a previous run so WHP/the window is free.
Get-Process duetos-vmm -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue

$logDir = "tools\vmm\logs"
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$log   = Join-Path $logDir "vmm-$stamp.log"

$vmmArgs = @("--kernel", $Kernel, "--mem", "$Mem", "--res", $Res,
             "--cmdline", "console=ttyS0 loglevel $LogLevel")
if ($Gdb -ne 0) { $vmmArgs += @("--gdb", "$Gdb") }

Write-Host "=== duetos-vmm: $exe" -ForegroundColor Cyan
Write-Host "=== kernel:     $Kernel"
Write-Host "=== loglevel=$LogLevel  mem=${Mem}MiB  res=$Res  gdb=$Gdb"
Write-Host "=== serial -> console + $log"
Write-Host "=== (Ctrl+C or close the framebuffer window to stop)" -ForegroundColor Cyan
Write-Host ""

# Foreground + tee: every serial line shows here AND lands in $log.
& $exe @vmmArgs 2>&1 | Tee-Object -FilePath $log
