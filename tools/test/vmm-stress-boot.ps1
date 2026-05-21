<#
.SYNOPSIS
  Stress-boot harness for the in-house VMM — launches with a chosen
  config, captures serial output to a log, terminates after a timeout,
  reports a triage summary.

.DESCRIPTION
  WHY THIS EXISTS
    Manual `tools\vmm\debug-kernel.ps1` is fine for one-shot interactive
    sessions. Stress testing needs a non-interactive harness that:
      - Can be run repeatedly (for intermittent bugs)
      - Sweeps configurations (memory size, headless, etc.)
      - Captures serial log to a stable path per run
      - Self-terminates after a timeout (the kernel never exits on its
        own under normal operation)
      - Reports a single-line PASS/FAIL plus a triage summary so a
        wrapping shell loop can decide whether to keep going

  WHAT IT DOES
    1. Launches duetos-vmm.exe with the supplied args.
    2. Sleeps for `-TimeoutSeconds` (default 60), polling for early
       exit so we don't sleep through a kernel panic.
    3. Stop-Process if still alive.
    4. Reads the captured stdout log and greps for known-bad patterns
       (PANIC, TRIPLE FAULT, kernel oops, [E], soft-lockup, ASAN, FAIL).
    5. Prints a single summary line: PASS / FAIL / EARLY-EXIT.
    6. Echoes the log path so the caller can dig in.

  EXIT CODES
    0  clean boot — no bad patterns, ran to timeout, killed cleanly
    1  bad patterns found (PANIC / TRIPLE / etc.)
    2  VMM exited early (before timeout) — usually means a crash that
       took down the VMM itself, OR --idle fired (check log for which)
    3  VMM binary or kernel ELF missing (config error)

  USAGE
    PS> tools\test\vmm-stress-boot.ps1
    PS> tools\test\vmm-stress-boot.ps1 -MemMB 256 -TimeoutSeconds 30
    PS> tools\test\vmm-stress-boot.ps1 -NoWindow -Label headless-2g

    Sweeping:
    PS> foreach ($mem in 256, 512, 2048, 8192) {
    PS>   tools\test\vmm-stress-boot.ps1 -MemMB $mem -Label "mem-$mem"
    PS> }

.PARAMETER MemMB
  Guest memory in MiB. Defaults to 2048.

.PARAMETER TimeoutSeconds
  How long to let the VMM run before killing it. Defaults to 60.

.PARAMETER NoWindow
  Launch the VMM headless (--no-window). The default also passes
  --no-window because the framebuffer window steals focus and that
  ruins long sweeps; pass -ShowWindow to override.

.PARAMETER ShowWindow
  Force the framebuffer window on. Inverts the NoWindow default.

.PARAMETER ExtraArgs
  Extra arguments forwarded to duetos-vmm.exe verbatim.

.PARAMETER Label
  Tag in log filenames so consecutive runs don't clobber each other.
  Defaults to a timestamp.

.PARAMETER LogDir
  Where to write the serial logs. Defaults to %TEMP%\duetos-stress.
#>
[CmdletBinding()]
param(
  [int]$MemMB = 2048,
  [int]$TimeoutSeconds = 60,
  [switch]$NoWindow,
  [switch]$ShowWindow,
  [string[]]$ExtraArgs = @(),
  [string]$Label = ((Get-Date).ToString('yyyyMMdd-HHmmss')),
  [string]$LogDir = (Join-Path $env:TEMP 'duetos-stress')
)

$ErrorActionPreference = 'Stop'

# Resolve repo root from this script: tools/test/<this>.ps1 → ../..
$scriptDir = $PSScriptRoot
$repoRoot  = (Resolve-Path (Join-Path $scriptDir '..\..')).Path

$vmmExe    = Join-Path $repoRoot 'tools\vmm\out\build\x64-Debug\duetos-vmm.exe'
$kernelElf = Join-Path $repoRoot 'build\x86_64-debug\kernel\duetos-kernel.elf'

if (-not (Test-Path -LiteralPath $vmmExe))    { Write-Error "VMM missing: $vmmExe";       exit 3 }
if (-not (Test-Path -LiteralPath $kernelElf)) { Write-Error "Kernel missing: $kernelElf"; exit 3 }

if (-not (Test-Path -LiteralPath $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

$stdoutLog = Join-Path $LogDir "vmm-$Label.stdout.log"
$stderrLog = Join-Path $LogDir "vmm-$Label.stderr.log"

# Default: headless. -ShowWindow overrides.
$headless = -not $ShowWindow.IsPresent
if ($NoWindow.IsPresent)  { $headless = $true }

$vmmArgs = @('--kernel', $kernelElf, '--mem', $MemMB)
if ($headless) { $vmmArgs += '--no-window' }
if ($ExtraArgs) { $vmmArgs += $ExtraArgs }

Write-Host "[stress-boot] label=$Label mem=${MemMB}M timeout=${TimeoutSeconds}s headless=$headless" -ForegroundColor Cyan
Write-Host "[stress-boot] log: $stdoutLog"

$startedAt = Get-Date
$p = Start-Process -FilePath $vmmExe -ArgumentList $vmmArgs `
                   -WorkingDirectory $repoRoot `
                   -RedirectStandardOutput $stdoutLog `
                   -RedirectStandardError  $stderrLog `
                   -PassThru -WindowStyle Hidden

# Poll for early exit so a panic doesn't make us sleep the full timeout.
$deadline = $startedAt.AddSeconds($TimeoutSeconds)
$earlyExit = $false
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { $earlyExit = $true; break }
  Start-Sleep -Milliseconds 500
}

$ranFor = ((Get-Date) - $startedAt).TotalSeconds

if (-not $p.HasExited) {
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 500  # let the file handles drain
}

# Triage the log.
$logContent = if (Test-Path -LiteralPath $stdoutLog) {
  Get-Content -LiteralPath $stdoutLog -Raw
} else { '' }

$logLines = if ($logContent) { $logContent -split "`n" } else { @() }
$lineCount = $logLines.Count

# Patterns sourced from CLAUDE.md "Fix Anything You Surface" — keep in
# sync with tools/test/boot-log-analyze.sh's bad-pattern set.
$badPatterns = @(
  'PANIC',
  'TRIPLE',
  'kernel oops',
  'unrecoverable',
  '\[E\] ',
  'soft-lockup',
  'ASAN',
  'UBSan',
  'KASAN',
  'out of range',
  'task-kill',
  '\bFAIL\b'   # \b guards against words like "FAILS" in unrelated text
)

$hits = @()
foreach ($pat in $badPatterns) {
  $matched = $logLines | Where-Object { $_ -match $pat }
  if ($matched) { $hits += [pscustomobject]@{Pattern = $pat; Lines = $matched} }
}

# Look for the boot-completed sentinel(s) — the kernel emits one of a
# few distinctive lines once the full self-test battery has finished.
$boot_done = $logLines | Where-Object {
  $_ -match '(\[smoke\] profile=.*complete|\[init\] PID 1 spawned|kernel ready)'
}

# Summary line.
$status = if ($hits.Count -gt 0) {
  'FAIL'
} elseif ($earlyExit) {
  if ($ranFor -lt 5) { 'EARLY-EXIT-EARLY' } else { 'EARLY-EXIT' }
} elseif (-not $boot_done) {
  'NO-COMPLETION-SENTINEL'
} else {
  'PASS'
}

Write-Host ""
Write-Host "[stress-boot] $status (label=$Label, ran for $([math]::Round($ranFor,1))s, $lineCount log lines)" -ForegroundColor $(if ($status -eq 'PASS') { 'Green' } else { 'Yellow' })
if ($hits.Count -gt 0) {
  Write-Host ""
  Write-Host "[stress-boot] bad-pattern hits:" -ForegroundColor Red
  foreach ($h in $hits) {
    Write-Host "  pattern: $($h.Pattern)" -ForegroundColor Red
    foreach ($l in $h.Lines | Select-Object -First 3) {
      Write-Host "    $l"
    }
    if ($h.Lines.Count -gt 3) { Write-Host "    ... and $($h.Lines.Count - 3) more" }
  }
}
if ($boot_done) {
  Write-Host "[stress-boot] completion sentinel: $($boot_done | Select-Object -First 1)" -ForegroundColor Green
}

switch ($status) {
  'FAIL'                  { exit 1 }
  'EARLY-EXIT'            { exit 2 }
  'EARLY-EXIT-EARLY'      { exit 2 }
  'NO-COMPLETION-SENTINEL'{ exit 0 }   # timeout without crash — common, not necessarily bad
  'PASS'                  { exit 0 }
}
