<#
.SYNOPSIS
    Repeat-boot a DuetOS ISO under Windows QEMU and grade each serial log,
    for hunting INTERMITTENT boot-time bugs.

.DESCRIPTION
    The WSL-side rigs (tools/qemu/run.sh, tools/test/ctest-boot-smoke.sh)
    run one boot at a time under TCG (or WSL2's nested KVM, which measured
    only ~8% faster than TCG on this project's hardware). Chasing a race
    that shows up in 1 boot out of 3 needs many boots, not one slow one.

    Windows QEMU with -accel whpx boots this kernel at roughly 0.7x
    realtime -- fast enough to run a statistically useful A/B in minutes.
    Enable the accelerator once, elevated:
        Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform -All
    (requires a reboot; WSL2 running is NOT sufficient -- that is the
    Hyper-V hypervisor, WHPX is a separate optional feature).

    ACCELERATOR CAVEAT: whpx/kvm NARROW timing windows. A race that lives
    in a slow path (e.g. AP bring-up while serial writes crawl) may
    reproduce far more readily under -Accel tcg. If a bug will not
    reproduce here, re-run with -Accel tcg before concluding it is fixed.

.PARAMETER RequirePattern
    A regex that MUST appear in every run's log for that run to count.
    This is the guard against the classic false negative: a run that ends
    BEFORE the code under test executes reports zero hits and looks clean.
    Runs missing it are flagged INVALID and the summary refuses the result.

.EXAMPLE
    # TLB-shootdown ack-target race (the bug this rig was written for).
    # Pre-fix: 15 hits / 6 boots. Post-fix: 0 / 6.
    .\run-whpx-repro.ps1 -Iso duetos.iso -Runs 6 -Seconds 25 -Smp 8 `
        -Pattern 'tlb shootdown timeout' -RequirePattern 'AP online cpu_id'

.EXAMPLE
    # A/B a fix against its parent commit. Verify the control really is
    # the control by content, not by git metadata:
    #   grep -ac SomeNewSymbol base.iso   # expect 0
    .\run-whpx-repro.ps1 -Iso base.iso -Tag control -Pattern 'PANIC'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Iso,
    [string]$Pattern = 'tlb shootdown timeout',
    [string]$RequirePattern = 'AP online cpu_id',
    [int]$Runs = 6,
    [int]$Seconds = 25,
    [int]$Smp = 8,
    [int]$MemMB = 2048,
    [ValidateSet('whpx', 'tcg')][string]$Accel = 'whpx',
    [string]$Tag = 'run',
    [string]$OutDir = $env:TEMP,
    [string]$Qemu = 'C:\Program Files\qemu\qemu-system-x86_64.exe'
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Qemu)) { throw "QEMU not found: $Qemu (override with -Qemu)" }
if (-not (Test-Path -LiteralPath $Iso))  { throw "ISO not found: $Iso" }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }
$isoFull = (Resolve-Path -LiteralPath $Iso).Path

$hits = 0; $valid = 0; $invalid = 0
"iso=$isoFull accel=$Accel smp=$Smp runs=$Runs secs=$Seconds"
"pattern='$Pattern'  require='$RequirePattern'"
""

for ($i = 1; $i -le $Runs; $i++) {
    $log = Join-Path $OutDir "whpx-$Tag-$i.log"
    if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
    $qargs = @(
        '-accel', $Accel, '-machine', 'q35', '-m', "$MemMB", '-smp', "$Smp",
        '-cdrom', $isoFull, '-boot', 'd', '-display', 'none',
        '-serial', "file:$log", '-no-reboot'
    )
    $p = Start-Process -FilePath $Qemu -ArgumentList $qargs -PassThru -NoNewWindow
    Start-Sleep -Seconds $Seconds
    if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit(5000) }

    if (-not (Test-Path -LiteralPath $log)) { "run $i : NO LOG"; $invalid++; continue }
    $txt = Get-Content -LiteralPath $log -Raw -ErrorAction SilentlyContinue
    if ([string]::IsNullOrEmpty($txt)) { "run $i : EMPTY LOG"; $invalid++; continue }

    $n = ([regex]::Matches($txt, $Pattern)).Count
    $reached = if ([string]::IsNullOrEmpty($RequirePattern)) { 1 }
               else { ([regex]::Matches($txt, $RequirePattern)).Count }
    if ($reached -eq 0) {
        "run $i : INVALID - never reached '$RequirePattern' (bytes=$($txt.Length))"
        $invalid++
    } else {
        $hits += $n; $valid++
        "run $i : hits=$n reached=$reached bytes=$($txt.Length)"
    }
}

""
"=== $Tag : $hits hit(s) of '$Pattern' across $valid valid boot(s) ($invalid invalid) ==="
if ($valid -eq 0) {
    "RESULT UNUSABLE: no run reached '$RequirePattern'. Raise -Seconds until it does."
    exit 2
}
if ($invalid -gt 0) { "WARNING: $invalid run(s) excluded; they never reached the code under test." }
exit 0
