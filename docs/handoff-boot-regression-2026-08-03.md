# Boot regression handoff — 2026-08-03

State of `main` at `7383661b` and what is known about the two open boot
failures. Written so the next session starts from evidence, not from a
re-derivation.

## Where CI stands

Green: `build debug`, `build release`, `host tests (asan-ubsan)`,
`host tests (thread)`, `fuzz-all`, `clang-format`, `cargo fmt + clippy`,
`clang-tidy`.

Red: all 14 boot jobs (10 `qemu smoke`, 4 `build+smoke flavor`).

## Provenance — this is not from the landing mechanics

The last green `build.yml` on this tree was `e8669b23` (2026-07-31 09:16).
Pre-landing `main` (`e4bf541f`) was that commit plus one docs-only change,
so `main` was verified-good. Roughly 938 commits accumulated on the feature
branch after 07-31 with no green build; landing them is what exposed these.
Both failures below are pre-existing in that accumulated work.

## Open failure 1 — AP kernel stack overflow (blocks every boot job)

```
[panic-precis] sched/kstack: guard-page hit — kernel stack overflow
  caller=0xffffffff803aa51a (TrapDispatch, traps.cpp:1776)  cpu=1  hv=KVM
[W] cpu/percpu : CurrentCpu LAPIC-resolved a non-kernel GSBASE on a non-BSP
    CPU (swapgs / AP-GS gap; recovered) — REGRESSION, count 69
```

Facts established:

- Identical across every profile and both 2 and 4 vCPU: same detection RIP,
  same fallback count (69), same ~13.3 s mark. Deterministic, not a race.
- Guard addresses differ but are exactly one slot (`0x21000`) apart, so these
  are distinct stacks — **not** a slot collision.
- Resolved against the matching `duetos-kernel-debug` ELF, the overflow RIP
  `0xffffffff8039d15e` is `ApEntryFromTrampoline`, `smp.cpp:1209` — which is
  the `core::LogWithValue(..., "AP online cpu_id", ...)` call.
- Serial output at the panic is interleaved character-by-character between
  BSP and AP.

Ruled out since (all verified against the source, not assumed):

- **The AP's initial RSP is correct.** `AllocateKernelStack` returns the
  *usable* base (above the guard page, see `UsableBaseFromSlot`), and
  `smp.cpp` sets `TrampU64At(kOffStack) = stack + kKernelStackUsableBytes`,
  which is the true top of the slot. Not an off-by-one-page or
  base/top inversion.
- **Not a slot collision** — guard addresses are exactly one slot apart.
- **Not the `LinuxFdClearSlotLocked` bug** — that is fixed and the fd
  self-test passes.

The AP prints its own `AP online cpu_id` line *successfully*, then faults on
the `call` instruction at `smp.cpp:1209`. A `call` pushes a return address,
so the guard was hit by that push — meaning the stack was already at the
guard boundary before the call, after only shallow work (CPUHP transitions
and an admission spin). Genuinely consuming 128 KiB there is implausible,
so the remaining candidates are a corrupted RSP somewhere between the
trampoline and this point, or the AP running on a stack that is not the one
it was given.

Note the kstack 75% tripwire is only evaluated at *free* time, and an AP
bootstrap stack is never freed, so it cannot report on this path. The
`[tripwire]` lines in a boot log are an unrelated memory-watchpoint
self-test — do not read them as stack-depth evidence.

So an AP overflows 128 KiB inside klog, immediately on coming online.
`percpu.cpp` documents exactly this hazard: klog tags every line via
`CurrentCpuIdOrBsp()` → `CurrentCpu()`, and re-entering that while GSBASE is
stale is unbounded recursion. `CurrentCpu()`'s fallback deliberately does not
log, and the `OnTimerTick` warn sets its one-shot flag before emitting, so the
obvious two recursion guards are present — the actual cycle is not yet
identified.

`smp.cpp` was rewritten by +436 lines in the landed work, and the kernel's own
comment states a non-zero fallback count *is* the regression signal ("a clean
boot must stay at zero now the AP-bring-up GS ordering + AP lidt are fixed").
The AP-GS gap is the prime suspect as root, with the overflow as consequence.

AP init ordering in `ApSetupCurrent` reads correctly: `LoadGdtForCurrent` →
`WriteMsrGsBase` → `WriteMsrKernelGsBase` → `IdtLoadForCurrent`. The 69
fallbacks therefore come from somewhere else; finding that caller is the next
concrete step.

## CLOSED — Linux fd self-test (was "open failure 2")

**This is fixed.** Booting the post-fix artifact ISO *directly* prints

```
[proc] linux-fd-table self-test OK
```

and no fd panic. The section below was written from a bad observation and
its conclusion was wrong; it is kept only because the trap that produced it
is worth knowing.

The bad observation came from running `tools/qemu/run.sh` with
`DUETOS_SMOKE_PROFILE` set. That combination **rebuilds the ISO from
`BUILD_DIR`**, so it booted the stale local `build/x86_64-debug` tree —
a kernel predating the fix — rather than the artifact named in
`DUETOS_SMOKE_ISO`. Always boot the artifact ISO directly with
`qemu-system-x86_64 -cdrom` when validating a downloaded build.

## (superseded) Linux fd self-test still panics

```
[panic-precis] proc/linux-fd: self-test: saturated fd slot became reusable
```

`7383661b` fixed a real bug in `LinuxFdClearSlotLocked`: it seeded a local with
`kLinuxFdGenerationExhausted`, called `LinuxFdNextGeneration`, and discarded the
return — but that function zeroes `*next_out` before deciding whether the epoch
may advance, so a saturated slot was published as generation 0. That
un-retires a permanently-retired slot and violates "zero is never published".

That fix is real and is confirmed present in the shipped binary (disassembly of
`LinuxFdClearSlotLocked` shows the return value stored, not discarded).
**It is not sufficient** — booting the post-fix artifact still panics on the
same assertion. One of the other three conditions in the self-test
(`kernel/proc/process.cpp` ~5695) still fails:

```c
exhausted_slot.state != 0 ||
exhausted_slot.generation != kLinuxFdGenerationExhausted ||
LinuxFdAllocLowest(p, 15) >= 0 ||
LinuxFdNextGeneration(kLinuxFdGenerationExhausted, &forbidden_next) ||
forbidden_next != 0
```

Next step: instrument which of the five disjuncts trips. `LinuxFdAllocLowest`
returning >= 0 is the most likely remaining candidate.

Note the static contract test originally **pinned the buggy statement sequence
as the contract**, so it passed while the kernel panicked. It has been rewritten
to assert the invariant and verified to fail against the old code — but treat
the rest of the `tools/test/test-*.py` suite with the same suspicion.

## Local reproduction loop (this is the important part)

The dev host already has QEMU 8.2.2, `grub-mkrescue`, `xorriso`, `mtools` in
WSL, and `/dev/kvm` is present. There is no need to build locally — CI's
`build debug` job succeeds and uploads both the ISO and the ELF:

```bash
gh run download <run-id> -n duetos-kernel-debug -D /tmp/kern
gh run download <run-id> -n qemu-serial-log-bringup-2cpu -D /tmp/serial

# boot it (reproduces the AP overflow in ~90s)
qemu-system-x86_64 -enable-kvm -cpu host -cdrom /tmp/kern/duetos.iso \
  -smp 2 -m 512M -display none -serial stdio -no-reboot

# resolve any runtime RIP against the matching ELF
addr2line -f -C -i -e /tmp/kern/kernel/duetos-kernel.elf 0x<rip>
```

Two traps that cost time here:

- Under TCG the boot does not reach AP bringup within 60 s, so a "no overflow"
  result from a short run is meaningless. Always confirm the log contains
  `Bringing up APs` before concluding anything. Use `-enable-kvm`.
- `DUETOS_SMOKE_ISO` with a prebuilt ISO does not apply `DUETOS_SMOKE_PROFILE`
  (the profile is injected by regenerating the GRUB cmdline into a fresh ISO),
  so that combination silently boots the default profile.

Serial logs contain NUL bytes; parse them in Python
(`read_bytes().replace(b"\x00", b"")`) rather than with shell text tools.

## BREAKTHROUGH — it is not a stack overflow

Arena geometry from the boot log (`[mm] kstack self-test ok`):
`arena_base=0xffffffffe0000000 slot_bytes=0x21000`, guard 0x1000 at the LOW
edge of each slot, usable above it.

Sixteen scheduler tasks occupy slots 0..15 (their `rsp=` values are each
`slot_top - 0x38`, spaced exactly 0x21000). The AP bootstrap stack is the
next allocation, slot 16:

```
AP slot 16 usable   = [0xffffffffe0211000, 0xffffffffe0231000)
exclusive top       =  0xffffffffe0231000
smp.cpp initial RSP =  usable_base + kKernelStackUsableBytes
                    =  0xffffffffe0211000 + 0x20000
                    =  0xffffffffe0231000   <-- exactly cr2
AP's OWN guard      =  0xffffffffe0210000   <-- NOT the faulting address
rsp at panic        =  0xffffffffe022f7d0   (0x1830 BELOW the top,
                                             ~126 KiB still unused below it)
```

`cr2 = 0xffffffffe0231000` is `(cr2 - arena_base) % 0x21000 == 0`, i.e. the
base of **slot 17** — the neighbouring slot's guard page, one byte past the
top of the AP's own stack.

So the AP never came close to overflowing. Something accessed `[top]` — one
past the end — and landed on the next slot's guard. The initial RSP is the
correct exclusive-top value (the first push goes to `top-8`, which is
mapped), so the bug is whatever reads/writes *at* RSP rather than below it:
an over-pop, a `ret` on a freshly-loaded RSP, or a frame walker running off
the top. Note `DumpBacktrace` (`panic.cpp:245`) appeared as the faulting RIP
in one local run, which fits a frame walker reading past the top.

### Second, separate bug: the guard-fault classifier misattributes

`IsKernelStackGuardFault` (see `kernel/mm/kstack.h`) answers "is this address
a stack-arena guard page?" but not "is it *this* stack's guard page". A fault
on slot 17's guard while running on slot 16 is therefore reported as
`sched/kstack: guard-page hit — kernel stack overflow`, which is precisely
backwards: the stack was 99% empty and the access was above the top, not
below the bottom.

This misreport is what made the bug look like unbounded klog recursion for
hours. Fix the classifier to compare the faulting address against the
*running* stack's own slot and report over-top vs under-bottom distinctly —
it will pay for itself the next time this class appears.

## Contract-suite audit — shape-pinning is systemic

`test-linux-fd-generation-exhaustion-contract.py` passed while the kernel
panicked because it asserted the *buggy statement sequence* as its contract.
A sweep of all 105 `tools/test/test-*.py` shows that is not isolated:
**37 files assert 4 or more literal C++ statements** (`assertIn("<code>")`
where the literal contains `;`, `=`, `->`, or a qualified call).

Worst offenders by count: `service-control-ingress` (23),
`job-scheduler-linearization` (20), `thread-group` (15), `displayd-engine`
(14), `linux-sysv-ipc-id-generation` (13).

Not every one is wrong — the distinction that matters:

- **Legitimate**: pinning a *value* that is itself the contract — a syscall
  number (`SYS_SERVICE_CONTROL = 228`), an ABI constant, a capacity
  (`kAddressSpaceWriteLeaseCapacity = 32`), a `_Static_assert` on a struct
  size. Changing these should break a test.
- **Shape-pinning (harmful)**: pinning *how* the code is written when the
  contract is about behaviour — `pending.state = JobMemberState::Active`,
  `p->linux_parent = nullptr`. These ratify whatever the code currently
  does, so a bug written today becomes the contract tomorrow.

The cheap test for any such assertion: *if the code were rewritten
correctly but differently, would this assertion fail?* If yes, and the
rewrite would still satisfy the stated contract, the assertion is pinning
shape and should be replaced by one that asserts the invariant.

Any assertion rewritten this way must be verified **both** directions —
green on the fixed code and red on the broken code. Two fixes in this
session (`linux-fd-generation-exhaustion`, `kstack-guard-classify`) were
validated that way; treat it as the standard, not extra credit.

## RESOLVED — the AP boot failure (root cause + fix, verified in CI)

**Root cause.** `ap_trampoline.S` reaches `ApEntryFromTrampoline` with `jmp`,
not `call`, so nothing pushed a return address and the AP arrived with
`rsp == the stack's exclusive top`. `KBP_PROBE_V` expands to
`__builtin_return_address(0)` (`kernel/debug/probes.h:460`), which reads the
current function's return address at `[rbp+8]` — with `rsp == top` that is
exactly `[top]`, and a slot's exclusive top IS the next slot's guard-page
base. The `kSmpApOnline` probe at `smp.cpp:1210` therefore faulted on the
neighbouring guard, which is precisely why the AP printed `AP online cpu_id`
(1209) and never reached `AP pre-enter` (1225).

**Fix** (`8220ac0c`): one `push 0` before the jump. It gives the
return-address slot a mapped, zero-valued home *and* restores the SysV entry
invariant `rsp % 16 == 8` — the page-aligned top is 16-aligned, so the old
arrangement also mis-aligned SSE spill slots.

**Verified in CI run 30809302454**: `OVER-TOP` banner count 0,
`AP pre-enter` x3, `[sched/idle] armed` x4. Boot jobs went from **0/14 to
10/14**: all four `build+smoke flavor` jobs, `bringup` 2 and 4 vCPU,
`cancellation-smp` 2 and 4 vCPU, `ring3`, `browser`, `pe-hello` all pass.

The `3247f9b7` instrumentation is what made this findable in one read
instead of another round of inference — keep it.

## NEW — ElfLoaderUnwindSelfTest false-positives under live SMP

Now that SMP actually works, `linux-4cpu` and `pe-winapi-4cpu` panic with

```
[elf-test] FAIL frame leak ([full] ...)
[panic-summary] subsystem=elf-loader msg="ElfLoaderUnwindSelfTest: frame leak detected"
```

`kernel/loader/elf_loader.cpp:663` samples a **global** free-frame count
before and after the test window and panics when `after < before`, with the
comment "tolerate gains, fail loudly on missing frames".

That oracle is only sound on a quiescent uniprocessor. In the linux-4cpu log
the self-test runs at line 2915, *after* `Bringing up APs` (2448) and
`SMP bring-up complete` (2592) — three other CPUs are online and allocating.
A peer CPU's allocation inside the window is indistinguishable from this
test leaking, so the check fires on healthy boots. It is a uniprocessor-era
assertion newly exposed by the AP fix, not a regression in the ELF loader.

Fix direction: the global counter is the wrong instrument under concurrency.
Either attribute frames to the address space under test, or gate the strict
panic on uniprocessor and downgrade to WARN + probe once APs are online.
Do not simply widen the tolerance — that hides real leaks in both modes.

Separately still open: the GSBASE AP-GS gap (`CurrentCpu LAPIC-resolved a
non-kernel GSBASE on a non-BSP CPU ... REGRESSION`) still appears once per
boot. The kernel's own comment says a clean boot must stay at zero, so it is
a real defect even though the boot now succeeds.

## Smoke-matrix timeouts: complete causal chain (as of 3e730aa1)

The rotating `forbidden signature: qemu_timeout` on 4-5 profiles per run is
NOT flakiness and NOT a slow boot. The kernel stays alive — timer ticks and
the policy engine keep logging to t=473s — while tasks wedge one by one.
Evidence from `qemu-serial-log-bringup-4cpu`, run 30840251239:

```
t=12344ms  [kpath-persist] online — kpath ledger -> KERNEL.KPATH.TSV
           (the SAME FAT32 write succeeds here, while SMP is still quiet)
t=14266ms  smoke: fix_journal_summary done      <- 05121fe8 fixed this stage
t=14298ms  smoke: [kpath] visited=123/656       <- last output from the smoke task
           smoke task -> KPathPersistFlush() -> WriteScratchToVolume()
           -> Fat32{LookupPath,DeleteAtPath,CreateAtPath}  ** WEDGES **
           holding g_fat32_mutex
t=18231ms  kheartbeat: "boot-slot healthy"      <- last heartbeat EVER
           kheartbeat -> PersistBootSlotState() -> installer::PersistSlotState()
           -> WriteFileReplacing() -> the same Fat32 entries
           ** BLOCKS acquiring g_fat32_mutex **
t=18231ms .. 473480ms   455 seconds with NO heartbeat
```

Three consequences, in order:

1. The smoke task never reaches `TranslatorBootSummaryEmit`, `BootReportEmit`,
   or the `[smoke] profile=bringup complete` sentinel. The harness sees only a
   timeout.
2. `HungTaskTick()` is called from inside the heartbeat beat
   (`kernel/diag/heartbeat.cpp:377`). When the heartbeat blocked, the hung-task
   detector stopped running — which is why a task hung for 459 s produced **zero**
   hung-task warnings. The detector is fine; it simply never ran.
3. Which profile loses varies per run because it depends on when each task first
   touches FAT32 — hence the rotating failure set that looked like flakiness.

### Two separate defects here

**(a) A FAT32 write can block forever.** Root cause not yet identified. Note
the same write succeeds at t=12344ms, so the path works when uncontended; it
only wedges once SMP is busy. Suspect the block/storage layer completion wait
or contention inside the create/delete chain. `kernel/fs` is clean per
`check-spinlock-log-order.py`, so this is NOT a log-under-lock inversion.

**(b) The watchdog is blockable by the thing it watches.** `HungTaskTick()`
runs on a task that performs filesystem I/O, so any I/O hang silences the
detector that exists to report I/O hangs. This is a design defect independent
of (a), and it is why (a) presented as an opaque timeout for several CI cycles
instead of naming itself.

Fixing (b) is the higher-leverage move and should come first: it converts this
class from "opaque qemu_timeout" into a named `hung-task` report, exactly as
the guard-fault classifier in 3247f9b7 converted the AP fault from a
misattributed "stack overflow" into a one-read diagnosis.

Suggested shape for (b), in preference order:
  - Diagnostic/telemetry writers must be best-effort: give the FAT32 layer a
    bounded acquire (MutexLockTimed already exists, sched.cpp:8875) and use it
    for `PersistBootSlotState` and `KPathPersistFlush`. Real filesystem users
    keep blocking semantics; diagnostics never block.
  - Failing that, drive `HungTaskTick()` from a context that performs no I/O.
Do NOT simply reorder the beat so the tick precedes the write — a permanently
blocked beat still never runs again, so that only masks the first occurrence.

Also worth fixing regardless: a diagnostic TSV write should never sit between
the smoke sleep and the completion sentinel. Even with (a) fixed,
`KPathPersistFlush` can delay or block the sentinel that authorises QEMU exit.

## GREEN — main is fully passing again (dd45d709)

CI run 30850329459: **26/26 jobs, zero failures, 16 smoke jobs included**.
First fully-green `build.yml` on `main` since 2026-07-31 (`e8669b23`).

No `qemu-serial-log-*` artifacts were produced, and that upload is
`if: failure()` — so no smoke job failed. The smoke gate asserts the
`[smoke] profile=<name> complete` sentinel and exits non-zero when it is
missing, so green means every profile booted to completion.

### What it took, in order

Each fix exposed the next real bug; the "flaky rotating timeouts" were a
queue of stacked races, never flakiness.

| # | Defect | How it was found |
|---|--------|------------------|
| 1 | Linux fd generation epoch published as 0, un-retiring permanently-retired slots | boot self-test panic |
| 2 | `DumpBacktrace` walked one quad past the top of any stack | reading the panic path |
| 3 | Guard-fault classifier reported over-top as overflow, inverting the diagnosis | arena arithmetic |
| 4 | AP entered via `jmp` with no return address; `__builtin_return_address(0)` in `KBP_PROBE_V` read the next slot's guard page | the classifier from #3 |
| 5 | SysV `rsp % 16 == 8` entry invariant violated (latent SSE spill misalignment) | same fix as #4 |
| 6 | `ElfLoaderUnwindSelfTest` global frame-count oracle invalid under SMP | CI panic once SMP worked |
| 7 | W^X drift detector fired on CPU-managed Accessed/Dirty bits, driving 46 autonomic security escalations | live 4-minute boot |
| 8 | Intel GPU self-test surface 4x undersized — FAILed on every boot since written | live boot log |
| 9 | ACPI RSDT entries read through misaligned `const u32*` (34 UBSan reports/boot) | live boot log |
| 10 | fix-journal ABBA deadlock: `g_lock` held across a klog call | boot log localisation |
| 11 | Watchdog blockable by the filesystem it watches — a wedged FAT32 write silenced the hung-task detector for 455 s | heartbeat liveness analysis |
| 12 | Test-only OOM injection was global; a peer CPU absorbed it and panicked on `AllocateKernelStack` | decoding interleaved serial |

Three of these (#6, #12, and the free-frame comparison inside #6) are the
same class: **uniprocessor-era test scaffolding that became unsafe the moment
SMP actually worked**. Test harnesses are where SMP assumptions hide, because
they are written assuming nothing else is running.

Two were diagnostics that lied (#3, #11). Both were worth fixing before the
bugs they masked: #3 turned the AP fault from a misattributed "stack
overflow" into a one-read diagnosis, and #11 restored the detector that
names a wedged task instead of leaving an opaque `qemu_timeout`.

### Still open (nothing blocking green)

- 67 lock scopes kernel-wide log while holding a lock —
  `python tools/test/check-spinlock-log-order.py`. Each is a potential ABBA
  with the serial lock; #10 was one of them, found the expensive way.
- GSBASE AP-GS gap: `CurrentCpu LAPIC-resolved a non-kernel GSBASE on a
  non-BSP CPU ... REGRESSION` still fires once per boot. The kernel's own
  comment says a clean boot must stay at zero.
- Compositor renders offset ~285px right / ~45px down instead of filling the
  1024x768 framebuffer, and clips the security dialog.
- 37 of 108 contract tests pin literal C++ statements rather than invariants.
- The FAT32 write that can block forever is mitigated (diagnostic writers no
  longer block on it) but the underlying root cause is unfixed.
