# qemu-smoke profile-matrix redesign — split monolith into per-profile jobs

**Last updated:** 2026-04-28
**Type:** Decision + Pattern
**Status:** Active

## Background

The pre-redesign qemu-smoke job booted the entire kernel (drivers, self-tests,
ring3 trio, every PE smoke, every Linux ABI smoke) inside a single QEMU run
and grepped a flat list of ~30 expected signatures out of the serial log.
Two structural problems:

1. **Wall-clock fragility.** The full boot needed to reach `Phase::Userland`
   AND run all spawned tasks to completion before any required signature
   appeared. Under TCG / oversubscribed-KVM the runner's ~30-40:1 wall:guest
   ratio meant a single attempt needed 1500s+ wall. Each iteration of
   "skip more under emulator" only nudged the budget.

2. **Single point of opacity.** A latent hang anywhere — driver init,
   ring3 spawn, PE load, Linux smoke — masked every other check. The
   logs interleaved at byte level (`SerialWrite` was unlocked) so even
   identifying where the kernel got to required forensics.

## Redesign

Split the smoke into independently-bootable **profiles**. Each profile boots
the kernel through the SAME bringup phase (driver / self-test coverage
unchanged), runs ONE focused scenario, prints a sentinel, and exits QEMU
cleanly via `arch::TestExit` → isa-debug-exit port. CI runs the profiles
in parallel as a job matrix.

### Profile catalog

| Profile      | Spawns                                  | ProfileExpectedExits | Required signatures |
|--------------|-----------------------------------------|----------------------|---------------------|
| `none`       | (everything — full bare-metal boot)     | (n/a, no exit path)  | (n/a)               |
| `bringup`    | nothing                                 | 0                    | bringup-complete + sentinel |
| `ring3`      | ring3-smoke-A/B/sandbox                 | 3                    | "Hello from ring 3!" + queued lines |
| `pe-hello`   | ring3-hello-pe                          | 1                    | `[hello-pe]` + spawn line |
| `pe-winapi`  | ring3-hello-winapi                      | 1                    | full `[vcruntime140]/[strings]/[heap]/[advapi]/[perf-counter]/[calc]/[files]/[clock]/[block]` battery + `exit rc val=0xbeef` |
| `pe-winkill` | ring3-winkill                           | 1                    | `pe spawn name=ring3-winkill` + `Windows Kill ` |
| `linux`      | SpawnRing3LinuxSmoke (only — see below) | 1                    | `linux` substring     |

### Selection mechanism

Kernel cmdline arg `smoke=<profile>` parsed by `kernel/test/smoke_profile.cpp`
out of the Multiboot2 cmdline tag. Default = `smoke=none` = "no profile",
preserves pre-redesign full-boot behavior.

`tools/qemu/run.sh` reads `DUETOS_SMOKE_PROFILE=<name>` and regenerates a
single-entry grub.cfg + smoke ISO with `multiboot2 ... smoke=<name>` baked
into the cmdline. `-device isa-debug-exit,iobase=0xf4,iosize=0x01` is added
unconditionally to QEMU args (no-op without a smoke profile).

### Exit mechanism

`arch::TestExit(0x10)` issues `OUT 0xf4, 0x10`; QEMU's isa-debug-exit
device terminates the process with status `(0x10 << 1) | 1 = 0x21`.
Real hardware is unaffected — port 0xf4 has no listener.

### When to call SmokeProfileSleepAndExit

After all profile-gated spawn sites have run (ring3 spawns, PE spawns,
Linux smokes) but BEFORE `SmpStartAps` and the `Phase::Userland` self-test
tail. Order matters: spawning, then waiting, then exiting. Under
profile=None the function returns and the caller continues into the
regular boot tail (idle loop + heartbeat thread).

### Polling strategy

Inside `SmokeProfileSleepAndExit`:
1. Capture `baseline_exited = sched::SchedStatsRead().tasks_exited`.
2. Loop: sleep 100ms (10 ticks), re-read tasks_exited, break when
   `tasks_exited >= baseline_exited + ProfileExpectedExits(profile)`.
3. Bounded by per-profile deadline (10–30s of guest) so a real wedge
   doesn't hang the test forever.
4. Final 100ms settle for reaper-tail logs to flush.
5. Sentinel `[smoke] profile=<name> complete`.
6. `arch::TestExit(0x10)`.

### Pitfall 4 — multi-call SerialWrite line splitting

`arch::SerialWrite` is atomic at the function level (per-call IRQ-off
spinlock with re-entry bypass), but multi-call sequences are not.
`SpawnRing3Task` and `SpawnPeFile` print one logical line via 9-12
consecutive SerialWrite calls. Between calls the lock is released and
IRQs re-enabled; a concurrent task printing in that window splits the
line at every call boundary.

Symptom: CI ring3 smoke missed `queued task name="ring3-smoke-B"`
because the visible log showed the line as `ring3-smoke-B" pid=0x...`
— the `[ring3] queued task name="` prefix got eaten by another
task's output. Same shape for pe-winapi's `[heap] HeapAlloc + GetProcessHe`
truncation.

**Fix:** `arch::SerialLineGuard` RAII helper (kernel/arch/x86_64/
serial.{h,cpp}). Holds the lock + sets the in-progress flag for the
whole scope; nested SerialWrite calls inside bypass their own per-call
acquire and write under the held lock. Wrap the multi-call print
sequences in a SerialLineGuard scope.

### Pitfall 5 — KVM-hidden Intel thermal MSRs

KVM hypervisors don't always expose `IA32_THERM_STATUS` /
`TEMPERATURE_TARGET` / `IA32_PACKAGE_THERM_STATUS` to guests, even on
Intel hosts. `rdmsr` against an unsupported MSR raises #GP that the
kernel's trap dispatcher doesn't recover from (no extable for the
thermal-probe RIPs). On a CI runner with hidden MSRs, the boot wedges
at `[boot] Reading MSR thermals.`; same code on a sister runner with
exposed MSRs passes.

**Fix:** gate `ThermalProbe()` on `arch::IsEmulator()`. Bare-metal
Intel + TCG (silently returns 0) keep working; under any KVM/HVM the
probe is skipped. Smoke critical path doesn't assert thermal output,
so this is observability-only loss.

## Pitfalls discovered (and fixed)

### Pitfall 0 — KMalloc + freed-page poison

KMalloc returns memory carrying the C2 freed-page poison `0xDE` bytes.
KMalloc'd structs that embed sync primitives (`SpinLock`, `Mutex`,
`HandleTable`) MUST be `memset(p, 0, sizeof(*p))` immediately after
the allocation. The serial / scheduler / process / linux-clone paths
all hit this; see `.claude/knowledge/kmalloc-zero-init-pattern.md` for
the full pattern + audit checklist.

### Pitfall 1 — absolute `tasks_live <= constant_baseline`

First poll-based attempt used `tasks_live <= kPostBringupBaseline` where
the baseline was a guessed constant (16). Actual post-bringup steady-state
on QEMU was BELOW 16, so the loop broke on the very first iteration before
any spawned task ran. Result: pe-winapi failed in 72s wall with no
required signatures present.

**Fix:** count expected exits per profile and wait for `tasks_exited`
to grow by exactly that delta from a baseline captured at SleepAndExit
entry. Lockstep maintenance — every ShouldSpawn truth-table entry has
a 1:1 ProfileExpectedExits sibling.

### Pitfall 2 — workers contaminate `tasks_exited`

Scheduler self-test workers (worker-A/B/C) loop 5 times then return.
`SchedTaskTrampoline` tail-calls `SchedExitC` on return, bumping
`g_tasks_exited`. Workers complete in <1s of guest post-spawn — usually
during the smoke profile's polling window — falsely satisfying the delta.

**Fix:** gate worker spawn behind `SmokeProfileGet() == SmokeProfile::None`.
Workers don't add signature coverage the smoke wrapper checks; bare-metal
profile=None runs them as before.

The kernel-built reader threads (kbd-reader, ui-ticker, mouse-reader,
win-timer) loop forever waiting on hardware events and NEVER exit, so
they don't pollute tasks_exited. They stay in the always-on path.

### Pitfall 3 — Linux profile spawns 7 ABI smokes, can't fit in budget

LinuxSmoke + 6 friends serialize through AddressSpaceCreate + ELF parse
+ Process create + scheduler queue + actual run + reap. At ~12:1
wall:guest = ~80-100s of wall per smoke. Seven of them = ~700s wall,
beyond per-profile 480s budget.

**Fix:** under profile=Linux, spawn only `SpawnRing3LinuxSmoke`. The
smoke wrapper asserts only on the substring "linux" appearing in the
log — one successful Linux ABI path covers it. The other six smokes
(ElfSmoke, FileSmoke, MmapSmoke, SynxTestElf, TranslateSmoke,
ExtendSmoke) + the FAT32 LINUX.ELF autospawn run on bare-metal
profile=None for full coverage.

## Adding a new profile

1. Append to `enum class SmokeProfile` in `kernel/test/smoke_profile.h`.
2. Append a parser branch + name in `kernel/test/smoke_profile.cpp`'s
   `SmokeProfileInit` and `SmokeProfileName`.
3. Append a `ProfileExpectedExits` case + a `ProfileDeadlineTicks` case.
4. If the profile needs a new spawn site, also append a `SmokeTarget`
   enum value + a `ShouldSpawn` case + the spawn-site gate at the
   call site. Lockstep: ShouldSpawn returns true under the new profile,
   ProfileExpectedExits matches the spawn count.
5. Append the profile to the matrix in `.github/workflows/build.yml`'s
   `qemu-smoke` job.
6. Append a per-profile signature list to `tools/test/profile-boot-smoke.sh`.

## Related files

- `kernel/test/smoke_profile.{h,cpp}` — profile dispatcher
- `kernel/arch/x86_64/cpu.h::TestExit` — isa-debug-exit
- `kernel/arch/x86_64/serial.{h,cpp}` — phase-1 serial spinlock
- `kernel/core/main.cpp` — `SmokeProfileInit` early call, `ShouldSpawn`
  gates around Linux smokes + worker self-test, `SmokeProfileSleepAndExit`
  call before `SmpStartAps`
- `kernel/proc/ring3_smoke.cpp` — `ShouldSpawn` gates around ring3-trio
  + 3 essential PEs (hello-pe, hello-winapi, winkill)
- `tools/qemu/run.sh` — per-profile ISO regeneration + isa-debug-exit
- `tools/test/profile-boot-smoke.sh` — per-profile signature lists
- `.github/workflows/build.yml` — qemu-smoke matrix job + host-tests job

## Related sibling: hosted unit tests (Phase 3)

`tests/host/` is a separate CMake project that builds with the host
system clang/g++ + glibc + ASan + UBSan. Scope today: arch-neutral
header-only kernel TUs (Result<T,E>, freestanding string primitives).
Adding a new test = drop `test_<thing>.cpp` + one-line append to
`tests/host/CMakeLists.txt`'s `add_host_test()` list. Target list to
expand to as kernel TUs grow `#ifdef DUETOS_HOST_TEST` shims:
paging math, MutexLock state machine, FAT32 LFN parser, slab allocator,
Result<T,E>::ErrorCode table, klog format helpers.
