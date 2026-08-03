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
