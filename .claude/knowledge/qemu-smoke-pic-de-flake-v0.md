# QEMU smoke #DE flake at PicDisable — observed 2026-04-30

## Status (2026-04-30)

**Fixed** — `PicDisable` now masks the chip BEFORE the ICW1 init
sequence and runs the whole reconfigure with IF=0 (saved/restored
across the function). The crash was hypothesis (3) below: a held
legacy-IRQ line delivered to the master 8259's pre-init vector base
of 0 (= #DE handler) during the multi-port reconfigure window.
Mask-first + CLI-around eliminates both delivery paths.

The smoke harness is now also single-attempt: any
`DUETOS CRASH` / `PANIC` / `triple fault` / `[health] ESCALATE`
is an immediate exit-1 in `profile-boot-smoke.sh` and
`ctest-boot-smoke.sh`, and the workflow retry-loops in `build.yml`
+ `release.yml` were collapsed to single attempts. Crashes that
"pass on retry" no longer hide.

Original observation kept below for the audit trail.

---

## Original observation

Flake reproduced only on GitHub-hosted runners under TCG; not
reproduced on the dev host (also TCG, no /dev/kvm).
`ctest-boot-smoke.sh`'s exit-3 retry path used to catch it: the
second attempt lands all 33 signatures and the job reported
SUCCESS — which is exactly what made the bug invisible until a
serial-log scrub turned it up.

## Symptom

`qemu smoke (ring3)` first attempt emits a `=== DUETOS CRASH DUMP
BEGIN ===` block immediately after `[boot] Disabling 8259 PIC.` and
before `[boot] Bringing up LAPIC.`. Vector reported as 0 (`#DE
Divide-by-zero`). Saved RIP `0xffffffff8010bbe1`.

`addr2line` resolves the saved RIP to `kernel/arch/x86_64/cpu.h:18`
inside `duetos::arch::Outb`. `objdump` confirms the byte at the
saved RIP is `add $0x4, %rsp` — the very next instruction after
`out %al, (%dx)` in the function epilogue. There is no `div`/`idiv`
anywhere in `Outb`, `IoWait`, or `PicDisable`, so a hardware #DE at
that RIP is structurally impossible.

`rflags` in the dump shows `IF=1` (interrupts enabled). `cs=0x08`
(kernel ring 0). The lower-half register values (`rax`, `rcx`,
`r10`, `r12..r15`) look like ACPI-table physical addresses cached
during `AmlNamespaceBuild`, consistent with this firing immediately
after the ACPI phase.

## Working hypotheses (not yet narrowed)

1. **IDT corruption** — some IDT slot's gate-type or offset field
   silently regressed during ACPI parsing, so when an IRQ from the
   LAPIC timer / 8259 / HPET fires asynchronously, the CPU dispatches
   to `isr_0` (the #DE stub) instead of the real handler. The
   reported "vector 0" then comes from the stub itself, and the
   saved RIP is post-`out` because IRQs are trap-class (saved RIP =
   next instruction after the interrupted one).

2. **ACPI parser stomping the IDT page** — `AmlNamespaceBuild` walks
   parser scratch buffers; if a write went out of bounds in TCG's
   slow-path code generator, a stray store could clobber an IDT
   gate. Would explain why we don't see this on KVM (different
   dispatch path) and why it's intermittent (depends on parser
   buffer alignment, which can shift commit-to-commit).

3. **PIC remap race under TCG** — between ICW1 and OCW1 the master
   8259 is in init mode. TCG's PIC model might allow a held legacy-
   timer line to deliver to a stale vector base. If the *previous*
   (firmware) base was 0 the IRQ would land at vector 0 = #DE stub.
   The dump's `IF=1` is consistent with this.

   Plausibility check: the BIOS / GRUB hand-off normally programs
   the master to base 0x08, not 0x00, so a stale base of 0 would
   require GRUB or the multiboot stub to leave the PIC unprogrammed.
   Worth checking with the qemu interrupt trace.

## Next-session investigation steps

1. Pull the `qemu.log` artifact from a flaking run (`-d int,cpu_reset`
   is already on). Look for the last `check_exception` line before
   the crash dump. That tells us the actual hardware vector.

2. Compare `qemu.log` from a clean run vs a flaking run on the same
   commit. The delta in the interrupt stream is the smoking gun.

3. If hypothesis (1) is right: dump the IDT after `IdtInit()` and
   again right before `PicDisable()` — any delta is the bug.

4. If hypothesis (2) is right: KASAN or `mm/heap` poison-on-free
   would catch it. Wait for KASAN runtime to land.

5. If hypothesis (3) is right: mask the 8259 *first* (`Outb(0x21,
   0xFF); Outb(0xa1, 0xFF);`) before sending ICW1. That guarantees
   no IRQ can be delivered while the chip is in init mode regardless
   of what base it had.

   This is also a strict improvement on the existing PicDisable
   sequence — the OCW1 mask currently runs last. Even if (3) isn't
   the bug, mask-first is the safer ordering on real hardware too.

## Pointers

- Crash site: `kernel/arch/x86_64/cpu.h:15` (`Outb`)
- Caller: `kernel/arch/x86_64/pic.cpp:31` (`PicDisable`)
- Boot path: `kernel/core/main.cpp:1381..1382`
- Smoke retry: `tools/test/ctest-boot-smoke.sh:252..262` (exit 3)
- Vector name table: `kernel/arch/x86_64/traps.cpp:209..240`
- Exception stubs: `kernel/arch/x86_64/exceptions.S:53` (`ISR_NOERR 0`)

## Resume prompt

> Investigate the early-boot #DE flake on GitHub-hosted runners
> documented in `.claude/knowledge/qemu-smoke-pic-de-flake-v0.md`.
> Pull the `qemu.log` artifact from a flaking run (look for the last
> `check_exception` before `=== DUETOS CRASH DUMP BEGIN ===`) and
> determine which of the three hypotheses applies: IDT corruption,
> ACPI parser stomp, or PIC remap race. If (3), the strict-improvement
> fix is mask-first in `PicDisable` — see step 5 in the entry.
