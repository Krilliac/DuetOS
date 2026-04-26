# Boot stack high-VMA alias — fixes #DF on first boot→user context switch under load

**Last updated:** 2026-04-26
**Type:** Issue + Pattern
**Status:** Active

## Description

The boot task's kernel stack (`stack_top` in `.bss.boot`) was linked at
the LOW virtual address (≈ phys 1 MiB, identity-mapped). Per-process
address spaces zero PML4[0..255] (the user half) at create time, so the
moment `Schedule()` activated a user AS while the boot task was the
running task, the boot stack VA became unmapped — the very next
push/pop on `prev`'s stack between `AddressSpaceActivate` and
`ContextSwitch` double-faulted.

The same physical stack pages are also mapped at the HIGH-VMA alias
via `boot_pml4[511] → boot_pdpt_high[510] → boot_pd`. PML4[511] is
copied verbatim into every per-process AS at create time, so the high
alias is mapped in every AS forever. The fix bumps `rsp` up by
`KERNEL_VIRTUAL_BASE` (`0xFFFFFFFF80000000`) at boot-trampoline time,
swapping the boot stack onto the high alias before any CR3 switch can
ever happen.

## Symptoms

Reproduced under host CPU pressure (`yes >/dev/null` × 8 on a 4-core
host while `tools/ctest-boot-smoke.sh` runs):

```
** CPU EXCEPTION **
=== DUETOS CRASH DUMP BEGIN ===
  message  : #DF Double fault
  vector     : 0x0000000000000008
  rip       : 0xffffffff801c1ce8 [region=k.text]
  rsp        : 0x00000000001097c0 [region=low-id-map]
  rbp        : 0x00000000001097c0 [region=low-id-map]
  cr2       : 0x00000000001097b8 [region=low-id-map]
  cr3       : 0x0000000000f6b000   ← user AS just loaded
  task     : ring3-windowed-hello#34
```

`0xffffffff801c1ce8` disassembles to `pop %rbp` immediately after
`mov %rax, %cr3` inside `duetos::arch::WriteCr3`. Reading the panic
in order:

1. The kernel was running on `prev`'s (boot's) stack at low VA
   `0x1097c0`.
2. `mov %rax, %cr3` activated `next`'s (`ring3-windowed-hello`'s)
   user AS.
3. The next `pop %rbp` tried to read `[rsp]` = `[0x1097c0]`. The
   user AS has PML4[0] = 0 — the low VA is no longer mapped.
4. The CPU tried to deliver `#PF`, but pushing the trap frame onto
   the now-unmapped low-VA stack faulted again → `#DF`.

CI's earlier panic (`mm.kernel_pagefault val=0xffffffff8017a06d`,
`pop %r15` in `isr_common`) was the SAME race manifesting one
instruction later — when the next user→boot transition tried to
read regs from `prev`'s stack with the user AS still active.

## Reproduction

The race is timing-sensitive: the boot task only matters when it
happens to be on-CPU at the moment of an AS switch, and that window
expands under host CPU pressure (TCG slows down, the runqueue piles
up). Local repro:

```bash
# Stress the host while running the smoke
( for i in 1 2 3 4 5 6 7 8; do yes >/dev/null & done; sleep 240; pkill -9 yes ) &
DUETOS_TIMEOUT=45 tools/ctest-boot-smoke.sh build/x86_64-debug
```

Without the fix: 5/5 FLAKY, all hitting `#DF` in `WriteCr3` or `#PF`
in `isr_common`'s `pop %r15`. With the fix: 8/8 PASS under the same
stress.

## Fix

In `kernel/arch/x86_64/boot.S`'s `long_mode_trampoline`, immediately
after the segment reload + paging is up, bias `rsp` to the high-VMA
alias of the same physical stack memory:

```asm
    mov     rsp, offset stack_top
    movabs  rax, 0xFFFFFFFF80000000     ; KERNEL_VIRTUAL_BASE
    add     rsp, rax
```

After this, every kernel access to the boot stack goes through
PML4[511] → boot_pdpt_high[510] → boot_pd, which is mapped in every
per-process AS (the create path copies PML4[256..511] verbatim from
the boot PML4). Boot's stack survives every CR3 switch, regardless of
which AS becomes active.

`stack_top` itself stays linked at low VMA — the 32-bit bootstrap at
`_start` runs before paging is on and must use physical addresses, so
the symbol's LMA cannot move. Only the runtime RSP value changes.

## Why not move `AddressSpaceActivate` to after `ContextSwitch`?

That was the first attempt. It fixed boot→user but broke user→boot:
when `prev` is a user task and `next` is the boot task, the symmetric
problem hits on the OTHER side — `mov rsp, rsi` inside `ContextSwitch`
loads the boot task's low-VA stack while the user CR3 is still active,
and the very next `pop %r15` faults.

The boot-stack-VA fix above is symmetric: every CR3 the kernel ever
loads has PML4[511] populated (boot copies it; per-process ASes copy
it from boot), so the boot task's stack is reachable in both
directions.

## Lifetime

Pre-existing latent bug. The pillar comment above `_start`'s stack
setup was already aware of it ("Later bring-up will move to a per-CPU
stack in kernel memory"); the rewrite of that comment in this slice
is now informed by the actual failure mode rather than a generic
"will revisit later" note.

## Verification

- `cmake --build build/x86_64-debug` clean (`-Werror` honoured)
- `tools/ctest-boot-smoke.sh` 8/8 PASS under heavy host stress
- Same fixture without stress: same 8/8 PASS (regression coverage)
- The headless screenshot helpers still produce the desktop frame
  (PLASMA + FIRE) — boot path through `kernel_main` unaffected
