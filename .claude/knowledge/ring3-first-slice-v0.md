# Ring 3 first slice — v0

_Last updated: 2026-04-20_

_Type: Observation_

## What landed

The smallest runnable transition from ring 0 to ring 3, without
syscalls or per-process address spaces:

- **GDT** grew from 5 to 7 slots. New slots are user code (DPL=3,
  access byte 0xFA) at slot 5 and user data (DPL=3, access byte
  0xF2) at slot 6. Consumer selectors carry RPL=3, so the CPU sees
  `0x2B` and `0x33` — not `0x28` / `0x30`. See
  `kernel/arch/x86_64/gdt.{h,cpp}` (`kUserCodeSelector`,
  `kUserDataSelector`).
- **TSS.RSP0** is now updatable at runtime via `arch::TssSetRsp0(u64)`.
  The CPU reads RSP0 on every user→kernel privilege transition; a
  stale or zero value there turns the next IRQ from ring 3 into a
  double fault.
- **`arch::EnterUserMode(u64 rip, u64 rsp)`** (in
  `kernel/arch/x86_64/usermode.S`) builds an iretq frame
  (SS / RSP / RFLAGS=0x202 / CS / RIP) and jumps. Marked
  `[[noreturn]]` because ring-3 returns to the kernel only via
  traps/IRQs. Loads user DS/ES/FS/GS before iretq — iretq itself
  loads SS/CS from the frame.
- **`customos::core::StartRing3SmokeTask()`** spawns a dedicated
  scheduler thread that maps a user code page + user stack page,
  publishes RSP0, and iretq's into ring 3. The user payload is
  four bytes: `F3 90 EB FC` (`pause; jmp short -4`) — no
  privileged instructions, no memory references, interruptible,
  infinite.

## Chosen VA layout

- `0x40000000` — user code page (U | P, executable, read-only)
- `0x40010000` — user stack page (U | P | W | NX)
- User RSP starts at `0x40011000` (top of stack page)

**Why 1 GiB, not 4 MiB (the traditional ELF low base):** boot.S
paves the first 1 GiB with 2 MiB PS-mapped entries in both the
identity and higher-half halves. The v0 paging API panics on any
4 KiB `MapPage` inside a PS region (it would have to split the
PS entry, which v0 doesn't do). `0x40000000` lives in PDPT[1],
which boot.S left empty, so `WalkToPte` creates fresh PD + PT
tables on first use and we get clean 4 KiB granularity.

## Evidence of ring-3 entry

A ring-3 infinite-loop payload plus a kernel that makes forward
progress together imply ring-3 entry worked. If the iretq had
faulted, the trap dispatcher halts the whole kernel and no further
`[heartbeat]`, `[kbd]`, or `[sched]` lines appear on COM1. The
smoke task prints its chosen addresses before iretq'ing:

```
[ring3] smoke task starting
[ring3] user rip=0x40000000 user rsp=0x40011000 rsp0=<kernel stack top>
[core/ring3] entering user mode at rip = 0x40000000
```

## What's still load-bearing for future slices

- Scheduler survives a task running in ring 3. Context switch out
  of a ring-3 task: timer IRQ → hardware saves iretq frame on
  RSP0 stack → isr_common pushes GPRs → `Schedule()` saves rsp
  at that depth into prev's Task struct. Resume: rsp restored,
  `ContextSwitch` rets through `Schedule` → `TrapDispatch` →
  `isr_common` pops GPRs → iretq back to ring 3 at the
  interrupted RIP. No special ring-3 case in `context_switch.S`.
- `EnterUserMode` is a one-way door. If a second ring-3 task ever
  needs to be created, the RSP0 contract must move into the
  scheduler's switch-in path (update TSS.rsp0 to the new task's
  kernel-stack top on every context switch into a user-mode-
  capable task).

## Deliberately deferred

- SYSCALL / SYSRET: requires STAR / LSTAR / SFMASK MSRs + a
  syscall entry stub. `int 0x80` gate: requires a DPL=3 IDT gate
  and a handler that consumes a trap frame.
- Per-process address space: single global PML4 still. Any user
  task sees the same user code/stack pages. One-and-done is fine
  while we only have one ring-3 task.
- FPU/SSE user state: kernel is built `-mno-sse
  -mgeneral-regs-only`; user code that touches xmm registers
  will take #UD, which is the correct signal that this layer
  doesn't exist yet.

## How to verify locally

```bash
cmake --preset x86_64-debug
cmake --build build/x86_64-debug --parallel $(nproc)
```

ELF builds clean. QEMU boot (once local qemu is installed) should
show the three `[ring3]` / `[core/ring3]` lines interleaved with
ongoing `[heartbeat]` and keyboard-reader output.
