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
- **`duetos::core::StartRing3SmokeTask()`** spawns a dedicated
  scheduler thread that maps a user code page + user stack page,
  publishes RSP0, and iretq's into ring 3. The user payload was
  originally four bytes (`pause; jmp short -4`); it is now 13
  bytes — four `pause` iterations followed by `SYS_EXIT` via
  `int 0x80`. See the syscall-slice follow-up below.

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

## Follow-up slice (2026-04-20, same session) — syscall gate v0

`int 0x80` with a DPL=3 interrupt gate is now online:

- `exceptions.S` got an `ISR_NOERR 128` stub; the usual
  `isr_common` path carries the trap frame to `TrapDispatch`.
- `arch::IdtSetUserGate(vec, handler)` installs a `0xEE`
  (P=1, DPL=3, type=0xE) descriptor. `SyscallInit` uses it to
  wire vector 0x80 → `isr_128`.
- `TrapDispatch` branches on `frame->vector == 0x80` before the
  exception fallback and calls `core::SyscallDispatch(frame)`.
- Calling convention: syscall number in rax, args in rdi/rsi/rdx,
  return value written into `frame->rax` (iretq delivers it).
- v0 catalogue: `SYS_EXIT = 0` → `sched::SchedExit()`. Unknown
  numbers log Warn and return `-1` in rax.

The ring-3 smoke payload now ends with `xor eax,eax; xor edi,edi;
int 0x80`, so the task exits cleanly after a few pauses instead
of looping forever. The reaper KFrees its stack + Task struct.

## Follow-up slices 046..048 — ABI fills in

- **SMEP + SMAP** (entry #046) land in `PagingInit` (CPUID-gated
  CR4 bits) alongside `mm::CopyFromUser` / `mm::CopyToUser`.
  Copy helpers validate the user pointer against the canonical
  low-half boundary (`0x00007FFF_FFFFFFFF`), reject
  overflow/boundary-crossing lengths, and bracket the actual
  byte copy with `stac` / `clac` when SMAP is active. Every
  kernel-side read/write of a user pointer goes through these —
  no other kernel path dereferences a user pointer directly.
- **SYS_GETPID = 1** returns `sched::CurrentTaskId()` — the
  first syscall that exercises the return-value half of the
  ABI. The dispatcher writes `frame->rax`; isr_common's
  pop-all + iretq delivers it to ring 3.
- **SYS_WRITE = 2** (entry #047) takes rdi=fd, rsi=buf, rdx=len.
  fd=1 (stdout) → COM1; anything else → -1. 256-byte
  kernel-stack bounce buffer via `mm::CopyFromUser`; short
  writes are allowed. NUL bytes inside the user buffer are
  forwarded faithfully.
- **Scheduler-owned TSS.RSP0** (entry #048): `Schedule()` now
  publishes the incoming task's kernel-stack top to the BSP's
  TSS on every switch-in, so multi-ring-3-task correctness is
  the scheduler's job instead of each user task's own
  responsibility. Manual `TssSetRsp0` call in
  `Ring3SmokeMain` kept as belt-and-braces.

## Updated ring-3 smoke payload

The payload grew from 13 → 33 bytes:

```
user_entry:                  ; at 0x40000000
    pause                    ; give the timer a tick
    pause
    mov eax, 2               ; SYS_WRITE
    mov edi, 1               ; fd = stdout
    mov esi, 0x40000080      ; msg ptr (fixed offset in page)
    mov edx, <msg_len>
    int 0x80
    xor eax, eax             ; SYS_EXIT
    xor edi, edi             ; rc = 0
    int 0x80
    hlt                      ; unreachable

msg: "Hello from ring 3!\n"  ; at 0x40000080
```

The complete user→kernel round-trip now looks like:

```
[ring3] smoke task starting
[ring3] user rip=0x40000000 user rsp=0x40011000 rsp0=<...>
[core/ring3] entering user mode at rip = 0x40000000
Hello from ring 3!
[sys] exit rc = 0
[sched/reaper] reaped task id = N
```

## Follow-up slices 049..051 — hygiene + one more syscall

- **Walk-first user-pointer check** (entry #049): both copy
  helpers now walk the PT and verify each 4 KiB page has
  `Present | User` before attempting the stac/clac-bracketed
  copy. Unmapped-but-in-range user pointers now return `false`
  instead of halting the kernel on #PF.
- **Per-task user-VM cleanup** (entry #050): Task struct
  gained a fixed 4-slot `user_regions[]` array (vaddr +
  frame). `sched::RegisterUserVmRegion` is called from the
  task's entry fn after each MapPage; the reaper walks the
  array on task death and does `mm::UnmapPage` +
  `mm::FreeFrame`. Ring-3 smoke registers its code + stack.
  No leaks across task lifetimes.
- **SYS_YIELD = 3** (entry #051): cooperative-yield syscall;
  kernel-side handler calls `sched::SchedYield`, returns 0.
  Smoke payload now does SYS_WRITE → SYS_YIELD → SYS_EXIT.

## Updated ring-3 smoke payload (38 bytes)

```
user_entry:                   ; at 0x40000000
    pause                     ; give the timer a tick
    pause
    mov eax, 2                ; SYS_WRITE
    mov edi, 1                ; fd = stdout
    mov esi, 0x40000080       ; msg ptr
    mov edx, <msg_len>
    int 0x80
    mov eax, 3                ; SYS_YIELD
    int 0x80
    xor eax, eax              ; SYS_EXIT
    xor edi, edi              ; rc = 0
    int 0x80
    hlt                       ; unreachable

msg: "Hello from ring 3!\n"   ; at 0x40000080
```

Expected serial log shape:

```
[ring3] smoke task starting
[ring3] user rip=0x40000000 user rsp=0x40011000 rsp0=<...>
[core/ring3] entering user mode at rip = 0x40000000
Hello from ring 3!
[sys] exit rc = 0
[sched/reaper] reaped task id = N
```

## Deliberately deferred (next batch after this)

- SYSCALL / SYSRET (STAR / LSTAR / SFMASK MSR path) — `int 0x80`
  is ~30× slower but correct; migrate once a consumer cares.
- `__copy_user_fault_fixup` — the walk-first check handles
  the "in-range but unmapped" case in pure C++; the fixup
  table becomes necessary the moment demand paging or
  concurrent cross-CPU unmap lands (race: page was mapped
  at walk time, gone by the time the copy reads it).
- Per-process address space: single global PML4 still. Any user
  task sees the same user code/stack pages — so a second
  ring-3 task needs either distinct VAs (simple patch to
  `Ring3SmokeMain`) or per-process CR3 (larger slice).
- Second ring-3 task — now unblocked on the cleanup side
  (regions reaped on exit), but still needs either sequential
  execution with fresh VAs or distinct VA bases for concurrent
  execution. Distinct-VA version is a small follow-up slice
  (patch the `mov esi, imm32` immediate at install time).
- Per-CPU TSS / per-AP RSP0 — the current `arch::TssSetRsp0`
  writes the BSP's TSS only; SMP join will need a per-CPU
  wrapper.
- Writable-bit check in `CopyToUser`'s walk — today the
  walker tests only Present + User, so a CopyToUser into a
  read-only user page panics mid-copy instead of returning
  false up front. No consumer yet; land when the first
  CopyToUser caller arrives.
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
