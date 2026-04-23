# Kernel-stack guard pages — v0

**Last updated:** 2026-04-23
**Type:** Observation + Decision
**Status:** Active — arena online, sched + reaper switched, self-test passes, clean boot.

## What

`kernel/mm/kstack.{h,cpp}` — a dedicated virtual-address arena for
kernel task stacks with a **deliberately-unmapped 4 KiB guard page
at the low edge of every slot**. Overflow now takes an immediate
kernel-mode `#PF` instead of silently scribbling the next heap
chunk and waiting for the runtime invariant checker's 5 s sentinel
scan (or the reaper on task exit) to notice.

Before: `SchedCreate` at `sched/sched.cpp:450` called
`mm::KMalloc(16 KiB)`. Overflow corrupted neighbouring heap
allocations — usually another task's stack — for up to 5 s before
the heartbeat noticed.

After: `SchedCreate` calls `mm::AllocateKernelStack(16 KiB)`. The
returned pointer is `slot_base + 4 KiB` (lowest usable byte). Below
it sits the guard page, PTE absent; any push past the bottom `#PF`s
at the first byte and the trap dispatcher emits a named panic
`sched/kstack: guard-page hit — kernel stack overflow` with the
offending task id, CR2 and RIP.

## Arena layout

```
0xFFFFFFFFE0000000 ─┐  arena base (inside paging.h's "reserved" range)
                    │  slot 0  guard page (unmapped)
+0x1000  ←──────────┘──── AllocateKernelStack returns this
                       slot 0  stack pages × 4 (RW | NX)
+0x5000                slot 1 guard page
...
stride = kKernelStackSlotBytes = 20 KiB
max slots = kKernelStackMaxSlots = 512 → 10 MiB of kernel VA
```

Each slot: `kKernelStackGuardPages = 1` + `kKernelStackPages = 4` =
20 KiB. Usable bytes per stack (`kKernelStackUsableBytes`) = 16 KiB,
unchanged from the prior heap-backed size.

## Allocator policy

- **O(1) bump + LIFO freelist.** Never-used slots come from a bump
  cursor; freed slots go onto a `u32` stack guarded by
  `sync::SpinLock g_kstack_lock`.
- **Per-slot frame shadow** (`g_slot_frames[slot][page]`,
  16 KiB of .bss). Lets `FreeKernelStack` recover the backing
  frame for each page without a new PTE-walker primitive —
  `mm::VirtToPhys` only works on direct-map VAs, and the arena sits
  outside it.
- **MapPage / UnmapPage / AllocateFrame / FreeFrame** are the only
  primitives used. No second PTE walker.
- **Stats**: `slots_in_use`, `slots_ever_allocated`, `slots_freed`,
  `high_water_slots`, `next_unseen_slot`, `freelist_depth`.

## Trap-dispatcher integration

`kernel/arch/x86_64/traps.cpp` — new branch inserted between the
NMI early-halt and the extable lookup. Must run **before** the
extable lookup so no stray fixup row can shadow a real overflow:

```cpp
if (frame->vector == 14 && (frame->cs & 3) == 0) {
    const u64 cr2 = ReadCr2();
    if (mm::IsKernelStackGuardFault(cr2)) {
        // emit identity + panic
    }
}
```

`IsKernelStackGuardFault` is an inline constexpr range check in
`kstack.h` — no link-time dependency from traps.cpp on kstack.cpp.

## Canary — retained

The 8-byte stack-bottom canary at `sched.cpp:460` (`kStackCanary =
0xC0DEB0B0CAFED00D`) stays. The guard page catches overflow at the
first byte of a push; the canary covers the narrow case of a
variable-length `alloca` that skips the canary word but falls into
the guard. Cost is one store per task create + one compare in the
reaper — free. Runtime invariant checker's walker at
`sched.cpp:1276` is unchanged.

## Self-test

`mm::KernelStackSelfTest()` runs from `kernel_main` right after
`PagingSelfTest()`:

1. Allocate a slot; touch base[0] and base[size-1].
2. Free; re-allocate; assert same VA returned (freelist LIFO).
3. Touch the recycled slot.
4. Free; assert stats land at baseline.

Does NOT verify guard-page absence via PTE walk — adding a public
walker for a single caller was rejected. The trap-dispatcher branch
is the live verifier.

## Scope cuts (explicitly deferred)

- **Boot task / task 0** still uses the `boot.S` stack
  (`sched.cpp:412`, `stack_base == nullptr`). Relocating it onto a
  guarded slot is a separate slice.
- **SMP AP bootstrap stacks** at `arch/x86_64/smp.cpp:286` remain
  `mm::KMalloc(16 KiB)`. APs today only run `cli; hlt` so overflow
  is impossible; swap when APs join the scheduler.
- **TLB shootdown on SMP** — `UnmapPage` issues a local `invlpg`
  only. Same gap as the MMIO arena, not introduced here.
- **Graceful OOM path** — `AllocateKernelStack` returns nullptr on
  arena exhaustion and `SchedCreate` panics (previous contract).
  A `Result<>`-shaped sibling arrives when a caller wants recovery.

## Files

- `kernel/mm/kstack.h` (new, ~180 lines)
- `kernel/mm/kstack.cpp` (new, ~260 lines)
- `kernel/CMakeLists.txt` (+1 line, `mm/kstack.cpp` in the shared list)
- `kernel/sched/sched.cpp` (~6 lines changed at `:451-461` and `:1462`)
- `kernel/arch/x86_64/traps.cpp` (+22 lines guard-page branch,
  +1 include line)
- `kernel/core/main.cpp` (+1 include, +4 lines self-test call)

## Verification (2026-04-23)

- `cmake --build build/x86_64-debug` — 226/226 targets, zero
  warnings from the new code.
- `clang-format --dry-run --Werror` clean on all edited files.
- Live QEMU boot + stack overflow test gated on runtime tooling
  install (`qemu-system-x86 ovmf grub-mkrescue xorriso mtools`);
  see `CLAUDE.md` "Live-test runtime tooling" for the install
  line. Self-test at boot exercises allocate/write/free/recycle.

## Revisit when

- APs join the scheduler → swap `arch/x86_64/smp.cpp` AP stacks
  onto the arena.
- SMP page-table API lands → wire TLB shootdown into `UnmapPage`;
  no per-arena code needed.
- A second stack size class is justified (e.g. tasks handling
  deep recursion) → promote `stack_bytes` from assertion to real
  parameter with a per-class sub-arena.
