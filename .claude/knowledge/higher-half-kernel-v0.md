# Higher-Half Kernel Move v0 — 0xFFFFFFFF80000000

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The kernel now runs at `0xFFFFFFFF80000000 + offset` instead of `1 MiB`. The low half of the virtual address space is free for userland mappings without disturbing kernel code; every future process will share the same higher-half kernel view. Boot time is unchanged; QEMU output is identical modulo the frame addresses shifting by one line (see below).

## Context

Applies to `kernel/arch/x86_64/{boot.S,linker.ld}` and `kernel/mm/frame_allocator.cpp`. This is a prerequisite for anything that involves per-process address spaces — user-mode code, the PE loader, kernel threads with separate stacks all assume the kernel is pinned in a fixed region that survives CR3 swaps.

## Details

### Virtual-memory layout

```
0x0000000000100000  ──┐ (identity, set up during boot and kept alive)
  ... first 1 GiB     │
0x0000000040000000  ──┘

0xFFFFFFFF80000000  ──┐ (higher-half kernel)
  ... first 1 GiB     │
0xFFFFFFFFC0000000  ──┘
```

Same 1 GiB of physical memory, aliased twice. The identity map is what lets:

- the boot trampoline run before the higher-half PML4 entry exists;
- the frame allocator read the Multiboot2 info struct, which GRUB parks at a low physical address;
- the allocator write the bitmap, which is placed in low RAM via `FindBitmapHome`.

The identity map is kept for now. A future commit will tear it down once there's a managed `phys_to_virt()` helper and the kernel no longer dereferences bare physical addresses.

### Page-table shape

Three tables in `.bss.boot`, all zero-initialised at load, then filled in from `_start` (32-bit):

```
PML4[0]             → boot_pdpt        (identity-half PDPT)
PML4[511]           → boot_pdpt_high   (higher-half PDPT)
boot_pdpt[0]        → boot_pd          (maps phys 0..1 GiB)
boot_pdpt_high[510] → boot_pd          (also maps phys 0..1 GiB)
boot_pd[0..511]     → 2 MiB PS pages covering phys 0..1 GiB
```

PML4 slot 511 covers virtual `[0xFFFF800000000000 .. top]`. Inside that, PDPT slot 510 covers `[0xFFFFFFFF80000000 .. +1 GiB]`. Slot 511 would cover `[0xFFFFFFFFC0000000 .. +1 GiB]` — not used yet.

The same `boot_pd` is referenced from both PDPTs, so the low and high PML4 paths converge on the same PDEs. Saves a 4 KiB page and keeps the two views trivially coherent.

### Why we need a 64-bit trampoline

The 32-bit `ljmp 0x08, offset X` only encodes a 32-bit offset. Our high-half kernel entry lives at something like `0xFFFFFFFF8010A100` — representable only as a 64-bit immediate. So:

1. 32-bit code enables paging and `ljmp`s to `long_mode_trampoline`, which lives at **low VMA** in `.text.boot`. The offset here is small (e.g. `0x101092`) and fits.
2. In the trampoline, already in long mode, we load the high-half target as a 64-bit immediate and do an indirect `jmp rax`.

```asm
mov     rax, offset long_mode_entry   ; emits REX.W + B8 + imm64
jmp     rax
```

The higher-half PML4 entry was installed back in the 32-bit setup, so the instruction fetch at the new RIP walks `PML4[511] → PDPT[510] → PD → phys 0..1 GiB` and resolves to the same physical pages as the identity map.

### Linker-script layout

```ld
KERNEL_VIRTUAL_BASE = 0xFFFFFFFF80000000;

. = 1M;
_kernel_start_phys = .;

.multiboot2    : ALIGN(8)    { KEEP(*(.multiboot2)) }
.text.boot     : ALIGN(4K)   { *(.text.boot) }
.rodata.boot   : ALIGN(16)   { *(.rodata.boot) }    ; bootstrap GDT
.bss.boot      : ALIGN(4K)   { *(.bss.boot) }       ; page tables + boot stack

. = ALIGN(4K);
. += KERNEL_VIRTUAL_BASE;

.text   : AT(ADDR(.text)   - KERNEL_VIRTUAL_BASE) ALIGN(4K) { *(.text .text.*) }
.rodata : AT(ADDR(.rodata) - KERNEL_VIRTUAL_BASE) ALIGN(4K) { *(.rodata .rodata.*) }
.data   : AT(ADDR(.data)   - KERNEL_VIRTUAL_BASE) ALIGN(4K) { *(.data .data.*) }
.bss    : AT(ADDR(.bss)    - KERNEL_VIRTUAL_BASE) ALIGN(4K) { *(COMMON) *(.bss .bss.*) }

. = ALIGN(4K);
_kernel_end_virt  = .;
_kernel_end_phys  = . - KERNEL_VIRTUAL_BASE;
```

The `AT(VMA - KERNEL_VIRTUAL_BASE)` directive pins each high-VMA section's **load** address to its contiguous low physical slot. `objdump -h` / `readelf -lW` confirms VirtAddr and PhysAddr are correct (one goes high, the other stays low).

### Sections that had to stay low-VMA

Anything the 32-bit (paging-off) or 64-bit (paging-on, not yet jumped to high half) code touches by address:

- `.text.boot` — the `_start` routine and the low-VMA trampoline.
- `.rodata.boot` — the bootstrap GDT and its pointer. `lgdt [gdt64_descriptor]` runs in 32-bit mode; the operand resolves to an instruction-encoded address, and paging is off, so that address must be the physical load address.
- `.bss.boot` — `boot_pml4`, `boot_pdpt`, `boot_pdpt_high`, `boot_pd`, and the boot stack. The 32-bit setup writes PTEs by `offset <label>`, and `mov esp, offset stack_top` likewise uses the low physical.

### Kernel-image physical symbols

`_kernel_start_phys` and `_kernel_end_phys` replace the old `_kernel_start` / `_kernel_end` symbols. They're declared in the linker script to hold **physical** addresses: the frame allocator uses them to mark kernel-image frames as reserved, which is a physical-frame operation, not a virtual one. Using the high-VMA addresses would silently fail (the frame indices fall past `g_bitmap_frames` and `BitmapMarkUsed` no-ops out-of-range frames). The C++ side picks them up as:

```cpp
extern "C" char _kernel_start_phys[];
extern "C" char _kernel_end_phys[];
```

### Bug caught by this commit — FindBitmapHome vs. Multiboot2 info struct

Landing the higher-half move shrunk the kernel's physical footprint slightly (the `.bss.boot` layout packs page tables tighter than the previous single `.bss`). On this QEMU/GRUB config, `_kernel_end_phys` = `0x110000` and GRUB parked the Multiboot2 info struct at `0x113a80` — inside the first "available" region and above the kernel end.

`FindBitmapHome` only skipped past the kernel image. The bitmap landed at `0x110000`, `16 KiB` long, which overwrote the info struct at `0x113a80`. The first mmap pass (for printing) had already run, so the memory map dumped correctly — but the second mmap pass (to mark available frames free) then walked a struct whose `total_size` had been scribbled with `0xFF`s, producing an effectively infinite iteration bound and silent hang.

Fix: `FindBitmapHome` now takes `info_size` and places the bitmap above `max(kernel_end_phys, info_phys + info_size)`. Diagnostic signature for the regression, if it returns: silent hang after `[mm] Multiboot2 memory map:` with a full map printed and no exception trace. The info struct's `total_size` field reading `0xFFFFFFFF` is the smoking gun.

### Verified boot output

```
[boot] DuetOS kernel reached long mode.
[boot] Multiboot2 handoff verified.
[boot] Installing kernel GDT.
[boot] Installing IDT (vectors 0..31).
[boot] Parsing Multiboot2 memory map.
[mm] Multiboot2 memory map:
  base=0x0000000000000000 len=0x000000000009fc00 type=available
  ...
  total frames : 0x000000000001ffdf
  free frames  : 0x000000000001fec9
[mm] frame allocator self-test
  alloc A    : 0x0000000000110000
  alloc B    : 0x0000000000111000
  alloc C    : 0x0000000000112000
  realloc    : 0x0000000000110000 (reused A/B/C)
[mm] frame allocator self-test OK
[boot] All subsystems online. Halting CPU.
```

The free-frame count is slightly lower than the pre-move baseline (`0x1FEC9` vs `0x1FECB`) because `FindBitmapHome` now places the bitmap past the info struct's page, and ReserveRange pins the info struct's page too.

### How to verify after edits

```bash
cmake --build build/x86_64-debug
DUETOS_TIMEOUT=10 tools/qemu/run.sh
```

Smoke tests:
- `[mm] frame allocator self-test OK` still prints end-to-end.
- `readelf -SW build/x86_64-debug/kernel/duetos-kernel.elf` shows `.text`, `.rodata`, `.data`, `.bss` with VirtAddr in the `0xffffffff80...` range and Off/size matching a low-LMA load.
- `llvm-nm` shows `long_mode_entry` at `0xffffffff801xxxxx` and `long_mode_trampoline` at a low physical address (e.g. `0x101xxx`).

Canaries for "the move regressed":
- Triple-fault right after `ljmp 0x08` → the trampoline isn't at a low VMA, or PML4[0] isn't pointing at `boot_pdpt`.
- Hang after `[mm] Multiboot2 memory map:` with no trap → bitmap placement collided with something (info struct, kernel image, the bitmap itself). Check `FindBitmapHome`.
- `[boot] WARNING: unexpected boot magic.` → the 32-bit PD-fill loop touched `edi` or `esi` again. Use `ebx`/`ebp`/`edx` for scratch in `.code32` paths.

## Notes

- The boot stack is still 16 KiB in `.bss.boot` at low VMA. Per-CPU kernel stacks will come with SMP bring-up and will live in proper kernel memory (high VMA). Switching off the boot stack is a one-liner (`mov rsp, <high_stack_top>`) once we have one.
- The identity map is convenient but leaks the kernel's layout into the lower half. Once there's a managed `phys_to_virt()` the identity map can be torn down and every subsystem that currently dereferences low physical addresses should move to it.
- `.rodata.boot` currently only holds the bootstrap GDT. If we add anything else that must be accessible before paging (or before the high-half jump), it belongs there too — not in `.rodata`.
- **See also:**
  - [kernel-bringup-v0.md](kernel-bringup-v0.md) — the original low-VMA boot path this commit replaces.
  - [gdt-idt-v0.md](gdt-idt-v0.md) — the kernel's own GDT/IDT, now installed from high-VMA code.
  - [frame-allocator-v0.md](frame-allocator-v0.md) — references `_kernel_start`/`_kernel_end`; those symbols were renamed to `_kernel_start_phys`/`_kernel_end_phys` here.
