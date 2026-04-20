# Physical Frame Allocator v0 — Bitmap over Multiboot2 Memory Map

**Last updated:** 2026-04-20
**Type:** Observation
**Status:** Active

## Description

The kernel is now memory-aware. A bitmap-backed physical frame allocator reads the Multiboot2 memory map at boot and hands out 4 KiB frames. End-to-end verified in QEMU: allocate three distinct frames, free them, re-allocate, confirm the lowest freed frame is reused.

## Context

Applies to `kernel/mm/{frame_allocator,multiboot2}.*`, `kernel/arch/x86_64/boot.S` (1 GiB identity map), and `kernel/arch/x86_64/linker.ld` (`_kernel_start`/`_kernel_end` symbols). This is the foundation every other MM subsystem will sit on — page table construction, heap, userland mapping all allocate frames through this interface.

## Details

### Identity-map extension (2 MiB → 1 GiB)

The previous boot.S mapped exactly one 2 MiB PDE. The allocator bitmap needs to live somewhere identity-mapped in normal RAM, and on a 512 MiB QEMU instance the first suitable spot above the kernel image falls past 2 MiB — so boot.S now fills all 512 PDEs of the single PD (= 1 GiB total).

```asm
mov     ecx, 512
mov     ebx, offset boot_pd         ; ebx, NOT edi (holds Multiboot2 magic)
mov     eax, 0x00000083             ; phys=0, P|RW|PS
fill_pd_loop:
    mov     [ebx], eax
    add     ebx, 8
    add     eax, 0x00200000         ; +2 MiB
    loop    fill_pd_loop
```

### Bug landed in this commit — don't touch edi/esi in boot.S

`edi` holds the Multiboot2 boot magic, `esi` holds the info-struct pointer. Both are preserved from 32-bit entry all the way to the `kernel_main` call. The first iteration of the 1 GiB map code wrote `mov edi, offset boot_pd` as the PD cursor and silently clobbered the magic. Symptom: `[boot] WARNING: unexpected boot magic.` on every boot. The fix is literally one register letter (`ebx`), but the lesson is worth recording: **any new code in 32-bit boot.S must not write edi or esi**. If future bring-up needs more scratch registers, use `ebx`/`ebp`/`edx` first.

### Linker-script symbols

```ld
_kernel_start = .;   // immediately before .multiboot2
...
. = ALIGN(4K);
_kernel_end = .;     // immediately after .bss, page-aligned
```

The allocator consumes these as `extern "C" char _kernel_start[]` / `_kernel_end[]` and reserves the covered frame range. Don't remove them — anything that reasons about "where is the kernel in physical memory" needs them.

### Bitmap layout

- Bit `N` == 1 → frame `N` (physical address `N << 12`) is in use.
- Default-initialised to all 1s, so any frame the bootloader doesn't explicitly describe as "available" stays reserved.
- Size = `ceil(highest_usable_addr / 4096 / 8)` bytes. For 512 MiB of RAM that's ~16 KiB, 4 pages.

### "Highest usable address" excludes reserved MMIO

Naïvely sizing the bitmap to "highest address anywhere in the map" falls over hard on QEMU q35: it reports a reserved region from `0xFD00000000` to `0x10000000000` (1 TiB range for pflash / hypervisor MMIO). Sizing a bitmap for 1 TiB of frames produces a 32 MiB bitmap, larger than our identity map will hold.

`ComputeHighestUsableAddr` only considers `Available` and `AcpiReclaimable` entries. MMIO regions that live past real RAM are the problem of whatever driver maps them explicitly — not the frame pool.

### Bitmap placement

Linear scan of the memory map, first "available" region above `_kernel_end` that is both ≥ bitmap size AND within the 1 GiB identity map. On a typical 512 MiB QEMU run the bitmap lands at `_kernel_end` rounded up to the next page (~`0x110000`), and the first allocatable frame is `0x114000`.

### What gets reserved

At `FrameAllocatorInit()`:

1. **Everything** — default-initialised to "used".
2. `Available` regions (per map) → flipped to "free".
3. **Low 1 MiB** — re-marked used. Even if the firmware claims segments of it are "available", real-mode IVT, BDA, EBDA, legacy video, and SMI handlers all live down here. The cost of giving up 256 frames is well under the cost of explaining a mysterious BIOS-interaction crash.
4. **Kernel image** (`_kernel_start` ... `_kernel_end`).
5. **The bitmap itself**.
6. **Multiboot2 info struct**'s page range — we still read tags after Init returns (future commits will want module lists, ACPI RSDP, framebuffer descriptor, etc.).
7. **Frame 0 explicitly**, aliasing `kNullFrame` used as the "no memory" sentinel.

### Allocation algorithm

Linear scan from a hint (`g_next_hint`, rewound to the lowest freed frame on `FreeFrame`). O(n) worst case but with `n ≈ 128k` on a 512 MiB machine that's still microseconds on a modern CPU.

Explicit scope-limiting decisions for v0:
- Not thread-safe. No lock. Boot is single-CPU until SMP lands, at which point a spinlock goes in.
- No NUMA zones. No DMA-capability split. No memory compaction.
- No reclaim. `FreeFrame` is the only path frames re-enter the pool.

### Verified boot output (QEMU q35, 512 MiB)

```
[boot] Parsing Multiboot2 memory map.
[mm] Multiboot2 memory map:
  base=0x0000000000000000 len=0x000000000009fc00 type=available
  base=0x000000000009fc00 len=0x0000000000000400 type=reserved
  base=0x00000000000f0000 len=0x0000000000010000 type=reserved
  base=0x0000000000100000 len=0x000000001fedf000 type=available
  base=0x000000001ffdf000 len=0x0000000000021000 type=reserved
  base=0x00000000b0000000 len=0x0000000010000000 type=reserved
  base=0x00000000fed1c000 len=0x0000000000004000 type=reserved
  base=0x00000000fffc0000 len=0x0000000000040000 type=reserved
  base=0x000000fd00000000 len=0x0000000300000000 type=reserved
  total frames : 0x000000000001ffdf           (131039 × 4 KiB ≈ 512 MiB)
  free frames  : 0x000000000001fecb           (130763 free after reservations)
[mm] frame allocator self-test
  alloc A    : 0x0000000000114000
  alloc B    : 0x0000000000115000
  alloc C    : 0x0000000000116000
  realloc    : 0x0000000000114000 (reused A/B/C)
[mm] frame allocator self-test OK
```

The 276-frame gap between total and free splits as: low 1 MiB (256) + kernel image + bitmap + info struct (~20).

### How to verify after edits

```bash
cmake --build build/x86_64-debug
CUSTOMOS_TIMEOUT=10 tools/qemu/run.sh
```

Canary for "the thing is broken":
- `[mm] frame allocator self-test OK` missing → something in Init or the bitmap panicked, read the `[panic]` line above.
- Duplicate alloc addresses → bit math regression in `BitmapMarkUsed`/`BitmapMarkFree`.
- `unexpected boot magic` → boot.S regression; check which registers your new code writes (see bug note above).
- `realloc` address not matching any of A/B/C → hint-rewind broken in `FreeFrame`.

## Notes

- `constinit` works for the bitmap state (all plain u64/u8\* initialised to 0/nullptr) but NOT for the descriptor-pointer structs — addresses-as-constants aren't allowed. Same rationale as [gdt-idt-v0.md](gdt-idt-v0.md): runtime assignment inside Init is the portable path.
- The memory-map dump at boot is ~150 bytes of output and trivial CPU cost. Keep it — misparses here produce bizarre downstream failures and the dump is the single fastest way to see "the firmware told us something unusual."
- When the heap lands, it will likely want an "allocate N contiguous frames" helper on top of this. Don't add it speculatively — add it when the heap needs it, and add it with a test that shows N-page allocations actually land contiguously.
- **See also:** [kernel-bringup-v0.md](kernel-bringup-v0.md) for the boot.S context these changes extend; [gdt-idt-v0.md](gdt-idt-v0.md) for the trap path that would catch out-of-bounds bitmap writes as #PF.
