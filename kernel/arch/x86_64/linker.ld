/*
 * DuetOS x86_64 kernel linker script.
 *
 * Layout:
 *   - Multiboot2 header and the 32-bit/64-bit boot trampoline (.text.boot,
 *     .rodata.boot, .bss.boot) live at LOW VMA = LOW LMA. That code runs
 *     before paging is enabled, and its boot-local data (page tables, boot
 *     stack, bootstrap GDT) has to be reachable by physical address.
 *
 *   - The rest of the kernel (.text, .rodata, .data, .bss) is linked at
 *     HIGH VMA (KERNEL_VIRTUAL_BASE + offset) with AT() directives that
 *     keep LMA contiguous with the low boot sections. boot.S installs a
 *     second mapping from 0xFFFFFFFF80000000 → phys 0 for the first 1 GiB,
 *     which is how execution jumps into the higher half.
 *
 * Physical layout (load addresses):
 *   0x00100000                        — image base
 *     .multiboot2
 *     .text.boot                      — 32-bit entry + 64-bit low trampoline
 *     .rodata.boot                    — bootstrap GDT
 *     .bss.boot                       — boot page tables + boot stack
 *   [aligned]                         — rest of the kernel
 *     .text, .rodata, .data, .bss     — high-VMA sections (LMA stays low)
 *
 * Virtual layout (runtime addresses):
 *   0x00100000                        — boot sections (identity-mapped)
 *   0xFFFFFFFF80000000 + off          — high-half kernel (same physical pages)
 */

KERNEL_VIRTUAL_BASE = 0xFFFFFFFF80000000;

ENTRY(_start)

SECTIONS
{
    . = 1M;
    _kernel_start_phys = .;

    /* Multiboot2 header must appear within the first 32 KiB of the ELF and
     * must be 8-byte aligned. Keeping it first in its own section guarantees
     * both. */
    .multiboot2 : ALIGN(8)
    {
        KEEP(*(.multiboot2))
    }

    /* Low-half boot code: 32-bit entry and the 64-bit trampoline that
     * far-jumps into the high half. Must stay identity-mapped so it's
     * reachable before the higher-half PML4 entry exists. */
    .text.boot : ALIGN(4K)
    {
        *(.text.boot)
    }

    /* Bootstrap read-only data (temporary GDT and its pointer). Accessed
     * in 32-bit mode where paging is off, so the address in the instruction
     * encoding must match the physical load address. */
    .rodata.boot : ALIGN(16)
    {
        *(.rodata.boot)
    }

    /* Boot page tables and boot stack. Zero-initialised. Keeping this at
     * low VMA means the 32-bit setup code can use direct `offset` addresses
     * to populate page-table entries without any paging magic. */
    .bss.boot : ALIGN(4K)
    {
        *(.bss.boot)
    }

    /* Move the location counter into the higher half. Everything below this
     * point is linked at KERNEL_VIRTUAL_BASE + (physical offset), while the
     * AT() directives below pin the LMA to the contiguous low physical. */
    . = ALIGN(4K);
    . += KERNEL_VIRTUAL_BASE;

    _text_start = .;
    .text : AT(ADDR(.text) - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        *(.text .text.*)
    }
    . = ALIGN(4K);
    _text_end = .;

    _rodata_start = .;
    .rodata : AT(ADDR(.rodata) - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        *(.rodata .rodata.*)
    }

    /* C++ static-constructor table. Modern toolchains emit one
     * pointer per `__attribute__((constructor))` / non-constinit
     * global into `.init_array`; the kernel runtime walks
     * [__init_array_start, __init_array_end) and invokes each
     * pointer once at boot (`core::RunInitArray`). KEEP() so the
     * symbols survive `--gc-sections`. (A1-followup, 2026-04-28.)
     */
    .init_array : AT(ADDR(.init_array) - KERNEL_VIRTUAL_BASE) ALIGN(8)
    {
        __init_array_start = .;
        KEEP(*(.init_array .init_array.*))
        __init_array_end = .;
    }

    /* Hot-patch pair registry. Each KHOTPATCH_REGISTER_PAIR
     * macro emits one HotPatchPair struct into this section.
     * `live-update kernel-auto-patch` walks
     * [__duetos_hotpatch_pairs_start, __duetos_hotpatch_pairs_end)
     * and installs every entry that isn't already live. See
     * kernel/debug/hot_patch.h for the macro + record layout.
     * KEEP() so the entries survive `--gc-sections`.
     */
    .duetos_hotpatch_pairs : AT(ADDR(.duetos_hotpatch_pairs) - KERNEL_VIRTUAL_BASE) ALIGN(8)
    {
        __duetos_hotpatch_pairs_start = .;
        KEEP(*(.duetos_hotpatch_pairs .duetos_hotpatch_pairs.*))
        __duetos_hotpatch_pairs_end = .;
    }

    /* KPath site registry. Each `KPATH(...)` macro emits one
     * `KPathSite` record into this section. The unified iterator
     * in `kernel/diag/kpath.cpp` walks
     * [__kpath_sites_start, __kpath_sites_end) to enumerate every
     * static call site marked at compile time. KEEP() so entries
     * survive `--gc-sections`. See kernel/diag/kpath.h for the
     * record layout.
     */
    .kpath_sites : AT(ADDR(.kpath_sites) - KERNEL_VIRTUAL_BASE) ALIGN(8)
    {
        __kpath_sites_start = .;
        KEEP(*(.kpath_sites .kpath_sites.*))
        __kpath_sites_end = .;
    }

    . = ALIGN(4K);
    _rodata_end = .;

    _data_start = .;
    .data : AT(ADDR(.data) - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        *(.data .data.*)
    }

    /* KPath mutable hit counters. Parallel-indexed to .kpath_sites;
     * each `KPATH(...)` macro stamps one u64 into this section from
     * the same TU as its corresponding site record. The KPathSite
     * struct carries an explicit `hits_ptr` so we never rely on the
     * link order matching across sections. */
    .kpath_hits : AT(ADDR(.kpath_hits) - KERNEL_VIRTUAL_BASE) ALIGN(8)
    {
        __kpath_hits_start = .;
        KEEP(*(.kpath_hits .kpath_hits.*))
        __kpath_hits_end = .;
    }
    . = ALIGN(4K);
    _data_end = .;

    _bss_start = .;
    .bss : AT(ADDR(.bss) - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        *(COMMON)
        *(.bss .bss.*)
    }
    . = ALIGN(4K);
    _bss_end = .;

    . = ALIGN(4K);
    _kernel_end_virt  = .;
    _kernel_end_phys  = . - KERNEL_VIRTUAL_BASE;

    /* Installer kernel-ELF embed blob (DUETOS_INSTALLER_KERNEL_EMBED).
     *
     * gen-kernel-blob.sh emits the embedded stage-1 ELF into the
     * .kernel_elf_blob input section. Pin it at physical 32 MiB —
     * well clear of the 0..16 MiB legacy-ISA DMA zone — so the
     * ~10 MiB blob does NOT push _kernel_end_phys past 16 MiB and
     * starve `mm/zone`'s Dma allocator. The real kernel image
     * (_kernel_start_phys.._kernel_end_phys) stays low and small;
     * frame_allocator.cpp reserves [_kernel_blob_start_phys,
     * _kernel_blob_end_phys) separately.
     *
     * The VMA floors at KERNEL_VIRTUAL_BASE + 32 MiB so the runtime
     * pointer (kBinKernelElfBytes) resolves through boot.S's
     * higher-half 1 GiB map (VMA = KVB + phys for the first 1 GiB).
     * It is a FLOOR, not a hard pin: instrumented builds (KASAN
     * shadow + UBSAN tables) inflate .bss past 32 MiB, so a hard
     * `AT(32M)` would overlap the tail of .bss and ld aborts with
     * "section .bss load address range overlaps". Take the max of
     * 32 MiB and the current (post-.bss) location instead — the
     * non-instrumented kernel still lands the blob at exactly
     * 32 MiB (.bss ends well below it), and instrumented kernels
     * float it just above .bss. Either way LMA == VMA - KVB stays
     * well inside the first 1 GiB higher-half map, and
     * _kernel_end_phys (computed above, before this section) is
     * unaffected so the DMA-zone reservation logic is unchanged.
     * When the embed is OFF the input is zero bytes: ld drops the
     * empty output section, emits no extra PT_LOAD, and
     * _kernel_blob_start_phys == _kernel_blob_end_phys so the
     * reservation is a no-op. */
    . = ALIGN(4K);
    . = (. < KERNEL_VIRTUAL_BASE + 32M) ? (KERNEL_VIRTUAL_BASE + 32M) : .;
    .kernel_elf_blob . : AT(. - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        _kernel_blob_start_phys = . - KERNEL_VIRTUAL_BASE;
        KEEP(*(.kernel_elf_blob .kernel_elf_blob.*))
        . = ALIGN(4K);
        _kernel_blob_end_phys = . - KERNEL_VIRTUAL_BASE;
    }

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.comment)
        *(.note.*)
    }
}
