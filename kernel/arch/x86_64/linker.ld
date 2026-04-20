/*
 * CustomOS x86_64 kernel linker script.
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

    .text : AT(ADDR(.text) - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        *(.text .text.*)
    }

    .rodata : AT(ADDR(.rodata) - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        *(.rodata .rodata.*)
    }

    .data : AT(ADDR(.data) - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        *(.data .data.*)
    }

    .bss : AT(ADDR(.bss) - KERNEL_VIRTUAL_BASE) ALIGN(4K)
    {
        *(COMMON)
        *(.bss .bss.*)
    }

    . = ALIGN(4K);
    _kernel_end_virt  = .;
    _kernel_end_phys  = . - KERNEL_VIRTUAL_BASE;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.comment)
        *(.note.*)
    }
}
