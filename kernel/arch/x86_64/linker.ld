/*
 * CustomOS x86_64 kernel linker script.
 *
 * The image is loaded by a Multiboot2 loader at physical 1 MiB. Identity-
 * mapped higher-half is NOT set up yet — that's a follow-up commit. For now
 * virtual == physical for everything the kernel touches.
 */

ENTRY(_start)

SECTIONS
{
    . = 1M;
    _kernel_start = .;

    /* Multiboot2 header must appear within the first 32 KiB of the ELF and
     * must be 8-byte aligned. Keeping it first in its own section guarantees
     * both. */
    .multiboot2 : ALIGN(8)
    {
        KEEP(*(.multiboot2))
    }

    .text.boot : ALIGN(4K)
    {
        *(.text.boot)
    }

    .text : ALIGN(4K)
    {
        *(.text .text.*)
    }

    .rodata : ALIGN(4K)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K)
    {
        *(.data .data.*)
    }

    .bss : ALIGN(4K)
    {
        *(COMMON)
        *(.bss .bss.*)
    }

    . = ALIGN(4K);
    _kernel_end = .;

    /DISCARD/ :
    {
        *(.eh_frame)
        *(.comment)
        *(.note.*)
    }
}
