/*
 * DuetOS userland shell ELF — linker script.
 *
 * Forces a single PT_LOAD at 0x400000 holding code + read-only data.
 * The default lld layout splits into 3 PT_LOADs (PHDR at 0x200000,
 * code at 0x400000, rodata at 0x401XXX); the v0 ELF loader was
 * designed for the previous hand-coded single-segment usershell.elf
 * and double-faults on the multi-segment variant. Collapsing
 * everything into one segment matches the loader's contract.
 *
 * The ENTRY directive matches the -e flag in the build script —
 * `_start` from crt0.S.
 */

ENTRY(_start)

PHDRS
{
    text PT_LOAD FILEHDR PHDRS FLAGS(5);  /* R + X (W^X enforced — no writable user mapping) */
}

SECTIONS
{
    . = 0x400000 + SIZEOF_HEADERS;

    .text : {
        *(.text .text.*)
        *(.rodata .rodata.*)
        *(.data .data.*)
    } :text

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    } :text

    /DISCARD/ : {
        *(.note.*)
        *(.comment)
        *(.eh_frame)
        *(.debug_*)
        *(.gnu.hash)
        *(.dynsym)
        *(.dynstr)
        *(.dynamic)
    }
}
