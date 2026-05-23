/*
 * kernel/subsystems/linux/vdso/vdso.lds
 *
 * Linker script for the v0 Linux vDSO blob. The output is later
 * objcopy'd to raw binary (--only-section=.vdso.text), so all
 * we need from the linker is: put .vdso.text at file offset 0
 * with __kernel_rt_sigreturn at byte 0, drop the noise sections.
 *
 * No PT_LOAD / PT_DYNAMIC yet — that arrives with the ELF-shaped
 * vDSO follow-up. Keep this minimal so it doesn't accumulate
 * cruft that has to be ripped back out.
 */

SECTIONS
{
    . = 0;
    .vdso.text : ALIGN(16) {
        *(.vdso.text)
    }
    /DISCARD/ : {
        *(.note.*)
        *(.comment)
        *(.eh_frame*)
        *(.gnu.linkonce.*)
    }
}
