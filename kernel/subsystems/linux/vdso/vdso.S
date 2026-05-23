/*
 * kernel/subsystems/linux/vdso/vdso.S
 *
 * DuetOS Linux-ABI vDSO blob — v0.
 *
 * A single page of executable code mapped into every Linux ELF
 * process at a kernel-chosen VA. The kernel records the entry-
 * point offsets in linux_vdso.h (mirrored to vdso_offsets.h via
 * the build script) and Process::vdso_*_va after the mapping
 * lands, so the signal-delivery path can route handler returns
 * through __kernel_rt_sigreturn without dropping the signal.
 *
 * Current exports (offset 0 first; reserved 0x40-aligned slots
 * for future entries):
 *
 *   0x00 — __kernel_rt_sigreturn
 *          Issues Linux SYS_rt_sigreturn (nr 15). The kernel
 *          pops the on-stack LinuxSignalFrame and resumes the
 *          interrupted RIP. If the syscall somehow returns,
 *          ud2 makes the misbehaviour loud rather than silent.
 *
 * Calling convention for __kernel_rt_sigreturn: nothing — RSP
 * already points at the LinuxSignalFrame and the kernel
 * recognises the frame by its magic word. The trampoline never
 * returns to its caller (the caller is the dispatched signal
 * handler, which expects its own `ret` to drop into the
 * restorer).
 *
 * GAP: this is not yet a real ELF shared object. There is no
 * ELF header on the blob, no dynamic symbol table, no
 * AT_SYSINFO_EHDR hookup. Static-linked ELFs that only need a
 * sa_restorer-style trampoline (everything currently exercised
 * in the Linux subsystem) work fine: the kernel hands them the
 * absolute VA of the trampoline directly. Dynamic-linked glibc
 * binaries that scan AT_SYSINFO_EHDR for __vdso_clock_gettime
 * etc. will see nothing here — promoting this to a proper
 * shared object with a hash table is a follow-up slice. The
 * 0x40-byte reservation per export below leaves room for those
 * symbols to land without reflowing the offset table the
 * kernel records.
 *
 * NOTE: This is assembled for x86_64 Linux ABI (System V), NOT
 * the Windows x64 ABI used by the userland libs DLLs. Linux
 * SYS_rt_sigreturn = 15. Syscall number goes in RAX, the
 * `syscall` instruction transitions to ring 0.
 */

    .section .vdso.text, "ax", @progbits

    /* ---------------- 0x00 ---------------- */
    .globl  __kernel_rt_sigreturn
    .balign 16
__kernel_rt_sigreturn:
    movq    $15, %rax           /* Linux SYS_rt_sigreturn */
    syscall
    ud2                         /* unreachable on success */

    .balign 64                  /* reserve slot to 0x40 */

    /* ---------------- 0x40 ---------------- */
    /* Reserved for __vdso_clock_gettime when it lands. Today
     * a no-op + fallback into the syscall path. Future
     * __vdso_* entries get 0x40-aligned slots in sequence
     * (0x80, 0xC0, …) so the kernel's offset table stays
     * append-only. */

    .balign 64
__duetos_vdso_end:

    .size   __kernel_rt_sigreturn, __duetos_vdso_end - __kernel_rt_sigreturn

/* Non-executable .note section so future tooling that wants to
 * stamp a version / build-id into the blob has somewhere to put
 * it. Filtered out of the raw-binary export by the linker
 * script, but keeps the ELF intermediate properly typed. */
    .section .note.duetos.vdso, "a", @note
    .long   1f - 0f             /* namesz */
    .long   0                   /* descsz */
    .long   0                   /* type */
0:  .ascii  "DUETOS\0\0"
1:
