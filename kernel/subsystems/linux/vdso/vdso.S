/*
 * kernel/subsystems/linux/vdso/vdso.S
 *
 * DuetOS Linux-ABI vDSO blob — v1.
 *
 * One executable page mapped into every Linux ELF process at a
 * kernel-chosen VA. The build script records per-export offsets
 * in a generated header (kOffLinuxVdso*) which spawn.cpp reads
 * to compute absolute VAs for each entry on each spawn. Today's
 * exports:
 *
 *   __kernel_rt_sigreturn   — signal-handler return trampoline.
 *                             Used by LinuxSignalCheckAndDeliver
 *                             when the caller's sigaction omitted
 *                             SA_RESTORER. Issues SYS_rt_sigreturn
 *                             (nr 15). Never returns.
 *
 *   __vdso_clock_gettime    — clock_gettime(clk_id, ts).
 *                             RDI/RSI in, RAX out. SYS_clock_gettime
 *                             (nr 228).
 *
 *   __vdso_gettimeofday     — gettimeofday(tv, tz).
 *                             RDI/RSI in, RAX out. SYS_gettimeofday
 *                             (nr 96).
 *
 *   __vdso_time             — time(t_out).
 *                             RDI in, RAX out (seconds since epoch).
 *                             SYS_time (nr 201).
 *
 *   __vdso_getcpu           — getcpu(cpu_out, node_out, ...).
 *                             RDI/RSI/RDX in, RAX out.
 *                             SYS_getcpu (nr 309).
 *
 * The __vdso_* entries are all "trap to syscall" today — same cost
 * as a direct `syscall` from user code, just routed through the
 * vDSO page so the export shape is correct and a future
 * shared-memory fast-path slice can swap the body without
 * changing the ABI.
 *
 * NO real ELF header / PT_LOAD / dynamic symbol table / hash
 * table yet. Static-linked binaries that hardcode the entry VA
 * (or get it via the kernel-recorded Process::linux_vdso_*_va
 * fields) work. Dynamic glibc that scans AT_SYSINFO_EHDR for
 * __vdso_* via the SysV hash table sees nothing — promoting
 * to a real .so is the next slice.
 *
 * GAP: AT_SYSINFO_EHDR auxv entry + real ELF wrapper — lands
 * with the dynamic-glibc support slice. Until then the
 * __vdso_* exports are reachable only via direct VA recorded
 * by the kernel (Process::linux_vdso_*_va) or by hardcoded
 * offsets in the build-time embedded blob.
 *
 * Assembled for x86_64 Linux ABI (System V) — RDI/RSI/RDX/R10/
 * R8/R9 are the integer argument registers; RAX is the syscall
 * number; `syscall` transitions to ring 0.
 */

    .section .vdso.text, "ax", @progbits

    /* ---------------- __kernel_rt_sigreturn ---------------- */
    /* Stays at offset 0 by convention (chronological — this was
     * the v0 export). Build script records the offset anyway,
     * so the spawn-time VA computation doesn't depend on the
     * file ordering. */
    .globl  __kernel_rt_sigreturn
    .balign 16
__kernel_rt_sigreturn:
    movq    $15, %rax           /* Linux SYS_rt_sigreturn */
    syscall
    ud2                         /* unreachable on success */

    /* ---------------- __vdso_clock_gettime ---------------- */
    /* clock_gettime(clk_id, struct timespec* ts). Returns 0 on
     * success or -errno on failure (which the syscall encodes
     * as a negative RAX in the SysV-Linux convention; vDSO
     * passes it through unchanged). */
    .globl  __vdso_clock_gettime
    .balign 16
__vdso_clock_gettime:
    movq    $228, %rax          /* Linux SYS_clock_gettime */
    syscall
    retq

    /* ---------------- __vdso_gettimeofday ---------------- */
    /* gettimeofday(struct timeval* tv, struct timezone* tz).
     * Same return convention as above. */
    .globl  __vdso_gettimeofday
    .balign 16
__vdso_gettimeofday:
    movq    $96, %rax           /* Linux SYS_gettimeofday */
    syscall
    retq

    /* ---------------- __vdso_time ---------------- */
    /* time(time_t* t). Returns seconds since epoch in RAX; if
     * t != NULL the kernel also writes the value through the
     * pointer. */
    .globl  __vdso_time
    .balign 16
__vdso_time:
    movq    $201, %rax          /* Linux SYS_time */
    syscall
    retq

    /* ---------------- __vdso_getcpu ---------------- */
    /* getcpu(unsigned* cpu, unsigned* node, struct getcpu_cache*
     * unused). Returns 0 on success. The third arg is ignored
     * by real Linux (the cache field was for the v2.6 LSCALL
     * fast-path, deprecated). */
    .globl  __vdso_getcpu
    .balign 16
__vdso_getcpu:
    movq    $309, %rax          /* Linux SYS_getcpu */
    syscall
    retq

    .balign 16
__duetos_vdso_end:

    .size   __kernel_rt_sigreturn, __duetos_vdso_end - __kernel_rt_sigreturn

/* Non-executable .note section for future build-id / version
 * stamping. Filtered out of the raw-binary export by the linker
 * script; keeps the intermediate ELF properly typed. */
    .section .note.duetos.vdso, "a", @note
    .long   1f - 0f             /* namesz */
    .long   0                   /* descsz */
    .long   0                   /* type */
0:  .ascii  "DUETOS\0\0"
1:
