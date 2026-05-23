/*
 * kernel/arch/aarch64/boot.S
 *
 * AArch64 boot entry — second-tier pillar (x86_64 is primary).
 *
 * QEMU `virt` machine and most real ARMv8-A hardware land the
 * boot CPU at EL2 (hypervisor exception level) with the MMU
 * disabled, caches off, and a flat physical view of memory. UEFI
 * boot lands at EL2 with the loader having already set up some
 * state — we tear most of it down for a known baseline.
 *
 * Boot sequence (Pillar 1: kernel runs at EL1, never returns to
 * EL2 once we leave it):
 *
 *   1. Park secondary CPUs immediately — only the boot CPU
 *      proceeds. SMP bringup is via PSCI later.
 *   2. If we landed at EL2, configure HCR_EL2 / SCTLR_EL1 /
 *      SPSR_EL2 / ELR_EL2 and ERET to a `at_el1:` label still
 *      in this file.
 *   3. Install the exception vector table (`vectors` symbol
 *      from exceptions.S).
 *   4. Set up the boot stack (`__boot_stack_top` symbol provided
 *      by the linker script).
 *   5. Zero the BSS so static u8 buffers start at 0 (clang
 *      codegen assumes it).
 *   6. Branch to `KernelMainAArch64` (C++) — never returns.
 *
 * GAP / follow-up:
 *   - PSCI-based SMP bringup (PSCI_CPU_ON hvc).
 *   - MMU bringup with translation tables (TTBR0/TTBR1, TCR_EL1,
 *     MAIR_EL1). Currently runs with MMU OFF — fine for serial-
 *     console "hello world" but blocks anything paged.
 *   - Cache/branch-prediction maintenance (IC IALLU + DSB ISH).
 *   - GIC interrupt controller init.
 *
 * STUB: KernelMainAArch64 itself does not exist yet — this file
 * lays the entry plumbing so a future kernel slice can write a
 * C++ main and have the boot path call it. As-is, the build
 * config for aarch64 produces an assemble-only artefact (no
 * link) — see kernel/arch/aarch64/CMakeLists.txt notes when that
 * lands.
 */

    .section .text.boot, "ax", %progbits
    .globl  _start
    .type   _start, %function
_start:
    /* Step 1: park secondaries. MPIDR_EL1's lower bits encode
     * the CPU's affinity (Aff0/Aff1/Aff2/Aff3). On QEMU virt the
     * boot CPU has Aff0 == 0; any other value is a secondary
     * that we leave spinning in WFE until PSCI bringup arrives
     * later. */
    mrs     x0, mpidr_el1
    and     x0, x0, #0xFF                  /* Aff0 */
    cbz     x0, .Lboot_cpu                 /* if Aff0 == 0, this is the boot CPU */
.Lparked:
    wfe                                    /* wait-for-event; PSCI_CPU_ON wakes us */
    b       .Lparked

.Lboot_cpu:
    /* Step 2: drop to EL1 if currently at EL2. Check CurrentEL
     * (bits [3:2]: 0 = EL0, 1 = EL1, 2 = EL2, 3 = EL3). */
    mrs     x0, CurrentEL
    cmp     x0, #(2 << 2)                  /* CurrentEL == EL2 ? */
    b.ne    .Lat_el1                       /* already at EL1 (or EL3, handled below) */

    /* At EL2 — configure HCR_EL2 to give EL1 AArch64 execution,
     * SCTLR_EL1 to a sane default (MMU off, caches off,
     * little-endian), SPSR_EL2 for the ERET, ELR_EL2 to our
     * EL1 landing pad, and SP_EL1 to the boot stack. */
    mov     x0, #(1 << 31)                 /* HCR_EL2.RW = 1 (EL1 is AArch64) */
    msr     hcr_el2, x0

    mov     x0, xzr                        /* SCTLR_EL1 = 0 (MMU off, caches off, little-endian) */
    /* RES1 bits: 11, 20, 22, 23, 28, 29 must be 1. */
    orr     x0, x0, #(1 << 11)
    orr     x0, x0, #(1 << 20)
    orr     x0, x0, #(1 << 22)
    orr     x0, x0, #(1 << 23)
    orr     x0, x0, #(1 << 28)
    orr     x0, x0, #(1 << 29)
    msr     sctlr_el1, x0

    /* SPSR_EL2 for ERET: D=I=A=F masked, mode = EL1h (uses SP_EL1). */
    mov     x0, #0x3C5                     /* DAIF + M[4:0] = 0b00101 (EL1h) */
    msr     spsr_el2, x0

    /* ELR_EL2 = where we resume after ERET. */
    adr     x0, .Lat_el1
    msr     elr_el2, x0

    /* Boot stack — physical address of the linker-script symbol. */
    adrp    x0, __boot_stack_top
    add     x0, x0, #:lo12:__boot_stack_top
    msr     sp_el1, x0

    eret                                   /* drop to EL1, jump to .Lat_el1 */

.Lat_el1:
    /* If we never went through the EL2 drop (we started at EL1
     * directly), SP wasn't set. Set it here unconditionally —
     * harmless if already set via SP_EL1 above. */
    adrp    x0, __boot_stack_top
    add     x0, x0, #:lo12:__boot_stack_top
    mov     sp, x0

    /* Step 3: install the exception vector table. VBAR_EL1 must
     * be 2 KiB aligned — exceptions.S ensures this. */
    adrp    x0, vectors
    add     x0, x0, #:lo12:vectors
    msr     vbar_el1, x0
    isb                                    /* sync the VBAR change before any exception path matters */

    /* Step 4: zero the BSS. Linker script provides __bss_start /
     * __bss_end as 8-byte-aligned. */
    adrp    x0, __bss_start
    add     x0, x0, #:lo12:__bss_start
    adrp    x1, __bss_end
    add     x1, x1, #:lo12:__bss_end
.Lbss_loop:
    cmp     x0, x1
    b.ge    .Lbss_done
    str     xzr, [x0], #8
    b       .Lbss_loop
.Lbss_done:

    /* Step 5: branch to the C++ kernel main. // STUB until
     * KernelMainAArch64 lands. */
    bl      KernelMainAArch64

    /* If main ever returns (it shouldn't), park forever. */
.Lkernel_returned:
    wfe
    b       .Lkernel_returned

    .size   _start, . - _start
