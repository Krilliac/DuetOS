/*
 * DuetOS — Intel CET (Control-flow Enforcement Technology) helpers.
 *
 * The probe + enable bookkeeping lives in cet.cpp / cet.h. This file
 * owns the four primitives that have to be assembly because the
 * compiler doesn't expose them as intrinsics in our toolchain
 * version, or because they touch state (RSP, MSRs) the C++ ABI
 * forbids us to disturb mid-function:
 *
 *   void CetEnableMsrs (u64 s_cet, u64 u_cet);
 *   void CetSetPl0Ssp  (u64 ssp);
 *   u64  CetGetSsp     (void);
 *   void CetSwitchSsp  (u64 ssp);
 *
 * The MSR helpers wrap the raw `wrmsr` so the cet.cpp init path
 * doesn't have to repeat the ECX/EDX/EAX dance for every CET MSR.
 * `CetGetSsp` returns the running shadow stack pointer (RDSSPQ);
 * `CetSwitchSsp` writes IA32_PL0_SSP for ring-0 (kernel) shadow
 * stacks. Ring-3 shadow-stack switching is implicit — `iretq` to
 * user mode pops the user SSP from the per-CPU table that
 * IA32_INTERRUPT_SSP_TABLE_ADDR points at.
 *
 * Endbr64 prologues: present on every entry below. The kernel will
 * have IBT enabled once cet.cpp::CetEnable() runs, at which point a
 * call into any of these (which IS an indirect call from C++) lands
 * on the prologue. Without it the first call would raise #CP.
 */

.intel_syntax noprefix

.set IA32_S_CET,                 0x6A2
.set IA32_PL0_SSP,               0x6A4
.set IA32_PL3_SSP,               0x6A7
.set IA32_INTERRUPT_SSP_TABLE,   0x6A8
.set IA32_U_CET,                 0x6A0

.section .text

/* -------------------------------------------------------------------------
 * CetEnableMsrs(s_cet, u_cet)
 *   rdi = IA32_S_CET value (kernel-mode CET config)
 *   rsi = IA32_U_CET value (user-mode CET config)
 *
 * Each MSR holds a 64-bit configuration word. Common bits:
 *   bit 0  SH_STK_EN     enable shadow stack
 *   bit 1  WR_SHSTK_EN   permit WRSS / WRUSS writes
 *   bit 2  ENDBR_EN      enforce IBT (require ENDBR landing pads)
 *   bit 3  LEG_IW_EN     legacy IW behavior (off in modern kernels)
 *   bit 4  NO_TRACK_EN   permit notrack-prefix indirect branches
 * Higher bits hold the LEGACY_BITMAP_BASE (which we don't use).
 * ------------------------------------------------------------------------- */
.align 16
.global CetEnableMsrs
.type CetEnableMsrs, @function
CetEnableMsrs:
    endbr64
    /* Save callee-saved we'll touch. We use rcx (MSR index) and
     * rax/rdx (MSR value), all caller-saved per SysV. */
    mov     rax, rdi
    mov     rdx, rdi
    shr     rdx, 32
    mov     rcx, IA32_S_CET
    wrmsr

    mov     rax, rsi
    mov     rdx, rsi
    shr     rdx, 32
    mov     rcx, IA32_U_CET
    wrmsr
    ret
.size CetEnableMsrs, . - CetEnableMsrs


/* -------------------------------------------------------------------------
 * CetSetPl0Ssp(ssp_top)
 *   rdi = address of the top of the kernel shadow stack for this CPU.
 *
 * IA32_PL0_SSP is the value the CPU loads into its shadow-stack
 * pointer when transferring to ring 0 — i.e. on every interrupt and
 * syscall entry. Set this once per CPU at bring-up; the AP path
 * does the same thing for each AP's allocation.
 * ------------------------------------------------------------------------- */
.align 16
.global CetSetPl0Ssp
.type CetSetPl0Ssp, @function
CetSetPl0Ssp:
    endbr64
    mov     rax, rdi
    mov     rdx, rdi
    shr     rdx, 32
    mov     rcx, IA32_PL0_SSP
    wrmsr
    ret
.size CetSetPl0Ssp, . - CetSetPl0Ssp


/* -------------------------------------------------------------------------
 * CetGetSsp() -> rax
 *
 * Reads the current shadow-stack pointer. Used by the scheduler at
 * task-out so the per-task SSP slot can be saved alongside the
 * regular RSP. RDSSPQ is encoded as `f3 48 1e c8` (REP REX.W
 * INCSSPQ rax) — and clang knows it as `rdsspq`.
 * ------------------------------------------------------------------------- */
.align 16
.global CetGetSsp
.type CetGetSsp, @function
CetGetSsp:
    endbr64
    rdsspq  rax
    ret
.size CetGetSsp, . - CetGetSsp


/* -------------------------------------------------------------------------
 * CetSwitchSsp(new_ssp)
 *   rdi = SSP value to install for the next ring-0 entry.
 *
 * Just an alias of CetSetPl0Ssp at the asm level — kept as a
 * separate symbol so the scheduler's intent (switching between
 * tasks) is distinct from the init-time intent (priming the BSP)
 * in stack traces and in the public API.
 * ------------------------------------------------------------------------- */
.align 16
.global CetSwitchSsp
.type CetSwitchSsp, @function
CetSwitchSsp:
    endbr64
    mov     rax, rdi
    mov     rdx, rdi
    shr     rdx, 32
    mov     rcx, IA32_PL0_SSP
    wrmsr
    ret
.size CetSwitchSsp, . - CetSwitchSsp


.section .note.GNU-stack, "", @progbits
