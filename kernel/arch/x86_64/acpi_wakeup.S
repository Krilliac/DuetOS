/*
 * ACPI S3 wake trampoline + CPU context save/restore.
 *
 * Two independent pieces live here:
 *
 *   1. acpi_wake_tramp_start .. acpi_wake_tramp_end
 *      A position-fixed blob copied byte-for-byte to physical
 *      0x9000. Firmware re-enters it in 16-bit REAL MODE after an S3
 *      resume (CS:IP built from the FACS waking vector). It walks
 *      real -> protected -> long mode using its own transition GDT
 *      and the kernel PML4 the BSP left in its parameter block, then
 *      jumps to the 64-bit resume entry (also from the block).
 *
 *      Modelled on ap_trampoline.S — same absolute-literal addressing
 *      discipline (`WAKE_BASE + OFF_*` are compile-time constants, so
 *      GNU as accepts them as single-symbol memory operands), same
 *      4 KiB padding so the parameter block stays inside the copied
 *      image. The two blobs occupy adjacent reserved low pages.
 *
 *   2. AcpiSuspendEnter / AcpiWakeResume64
 *      A setjmp/longjmp pair across the power transition.
 *      AcpiSuspendEnter saves the architectural state S3 destroys and
 *      returns 0 if the sleep never took; AcpiWakeResume64 restores
 *      it and returns 1 out of the same call. Both share one exit
 *      path so the stack stays balanced either way.
 *
 * Restoration order matters and is not arbitrary:
 *   CR3 is already live (the trampoline loaded it) -> CR4 -> EFER ->
 *   CR0 -> GDT + CS/data selectors -> TSS busy-bit clear + LTR ->
 *   IDT -> MSRs -> stack + GPRs. Loading the IDT before the GDT would
 *   leave gate selectors resolving against the transition GDT; taking
 *   an NMI in that window would fault on a bogus IST.
 *
 * See acpi_wakeup.h for the AcpiWakeContext layout this file indexes
 * by raw byte offset; acpi_wakeup.cpp static_asserts the offsets.
 */

.intel_syntax noprefix

/* ---- Trampoline layout (offsets from the blob start) ------------- */
.set WAKE_BASE,         0x9000
.set OFF_REAL,          0x0000
.set OFF_PROT,          0x0040
.set OFF_LONG,          0x00A0
.set OFF_GDT,           0x00F0
.set OFF_GDT_PTR,       0x0118
.set OFF_PML4,          0x0F00      /* u64: kernel CR3            */
.set OFF_RESUME,        0x0F08      /* u64: AcpiWakeResume64 VA   */

/* ---- AcpiWakeContext byte offsets (mirrored in acpi_wakeup.h) ---- */
.set CTX_RSP,            0
.set CTX_CR0,            8
.set CTX_CR3,           16
.set CTX_CR4,           24
.set CTX_EFER,          32
.set CTX_STAR,          40
.set CTX_LSTAR,         48
.set CTX_SFMASK,        56
.set CTX_FS_BASE,       64
.set CTX_GS_BASE,       72
.set CTX_KGS_BASE,      80
.set CTX_TSS_RSP0,      88
.set CTX_GDTR,          96
.set CTX_IDTR,         106
.set CTX_TR,           116
.set CTX_CS,           118
.set CTX_SS,           120
.set CTX_DS,           122
.set CTX_RESUME_COUNT, 124

/* MSR numbers. */
.set MSR_EFER,          0xC0000080
.set MSR_STAR,          0xC0000081
.set MSR_LSTAR,         0xC0000082
.set MSR_SFMASK,        0xC0000084
.set MSR_FS_BASE,       0xC0000100
.set MSR_GS_BASE,       0xC0000101
.set MSR_KERNEL_GS,     0xC0000102

.section .text.acpi_wake_tramp, "ax", @progbits

.global acpi_wake_tramp_start
.global acpi_wake_tramp_end

acpi_wake_tramp_start:

/* ------------------------------------------------------------------
 * 16-bit real-mode entry. Firmware enters here with CS:IP built from
 * the FACS waking vector (0x0900:0x0000 -> linear 0x9000).
 * ------------------------------------------------------------------ */
.org OFF_REAL
.code16
    cli
    cld

    /* Breadcrumb '1' straight out of the UART. Nothing else in the
       machine is trustworthy yet, and the alternative to a raw port
       write is a silent failure that looks identical to "firmware
       never jumped here at all". */
    mov     dx, 0x3F8
    mov     al, 0x31
    out     dx, al

    /* Flat segments so absolute sub-1-MiB addresses resolve to
       themselves. Firmware leaves these arbitrary. */
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     ss, ax

    lgdt    [WAKE_BASE + OFF_GDT_PTR]

    /* Enter protected mode (CR0.PE=1). Also force-clear CR0.PG in
       case firmware resumed with paging already on from its own
       stub — we install our own CR3 below. */
    mov     eax, cr0
    and     eax, 0x7FFFFFFF
    or      eax, 1
    mov     cr0, eax

    /* Far jump to 32-bit code, hand-encoded: 0x66 operand-size
       prefix + 0xEA far jmp + imm32 offset + imm16 selector. */
    .byte   0x66, 0xEA
    .long   WAKE_BASE + OFF_PROT
    .word   0x08

/* ------------------------------------------------------------------
 * 32-bit protected mode. PAE + LME + paging, using the kernel PML4.
 * ------------------------------------------------------------------ */
.org OFF_PROT
.code32
    mov     ax, 0x10
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    /* Breadcrumb '2': protected mode reached. */
    mov     dx, 0x3F8
    mov     al, 0x32
    out     dx, al

    /* CR3 = kernel PML4 (BSP wrote it into the parameter block). */
    mov     eax, [WAKE_BASE + OFF_PML4]
    mov     cr3, eax

    /* CR4: PAE (required for long mode) + OSFXSR + OSXMMEXCPT so the
       far jump below and the resume stub can execute SSE. The full
       CR4 — SMEP/SMAP/CET — is restored from the saved context by
       AcpiWakeResume64; this is only enough to get there. */
    mov     eax, cr4
    or      eax, (1 << 5) | (1 << 9) | (1 << 10)
    mov     cr4, eax

    /* CR0.EM=0, CR0.MP=1 for SSE, mirroring boot.S. */
    mov     eax, cr0
    and     eax, ~(1 << 2)
    or      eax, (1 << 1)
    mov     cr0, eax

    /* EFER.LME + EFER.NXE. NXE is not optional: kernel MMIO PTEs
       carry the NX bit, and touching one with NXE=0 is a reserved-bit
       #PF. Same rationale as ap_trampoline.S. */
    mov     ecx, MSR_EFER
    rdmsr
    or      eax, (1 << 8) | (1 << 11)
    wrmsr

    /* CR0.PG=1 — long mode activates on the CS reload below. */
    mov     eax, cr0
    or      eax, 1 << 31
    mov     cr0, eax

    .byte   0xEA
    .long   WAKE_BASE + OFF_LONG
    .word   0x18

/* ------------------------------------------------------------------
 * 64-bit long mode. Hand off to the kernel resume stub, which runs at
 * its normal kernel VA (mapped by the CR3 we just installed).
 * ------------------------------------------------------------------ */
.org OFF_LONG
.code64
    /* Breadcrumb '3': long mode reached, kernel CR3 live. */
    mov     dx, 0x3F8
    mov     al, 0x33
    out     dx, al

    mov     rax, WAKE_BASE + OFF_RESUME
    jmp     [rax]

/* ------------------------------------------------------------------
 * Transition GDT — discarded as soon as AcpiWakeResume64 reloads the
 * kernel's own GDT from the saved GDTR.
 * ------------------------------------------------------------------ */
.org OFF_GDT
    .quad   0x0000000000000000   /* 0x00 null */
    .quad   0x00CF9A000000FFFF   /* 0x08 32-bit code */
    .quad   0x00CF92000000FFFF   /* 0x10 32-bit data */
    .quad   0x00AF9A000000FFFF   /* 0x18 64-bit code (L bit set) */
    .quad   0x00AF92000000FFFF   /* 0x20 64-bit data */

.org OFF_GDT_PTR
    .word   0x27                   /* limit = 5 entries * 8 - 1 */
    .quad   WAKE_BASE + OFF_GDT    /* base */

/* Pad to a full 4 KiB so the parameter block at OFF_PML4/OFF_RESUME
   is inside the image the BSP copies. */
.org 0x1000
acpi_wake_tramp_end:


/* ==================================================================
 * Save / restore pair. These are ordinary kernel text, linked and run
 * at their kernel VA — NOT part of the copied blob.
 * ================================================================== */
.section .text, "ax", @progbits
.code64

.global AcpiSuspendEnter
.global AcpiWakeResume64

/*
 * u32 AcpiSuspendEnter(AcpiWakeContext* ctx, void (*enter_sleep)());
 *   rdi = ctx, rsi = enter_sleep
 *
 * Returns 0 when enter_sleep returned normally (the platform did not
 * honour the sleep write), 1 when we actually resumed from S3.
 */
AcpiSuspendEnter:
    /* Callee-saved set + flags. The resume path pops this exact
       frame, so the two paths must push identically. */
    push    rbp
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    pushfq

    /* Stash the context pointer where the resume path can find it —
       it is a global, but keeping rdi live across the sleep call is
       not possible (rdi is caller-saved). */
    mov     [rdi + CTX_RSP], rsp

    /* Control registers. */
    mov     rax, cr0
    mov     [rdi + CTX_CR0], rax
    mov     rax, cr3
    mov     [rdi + CTX_CR3], rax
    mov     rax, cr4
    mov     [rdi + CTX_CR4], rax

    /* Descriptor tables + task register. */
    sgdt    [rdi + CTX_GDTR]
    sidt    [rdi + CTX_IDTR]
    str     word ptr [rdi + CTX_TR]
    mov     ax, cs
    mov     [rdi + CTX_CS], ax
    mov     ax, ss
    mov     [rdi + CTX_SS], ax
    mov     ax, ds
    mov     [rdi + CTX_DS], ax

    /* MSRs. rdmsr clobbers rax/rdx/rcx, so rdi is reloaded implicitly
       by staying untouched (it is callee-clobbered but we never let
       anything call out of here until the sleep write). */
    mov     ecx, MSR_EFER
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    mov     [rdi + CTX_EFER], rax

    mov     ecx, MSR_STAR
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    mov     [rdi + CTX_STAR], rax

    mov     ecx, MSR_LSTAR
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    mov     [rdi + CTX_LSTAR], rax

    mov     ecx, MSR_SFMASK
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    mov     [rdi + CTX_SFMASK], rax

    mov     ecx, MSR_FS_BASE
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    mov     [rdi + CTX_FS_BASE], rax

    mov     ecx, MSR_GS_BASE
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    mov     [rdi + CTX_GS_BASE], rax

    mov     ecx, MSR_KERNEL_GS
    rdmsr
    shl     rdx, 32
    or      rax, rdx
    mov     [rdi + CTX_KGS_BASE], rax

    /* Commit the sleep. On a real S3 this never returns; control
       reappears at AcpiWakeResume64 via firmware + trampoline. */
    call    rsi

    /* Still running => the platform declined the transition. */
    xor     eax, eax
    jmp     .Lwake_exit

/*
 * AcpiWakeResume64 — entered from the trampoline in long mode with
 * the kernel CR3 live, the transition GDT loaded, interrupts off, and
 * no usable stack. Restores everything S3 destroyed.
 */
AcpiWakeResume64:
    /* The context is a fixed global; RIP-relative so we do not depend
       on any register surviving the power cycle. */
    lea     rdi, [rip + g_acpi_wake_ctx]

    /* CR4 first: SMEP/SMAP/CET must be live before we touch kernel
       structures, and CR4 writes are legal in long mode. */
    mov     rax, [rdi + CTX_CR4]
    mov     cr4, rax

    /* EFER — SCE (SYSCALL enable) and NXE come back here. */
    mov     rax, [rdi + CTX_EFER]
    mov     rdx, rax
    shr     rdx, 32
    mov     ecx, MSR_EFER
    wrmsr

    /* CR0 — WP in particular. */
    mov     rax, [rdi + CTX_CR0]
    mov     cr0, rax

    /* Kernel GDT. CS still holds the transition selector with a
       cached descriptor, so reload it with a far return. */
    lgdt    [rdi + CTX_GDTR]

    movzx   rax, word ptr [rdi + CTX_CS]
    push    rax
    lea     rax, [rip + .Lwake_cs_reloaded]
    push    rax
    /* 64-bit far return. Spelled as raw bytes because the integrated
       assembler rejects `lretq` in Intel syntax: REX.W (0x48) + RETF
       (0xCB) pops a 64-bit RIP and a 16-bit CS from the stack. */
    .byte   0x48, 0xCB

.Lwake_cs_reloaded:
    /* Data selectors. SS must be reloaded before any stack use. */
    mov     ax, [rdi + CTX_DS]
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ax, [rdi + CTX_SS]
    mov     ss, ax

    /* The TSS descriptor in the (restored) GDT still carries the BUSY
       type from before the suspend — nothing cleared it, because the
       CPU that set it lost power rather than switching away. `ltr` on
       a busy TSS raises #GP, so clear bit 1 of the access byte
       (type 0xB "busy" -> 0x9 "available") first.
       GDT base is at CTX_GDTR+2; the access byte of the descriptor
       selected by TR is at base + (TR & ~7) + 5. */
    mov     rax, [rdi + CTX_GDTR + 2]      /* GDT base */
    movzx   rcx, word ptr [rdi + CTX_TR]
    and     rcx, 0xFFF8
    add     rax, rcx
    and     byte ptr [rax + 5], 0xFD       /* clear the busy bit */

    /* Restore the scheduler-owned RSP0 into the TSS body before LTR
       caches the descriptor. TSS base is split across the descriptor:
       base[23:0] at +2..+4, base[31:24] at +7, base[63:32] at +8. */
    movzx   rdx, byte ptr [rax + 7]
    shl     rdx, 24
    movzx   rcx, word ptr [rax + 2]
    or      rdx, rcx
    movzx   rcx, byte ptr [rax + 4]
    shl     rcx, 16
    or      rdx, rcx
    mov     ecx, [rax + 8]
    shl     rcx, 32
    or      rdx, rcx                        /* rdx = TSS base */
    mov     rcx, [rdi + CTX_TSS_RSP0]
    mov     [rdx + 4], rcx                  /* Tss::rsp0 is at +4 */

    movzx   rax, word ptr [rdi + CTX_TR]
    ltr     ax

    /* Kernel IDT — after the GDT, so gate selectors resolve. */
    lidt    [rdi + CTX_IDTR]

    /* SYSCALL MSRs + segment bases. */
    mov     rax, [rdi + CTX_STAR]
    mov     rdx, rax
    shr     rdx, 32
    mov     ecx, MSR_STAR
    wrmsr

    mov     rax, [rdi + CTX_LSTAR]
    mov     rdx, rax
    shr     rdx, 32
    mov     ecx, MSR_LSTAR
    wrmsr

    mov     rax, [rdi + CTX_SFMASK]
    mov     rdx, rax
    shr     rdx, 32
    mov     ecx, MSR_SFMASK
    wrmsr

    mov     rax, [rdi + CTX_FS_BASE]
    mov     rdx, rax
    shr     rdx, 32
    mov     ecx, MSR_FS_BASE
    wrmsr

    mov     rax, [rdi + CTX_KGS_BASE]
    mov     rdx, rax
    shr     rdx, 32
    mov     ecx, MSR_KERNEL_GS
    wrmsr

    /* GS_BASE last among the MSRs: the `mov %ax, %gs` above zeroed
       IA32_GS_BASE as a side effect, so the per-CPU pointer has to be
       reprogrammed after the segment loads, not before. Same ordering
       trap the SMP AP path documents. */
    mov     rax, [rdi + CTX_GS_BASE]
    mov     rdx, rax
    shr     rdx, 32
    mov     ecx, MSR_GS_BASE
    wrmsr

    /* Record that we came through here — the wake proof the suspend
       orchestrator logs and the self-test checks. */
    inc     dword ptr [rdi + CTX_RESUME_COUNT]

    /* Back onto the suspended kernel stack and out through the shared
       epilogue with a return value of 1. */
    mov     rsp, [rdi + CTX_RSP]
    mov     eax, 1

.Lwake_exit:
    popfq
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret

.section .note.GNU-stack, "", @progbits
