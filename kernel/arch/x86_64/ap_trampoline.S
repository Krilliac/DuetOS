/*
 * AP (Application Processor) trampoline — v0.
 *
 * Each AP starts in 16-bit real mode at CS:IP = SIPI_vector:0 = 0x8000
 * after the BSP sends INIT-SIPI-SIPI with vector 0x08. This file
 * provides the code an AP runs to transition real → protected → long
 * mode and jump into a C++ entry that takes over.
 *
 * Layout (offsets from ap_trampoline_start, which is copied to phys
 * 0x8000 at boot):
 *
 *     0x0000  _tramp_real    — 16-bit entry, sets up PE
 *     0x0040  _tramp_prot    — 32-bit, sets up PAE + LME + PG
 *     0x00A0  _tramp_long    — 64-bit, jumps to C++ entry
 *     0x00F0  _tramp_gdt     — 5-entry GDT (null, 32c, 32d, 64c, 64d)
 *     0x0118  _tramp_gdt_ptr — GDTR value (limit + base)
 *     ...
 *     0xFD4   online_flag (u32) — AP writes 1 when it's alive
 *     0xFD8   cpu_id (u32)      — BSP writes per-AP
 *     0xFE0   ap_entry_fn (u64) — BSP writes (kernel VA of ApEntry)
 *     0xFE8   stack_top (u64)   — BSP writes per-AP
 *     0xFF0   pml4_phys (u64)   — BSP writes (shared PML4 root)
 *
 * Position-independent WRT the source image: assembler uses only
 * literal absolute addresses of the form `TRAMP_BASE + OFF_*`, which
 * are compile-time constants. No cross-symbol arithmetic in memory
 * operands (works around GNU as's "one symbol per operand"
 * restriction). The BSP copies this image byte-for-byte to phys
 * 0x8000, so the literal addresses resolve correctly at runtime.
 *
 * See docs/knowledge/smp-ap-bringup-scope.md for the plan this
 * implements and the remaining AP-side work (scheduler join).
 */

.intel_syntax noprefix

.set TRAMP_BASE,        0x8000
.set OFF_REAL,          0x0000
.set OFF_PROT,          0x0040
.set OFF_LONG,          0x00A0
.set OFF_GDT,           0x00F0
.set OFF_GDT_PTR,       0x0118
.set OFF_ONLINE_FLAG,   0xFD4
.set OFF_CPU_ID,        0xFD8
.set OFF_ENTRY,         0xFE0
.set OFF_STACK,         0xFE8
.set OFF_PML4,          0xFF0

.section .text.ap_tramp, "ax", @progbits

.global ap_trampoline_start
.global ap_trampoline_end

ap_trampoline_start:

/* ------------------------------------------------------------------
 * 16-bit real-mode entry. CS:IP = 0x0800:0x0000 → linear 0x8000.
 * ------------------------------------------------------------------ */
.org OFF_REAL
.code16
    cli
    cld

    /* Flat segments: DS=ES=SS=0 so absolute addresses below 1 MiB
       resolve to themselves. */
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     ss, ax

    /* Load the trampoline's tiny GDT. Memory operand is a compile-
       time constant (single `.set` expression) so GNU as accepts it
       in Intel syntax without complaining about multiple symbols. */
    lgdt    [TRAMP_BASE + OFF_GDT_PTR]

    /* Enter protected mode (CR0.PE=1). */
    mov     eax, cr0
    or      eax, 1
    mov     cr0, eax

    /* Far jump to 32-bit code — reloads CS. Intel-syntax ljmp with
       immediate selector+offset doesn't assemble cleanly in GNU as,
       so hand-encode: 0x66 operand-size prefix + 0xEA far jmp + imm32
       offset + imm16 selector. */
    .byte   0x66, 0xEA
    .long   TRAMP_BASE + OFF_PROT
    .word   0x08

/* ------------------------------------------------------------------
 * 32-bit protected mode. Enable PAE + LME, then paging.
 * ------------------------------------------------------------------ */
.org OFF_PROT
.code32
    /* Reload data segments to the flat 32-bit data selector. */
    mov     ax, 0x10
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    /* CR3 = shared kernel PML4 from the BSP-written parameter block. */
    mov     eax, [TRAMP_BASE + OFF_PML4]
    mov     cr3, eax

    /* CR4.PAE + SSE support bits. Must match the BSP path in
     * boot.S so SSE-using user binaries work on any CPU:
     *   bit 5  = PAE   (required for long mode)
     *   bit 9  = OSFXSR  (SSE FXSAVE/FXRSTOR)
     *   bit 10 = OSXMMEXCPT (SIMD FP exceptions) */
    mov     eax, cr4
    or      eax, (1 << 5) | (1 << 9) | (1 << 10)
    mov     cr4, eax

    /* CR0 tune-up for SSE: CR0.EM=0 (no emulation), CR0.MP=1.
     * See boot.S for rationale. */
    mov     eax, cr0
    and     eax, ~(1 << 2)
    or      eax, (1 << 1)
    mov     cr0, eax

    /* EFER.LME = 1 AND EFER.NXE = 1. NXE matters: the kernel's MMIO
       mappings have the NX bit set (see mm/paging.h kKernelMmio),
       and accessing them with NXE=0 triggers a reserved-bit #PF on
       the very first LAPIC register read from the AP. BSP turns NXE
       on in PagingInit; each AP has to do the same in its own EFER. */
    mov     ecx, 0xC0000080
    rdmsr
    or      eax, (1 << 8) | (1 << 11)
    wrmsr

    /* CR0.PG = 1. Long mode becomes active once CS is reloaded. */
    mov     eax, cr0
    or      eax, 1 << 31
    mov     cr0, eax

    /* Far jump to 64-bit code. Hand-encoded like the real→prot jump
       above, but without the operand-size prefix (native 32-bit
       ljmp already has a 4-byte offset + 2-byte selector). */
    .byte   0xEA
    .long   TRAMP_BASE + OFF_LONG
    .word   0x18

/* ------------------------------------------------------------------
 * 64-bit long mode. Set the AP's stack + jump to the C++ entry.
 * ------------------------------------------------------------------ */
.org OFF_LONG
.code64
    /* Load the per-AP stack top (kernel VA, set up by BSP). */
    mov     rax, TRAMP_BASE + OFF_STACK
    mov     rsp, [rax]
    xor     rbp, rbp

    /* cpu_id → rdi (SysV first arg for ApEntryFromTrampoline). */
    mov     rax, TRAMP_BASE + OFF_CPU_ID
    mov     edi, [rax]

    /* Tail-call into the kernel's C++ entry point. [[noreturn]]. */
    mov     rax, TRAMP_BASE + OFF_ENTRY
    jmp     [rax]

/* ------------------------------------------------------------------
 * GDT used only during the real → protected → long transition. The
 * kernel's real GDT is loaded later by the AP's C++ entry once it
 * joins the scheduler (future commit).
 * ------------------------------------------------------------------ */
.org OFF_GDT
_tramp_gdt:
    .quad   0x0000000000000000   /* 0x00 null */
    .quad   0x00CF9A000000FFFF   /* 0x08 32-bit code */
    .quad   0x00CF92000000FFFF   /* 0x10 32-bit data */
    .quad   0x00AF9A000000FFFF   /* 0x18 64-bit code (L bit set) */
    .quad   0x00AF92000000FFFF   /* 0x20 64-bit data */

.org OFF_GDT_PTR
    .word   0x27                   /* limit = 5 entries * 8 bytes - 1 */
    .quad   TRAMP_BASE + OFF_GDT   /* base = absolute addr of gdt */

/* Pad the whole trampoline to a full 4 KiB so that the parameter
   block at 0xFD4..0xFFF stays inside the section the BSP copies.
   BSS-style `.space` is fine since we zero-fill at copy time. */
.org 0x1000
ap_trampoline_end:
