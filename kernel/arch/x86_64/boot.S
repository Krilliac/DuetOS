/*
 * CustomOS x86_64 boot entry.
 *
 * A Multiboot2-compatible bootloader (e.g. GRUB) loads this image in 32-bit
 * protected mode. This file brings the CPU up to long mode, installs both an
 * identity map and a higher-half map over the first 1 GiB of physical memory,
 * then far-jumps into the high-virtual-address kernel and calls kernel_main().
 *
 * Virtual-memory layout set up here:
 *   0x0000000000 .. 0x0000040000000   First 1 GiB, IDENTITY-mapped.
 *                                     Needed for the bootstrap trampoline,
 *                                     the Multiboot2 info struct, and the
 *                                     frame allocator's bitmap home.
 *   0xFFFFFFFF80000000 .. +1 GiB      Same first 1 GiB of physical memory,
 *                                     mapped into the kernel's higher half.
 *                                     The linker places all non-boot sections
 *                                     up here.
 *
 * Section placement (see linker.ld for full layout):
 *   .text.boot, .rodata.boot, .bss.boot  — STAY at low VMA. Used before the
 *                                          higher-half mapping is active.
 *   .text / .rodata / .data / .bss       — linked at KERNEL_VIRTUAL_BASE + off.
 *
 * After a far jump through the 64-bit trampoline below, execution lands in
 * high-VMA `.text` and kernel_main() is invoked with Multiboot2 handoff
 * state still preserved in rdi/rsi.
 */

.intel_syntax noprefix

#define KERNEL_VIRTUAL_BASE_HI  0xFFFFFFFF
#define KERNEL_VIRTUAL_BASE_LO  0x80000000

/* ---------------------------------------------------------------------------
 * Multiboot2 header — lives in its own section so the linker script can
 * place it at the very start of the image where the loader will find it.
 * ------------------------------------------------------------------------- */
.section .multiboot2, "a"

#define MULTIBOOT2_MAGIC        0xE85250D6
#define MULTIBOOT2_ARCH_I386    0
#define MULTIBOOT2_TAG_END      0

.align 8
multiboot2_header_start:
    .long   MULTIBOOT2_MAGIC
    .long   MULTIBOOT2_ARCH_I386
    .long   multiboot2_header_end - multiboot2_header_start
    .long   -(MULTIBOOT2_MAGIC + MULTIBOOT2_ARCH_I386 + (multiboot2_header_end - multiboot2_header_start))

    /* End tag */
    .align 8
    .word   MULTIBOOT2_TAG_END
    .word   0
    .long   8
multiboot2_header_end:


/* ---------------------------------------------------------------------------
 * Boot-local BSS. Stays at low VMA (= LMA) so the 32-bit bootstrap code can
 * write page-table entries and use the boot stack by physical address, with
 * no paging in effect.
 *
 *   boot_pml4       — top-level page map
 *   boot_pdpt       — identity-half PDPT (referenced by PML4[0])
 *   boot_pdpt_high  — higher-half PDPT (referenced by PML4[511])
 *   boot_pd         — shared 2 MiB PD; mapped from BOTH PDPTs so the first
 *                     1 GiB of physical memory is visible at phys==virt AND
 *                     at 0xFFFFFFFF80000000..
 * ------------------------------------------------------------------------- */
.section .bss.boot, "aw", @nobits
.align 4096
boot_pml4:
    .skip 4096
boot_pdpt:
    .skip 4096
boot_pdpt_high:
    .skip 4096
boot_pd:
    .skip 4096

.align 16
stack_bottom:
    .skip 16384                 /* 16 KiB boot stack */
stack_top:


/* ---------------------------------------------------------------------------
 * 32-bit entry. The Multiboot2 loader jumps here with:
 *   eax = 0x36d76289 (Multiboot2 magic)
 *   ebx = physical address of the Multiboot2 info structure
 * ------------------------------------------------------------------------- */
.section .text.boot, "ax"
.code32
.global _start
.type _start, @function
_start:
    cli
    cld

    /* Set up a temporary 32-bit stack. */
    mov     esp, offset stack_top

    /* Stash the Multiboot2 handoff state before we touch any registers.
     * Don't clobber edi/esi anywhere between here and kernel_main. */
    mov     edi, eax            /* edi = Multiboot2 magic      */
    mov     esi, ebx            /* esi = info struct phys addr */

    /*
     * Build the page hierarchy.
     *
     *   PML4[0]             -> boot_pdpt        (identity half)
     *   PML4[511]           -> boot_pdpt_high   (higher half)
     *   boot_pdpt[0]        -> boot_pd          (maps 0..1 GiB)
     *   boot_pdpt_high[510] -> boot_pd          (maps 0xFFFFFFFF80000000..+1G)
     *   boot_pd[0..511]     -> phys 0..1 GiB in 2 MiB PS pages
     *
     * PML4 index 511 covers virtual [0xFFFF800000000000 .. top].
     * Inside that, PDPT index 510 covers [0xFFFFFFFF80000000 .. +1 GiB].
     * Index 511 would be [0xFFFFFFFFC0000000 .. +1 GiB].
     *
     * All three tables live in .bss.boot and are zero-initialised, so we
     * write only the entries we care about — unused slots stay zero, and
     * absent PML4/PDPT entries cause any stray access to #PF rather than
     * silently aliasing memory.
     */

    /* PML4[0] -> boot_pdpt (identity) */
    mov     eax, offset boot_pdpt
    or      eax, 0x03                   /* present | writable */
    mov     [boot_pml4 + 0], eax

    /* PML4[511] -> boot_pdpt_high (higher half). Each PML4 entry is 8 bytes
     * so slot 511 is at offset 511 * 8 = 0xFF8. */
    mov     eax, offset boot_pdpt_high
    or      eax, 0x03
    mov     [boot_pml4 + 0xFF8], eax

    /* boot_pdpt[0] -> boot_pd (identity-maps 0..1 GiB) */
    mov     eax, offset boot_pd
    or      eax, 0x03
    mov     [boot_pdpt + 0], eax

    /* boot_pdpt_high[510] -> boot_pd (maps 0xFFFFFFFF80000000..+1 GiB to the
     * same physical range). Slot 510 is at offset 510 * 8 = 0xFF0. */
    mov     eax, offset boot_pd
    or      eax, 0x03
    mov     [boot_pdpt_high + 0xFF0], eax

    /* Fill boot_pd with 512 × 2 MiB PS pages covering phys 0..1 GiB.
     * ebx is free here (it was stashed into esi earlier) so we use it as
     * the PD cursor. DO NOT touch edi/esi. */
    mov     ecx, 512                    /* 512 PDEs = 1 GiB */
    mov     ebx, offset boot_pd
    mov     eax, 0x00000083             /* phys 0, P | RW | PS (2 MiB huge) */
fill_pd_loop:
    mov     [ebx], eax
    add     ebx, 8                      /* next PDE (high 32 bits stay zero) */
    add     eax, 0x00200000             /* advance physical by 2 MiB        */
    loop    fill_pd_loop

    /* Load PML4 into CR3. */
    mov     eax, offset boot_pml4
    mov     cr3, eax

    /* Enable PAE (CR4.PAE = bit 5). */
    mov     eax, cr4
    or      eax, (1 << 5)
    mov     cr4, eax

    /* Enable long mode via EFER.LME (MSR 0xC0000080, bit 8). */
    mov     ecx, 0xC0000080
    rdmsr
    or      eax, (1 << 8)
    wrmsr

    /* Enable paging — CR0.PG (bit 31). PE (bit 0) is already set. */
    mov     eax, cr0
    or      eax, (1 << 31)
    mov     cr0, eax

    /* Load the 64-bit GDT and far-jump into the low 64-bit trampoline.
     * The trampoline performs a 64-bit absolute jump to the high-half
     * `long_mode_entry`. We can't ljmp directly to the high-VMA target
     * because ljmp's offset field is only 32 bits. */
    lgdt    [gdt64_descriptor]
    ljmp    0x08, offset long_mode_trampoline

.size _start, . - _start


/* ---------------------------------------------------------------------------
 * 64-bit trampoline, still at LOW VMA. Bridges the 32-bit ljmp (32-bit
 * offset) and the high-VMA kernel entry (64-bit absolute address). Keeps
 * the Multiboot2 handoff in rdi/rsi by zero-extending edi/esi.
 * ------------------------------------------------------------------------- */
.code64
.global long_mode_trampoline
.type long_mode_trampoline, @function
long_mode_trampoline:
    /* Reload data segments. In long mode ds/es/fs/gs/ss are mostly ignored
     * for data access, but some corner cases still consult the selector
     * limit/present bits — null them explicitly. */
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    /* Switch onto the boot stack. stack_top lives in .bss.boot (low VMA);
     * that's fine because the identity map covers it. Later bring-up will
     * move to a per-CPU stack in kernel memory. */
    mov     rsp, offset stack_top
    xor     rbp, rbp                    /* end the call-chain for debuggers */

    /* Zero-extend the 32-bit Multiboot2 handoff state stashed in edi/esi
     * into the 64-bit argument registers kernel_main expects. */
    mov     edi, edi
    mov     esi, esi

    /* Jump to the high-VMA kernel entry. `offset long_mode_entry` resolves
     * to a 64-bit immediate (the symbol is at 0xFFFFFFFF80xxxxxx); `mov r64,
     * imm64` encodes it, and `jmp rax` does the indirect branch. The high
     * mapping is already active via boot_pml4[511] -> boot_pdpt_high[510]
     * -> boot_pd, so the instruction fetch at the new RIP resolves to the
     * same physical pages as the identity-mapped copy. */
    mov     rax, offset long_mode_entry
    jmp     rax

.size long_mode_trampoline, . - long_mode_trampoline


/* ---------------------------------------------------------------------------
 * Bootstrap GDT used only while we're in the trampoline. The kernel
 * re-installs its own GDT (with the same layout) from gdt.cpp once it
 * reaches C++. Kept in .rodata.boot so lgdt's operand resolves to a low
 * physical address (paging is off when lgdt runs). The descriptor's base
 * field points to gdt64, also in .rodata.boot.
 * ------------------------------------------------------------------------- */
.section .rodata.boot, "a"
.align 16
gdt64:
    .quad   0                               /* null descriptor       */
    .quad   0x00AF9A000000FFFF              /* 0x08 = 64-bit code    */
    .quad   0x00AF92000000FFFF              /* 0x10 = 64-bit data    */
gdt64_end:

gdt64_descriptor:
    .word   gdt64_end - gdt64 - 1
    .quad   gdt64


/* ---------------------------------------------------------------------------
 * High-VMA kernel entry. Landed here by the trampoline's `jmp rax`; RIP is
 * now in the 0xFFFFFFFF80000000 range and subsequent fetches go through
 * the higher-half mapping. Tail-calls kernel_main() with the Multiboot2
 * handoff still intact.
 * ------------------------------------------------------------------------- */
.section .text, "ax"
.code64
.global long_mode_entry
.type long_mode_entry, @function
long_mode_entry:
    call    kernel_main

    /* kernel_main should never return. If it does, halt deterministically. */
hang:
    cli
    hlt
    jmp     hang

.size long_mode_entry, . - long_mode_entry


/* Mark the stack non-executable so the linker doesn't emit a PT_GNU_STACK
 * entry with execute permission (lld warns otherwise). */
.section .note.GNU-stack, "", @progbits
