/*
 * CustomOS x86_64 boot entry.
 *
 * A Multiboot2-compatible bootloader (e.g. GRUB) loads this image in 32-bit
 * protected mode. This file brings the CPU up to long mode with a tiny
 * identity-mapped page hierarchy, then calls kernel_main().
 *
 * Memory layout set up here (all physical = virtual while we're identity-mapped):
 *   0x0000000000 .. 0x0000040000000   First 1 GiB, mapped via 512 × 2 MiB PDEs.
 *
 *   Why 1 GiB: the frame allocator bitmap lives in normal RAM and scales
 *   with physical memory size. QEMU dev machines routinely have 512 MiB
 *   to a few GiB. 1 GiB keeps us well under the "need a second PDPT"
 *   threshold while giving the allocator room to work without further
 *   paging surgery.
 *
 * This is deliberately the smallest bring-up that can call C++ code. Paging,
 * IDT, GDT, SMP, and the real kernel address-space layout come in follow-up
 * commits — this file's job is "hand control to kernel_main() in long mode
 * with a valid stack."
 */

.intel_syntax noprefix

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
 * BSS reservations: stack, and the three-level page hierarchy we need to
 * enter long mode (PML4 + PDPT + PD). Each table is 4 KiB, naturally aligned.
 * ------------------------------------------------------------------------- */
.section .bss, "aw", @nobits
.align 4096
boot_pml4:
    .skip 4096
boot_pdpt:
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

    /* Stash the Multiboot2 handoff state before we touch any registers. */
    mov     edi, eax            /* edi = Multiboot2 magic  */
    mov     esi, ebx            /* esi = info struct phys addr */

    /*
     * Build identity-mapped first 1 GiB using 512 × 2 MiB PDEs.
     *   PML4[0]    -> boot_pdpt   (P | RW)
     *   PDPT[0]    -> boot_pd     (P | RW)
     *   PD[0..511] -> phys 0..1 GiB in 2 MiB steps (P | RW | PS)
     *
     * All three tables live in .bss and are zero-initialised, so we only
     * write the entries we care about — unused high slots stay zero. We
     * write just the low 32 bits of each PDE: the high 32 stay zero,
     * which is correct for any physical address under 4 GiB.
     */
    mov     eax, offset boot_pdpt
    or      eax, 0x03           /* present | writable */
    mov     [boot_pml4], eax

    mov     eax, offset boot_pd
    or      eax, 0x03
    mov     [boot_pdpt], eax

    /* NOTE: edi and esi hold the Multiboot2 magic and info pointer that we
     * pass to kernel_main. Don't touch them here. ebx was stashed into esi
     * above so it's free to reuse as our PD cursor. */
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

    /* Load the 64-bit GDT and far-jump into the 64-bit code segment. */
    lgdt    [gdt64_descriptor]
    ljmp    0x08, offset long_mode_entry

.size _start, . - _start


/* ---------------------------------------------------------------------------
 * 64-bit entry. Runs with the identity-mapped first 2 MiB, the temporary
 * GDT, and the boot stack. Reloads the data segments (all set to zero/null
 * in long mode) and calls kernel_main().
 * ------------------------------------------------------------------------- */
.code64
.global long_mode_entry
.type long_mode_entry, @function
long_mode_entry:
    /* In long mode, ds/es/fs/gs/ss are effectively ignored for data access
     * but segment limit checks still apply in some corner cases — zero them. */
    xor     ax, ax
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    mov     ss, ax

    /* Re-set the stack pointer in 64-bit. */
    mov     rsp, offset stack_top
    xor     rbp, rbp            /* end the call-chain for debuggers */

    /* Pass Multiboot2 magic in rdi and info-pointer in rsi to kernel_main.
     * They were stashed in edi/esi during 32-bit entry and are zero-extended
     * for free when we read them as 64-bit registers. */
    mov     edi, edi
    mov     esi, esi

    call    kernel_main

    /* kernel_main should never return. If it does, halt deterministically. */
hang:
    cli
    hlt
    jmp     hang

.size long_mode_entry, . - long_mode_entry


/* ---------------------------------------------------------------------------
 * Minimal 64-bit GDT: null, 64-bit code, 64-bit data. The temporary IDT is
 * not installed here — the kernel will set up its real IDT in kernel_main.
 * ------------------------------------------------------------------------- */
.section .rodata
.align 16
gdt64:
    .quad   0                               /* null descriptor       */
    .quad   0x00AF9A000000FFFF              /* 0x08 = 64-bit code    */
    .quad   0x00AF92000000FFFF              /* 0x10 = 64-bit data    */
gdt64_end:

gdt64_descriptor:
    .word   gdt64_end - gdt64 - 1
    .quad   gdt64

/* Mark the stack non-executable so the linker doesn't emit a PT_GNU_STACK
 * entry with execute permission (lld warns otherwise). */
.section .note.GNU-stack, "", @progbits
