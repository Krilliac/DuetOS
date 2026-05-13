/*
 * DuetOS — ring-0 → ring-3 transition.
 *
 *   [[noreturn]] void EnterUserMode(u64 user_rip, u64 user_rsp);
 *
 * SysV AMD64 calling convention: rdi = user_rip, rsi = user_rsp.
 *
 * Contract (see usermode.h):
 *   - Caller already mapped `user_rip`'s code page with kPageUser + exec,
 *     and `user_rsp`'s stack page with kPageUser + write + NX.
 *   - Caller already called arch::TssSetRsp0(kernel_stack_top) so the next
 *     user→kernel transition lands on a valid kernel stack.
 *
 * The iretq frame pushed here is the canonical Intel SDM Vol. 3A §6.14.1
 * layout (SS / RSP / RFLAGS / CS / RIP, bottom to top in memory, highest
 * slot popped first). The RFLAGS value (0x202) sets IF=1 + the always-
 * set reserved bit 1, so the user task is immediately interruptible —
 * without that, the next timer tick could only land after the user code
 * itself sti'd, and ring-3 code has no privilege to sti.
 *
 * Segment-register hygiene: DS/ES/FS/GS are loaded with kUserDataSelector
 * BEFORE the iretq. iretq itself loads SS/CS from the frame; the other
 * four need to match the new privilege level or we'd enter ring 3 with
 * stale kernel-DS (which still works for data access but leaks kernel
 * selector state into ring 3 — considered a #GP accelerant on some
 * CPUs and generally bad posture).
 */

.intel_syntax noprefix

.section .text
.align 16
.global EnterUserMode
.type EnterUserMode, @function
EnterUserMode:
    /* Direct-call target from Ring3UserEntry, but emit endbr for
     * hygiene — cheap NOP on pre-CET CPUs. */
    endbr64
    /* Tail into the 3-arg form with user_gs_base=0; zero GSBASE is
     * what non-Win32 ring-3 tasks already ran with before the PE
     * TEB slice landed. */
    xor     edx, edx
    jmp     EnterUserModeWithGs
.size EnterUserMode, . - EnterUserMode

.global EnterUserModeWithGs
.type EnterUserModeWithGs, @function
EnterUserModeWithGs:
    /*   rdi = user_rip
     *   rsi = user_rsp
     *   rdx = user_gs_base (0 for non-PE tasks)
     */
    endbr64
    /* Disable interrupts from the moment we start setting up segments.
     * A timer tick between "mov ds, ax" and "iretq" would deliver onto
     * the current kernel stack with the data segments half-swapped;
     * iretq on the way back then restores them cleanly. The iretq
     * frame's RFLAGS has IF=1, so interrupts re-enable atomically on
     * the ring-3 transition. */
    cli

    /* swapgs NOW, before we touch the GS selector. Rationale: in long
     * mode, `mov gs, <non-null sel>` reloads the hidden GSBASE from
     * the selected descriptor's base field. The user-data descriptor's
     * base is 0, so the mov below would ZERO GSBASE — and on the next
     * kernel entry (timer / syscall), any gs-relative read of per-CPU
     * state would fault against address 0. Instead, stash the kernel's
     * GSBASE into the KERNEL_GS_BASE MSR now; the isr_common entry
     * path's matching swapgs restores it on every trap from user. The
     * `mov gs, ax` that follows is free to zero GSBASE — that's the
     * value user mode sees, and KERNEL_GS_BASE preserves the kernel's
     * pcpu pointer across the round trip. */
    swapgs

    /* Load user data selector into DS/ES/FS/GS. The selector includes
     * RPL=3 (0x33); the CPU checks DPL == RPL for data segments loaded
     * outside of an iretq, which is why we don't just push zero here. */
    mov     ax, 0x33                /* kUserDataSelector */
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax
    /* SS is loaded by iretq from the frame — do NOT mov it here. */

    /* Load the requested user GSBASE. `mov gs, ax` above zeroed
     * GSBASE via the Intel-variant descriptor load; MSR_GS_BASE
     * (0xC0000101) is the only way to set it to a non-descriptor
     * value in long mode without requiring CR4.FSGSBASE. Skip the
     * wrmsr if caller passed 0 — the `mov gs, ax` already set it
     * to zero and wrmsr would just repeat that. Clobbers rax, rcx,
     * rdx (all caller-saved; rdi, rsi preserved so we can push
     * them below). */
    test    rdx, rdx
    jz      1f
    mov     rax, rdx                /* low 32 */
    shr     rdx, 32                 /* high 32 */
    mov     ecx, 0xC0000101         /* MSR_GS_BASE */
    wrmsr
1:

    /* Build the iretq frame. In memory, lowest to highest:
     *   [rsp+0]  : RIP    <- user entry point
     *   [rsp+8]  : CS     <- kUserCodeSelector (0x2B)
     *   [rsp+16] : RFLAGS <- 0x202 (IF=1 + reserved bit 1)
     *   [rsp+24] : RSP    <- user stack pointer
     *   [rsp+32] : SS     <- kUserDataSelector (0x33)
     *
     * push order is reverse (SS first = highest, RIP last = lowest). */
    push    0x33                    /* SS = kUserDataSelector */
    push    rsi                     /* user RSP */
    push    0x202                   /* RFLAGS: IF=1, reserved=1 */
    push    0x2B                    /* CS = kUserCodeSelector */
    push    rdi                     /* user RIP */

    /* Zero every GPR we can — hygiene. A freshly-started Windows
     * PE entry point expects `void(void)` calling convention:
     * the CRT doesn't meaningfully read any arg register, but real
     * Win32 CRT code (and Linux _start) both contain code paths
     * that dereference a GPR assuming it's 0 or a valid handle.
     * Leaking kernel register state into ring 3 is both a spec
     * violation and a predictable faults vector. Scrub rax, rbx,
     * rcx, rdx, rbp, rsi, rdi, r8..r15 before iretq. rsp is set
     * by the iretq frame itself. */
    xor     eax, eax
    xor     ebx, ebx
    xor     ecx, ecx
    xor     edx, edx
    xor     ebp, ebp
    xor     esi, esi
    xor     edi, edi
    xor     r8d,  r8d
    xor     r9d,  r9d
    xor     r10d, r10d
    xor     r11d, r11d
    xor     r12d, r12d
    xor     r13d, r13d
    xor     r14d, r14d
    xor     r15d, r15d

    iretq

    /* Unreachable — iretq either enters user mode or #GPs. The ud2
     * is a belt-and-braces halt so an impossible fallthrough doesn't
     * silently execute whatever follows in the .text section. */
    ud2
.size EnterUserModeWithGs, . - EnterUserModeWithGs


/* EnterUserModeThread: 4-arg sibling of EnterUserModeWithGs. Used
 * by SYS_THREAD_CREATE to start a ring-3 Task with RCX = thread
 * param (Win32 x64 calling convention's first arg). All other
 * segment + GSBASE + RFLAGS setup is identical. The only
 * difference vs the 3-arg form is the final register-scrub step:
 * we load RCX from the 4th arg instead of zeroing it.
 *
 *   rdi = user_rip
 *   rsi = user_rsp
 *   rdx = user_gs_base
 *   rcx = user_rcx (stashed into r15 immediately; restored to
 *         rcx just before iretq)
 */
.global EnterUserModeThread
.type EnterUserModeThread, @function
EnterUserModeThread:
    endbr64
    mov     r15, rcx                /* stash user_rcx; r15 is scrubbed below anyway */

    cli
    swapgs

    mov     ax, 0x33
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    test    rdx, rdx
    jz      2f
    mov     rax, rdx
    shr     rdx, 32
    mov     ecx, 0xC0000101         /* MSR_GS_BASE */
    wrmsr
2:

    push    0x33
    push    rsi
    push    0x202
    push    0x2B
    push    rdi

    /* Zero every GPR except rcx — load rcx from the stashed r15.
     * This is the one difference from EnterUserModeWithGs. */
    xor     eax, eax
    xor     ebx, ebx
    mov     rcx, r15
    xor     edx, edx
    xor     ebp, ebp
    xor     esi, esi
    xor     edi, edi
    xor     r8d,  r8d
    xor     r9d,  r9d
    xor     r10d, r10d
    xor     r11d, r11d
    xor     r12d, r12d
    xor     r13d, r13d
    xor     r14d, r14d
    xor     r15d, r15d

    iretq

    ud2
.size EnterUserModeThread, . - EnterUserModeThread

/* EnterUserMode32: enter ring 3 in 32-bit compatibility mode for
 * PE32 (i386) workloads. Builds an iretq frame with the 32-bit
 * user code (0x3B) + data (0x43) selectors from gdt.h. The slots
 * pushed are still 8 bytes each — that's the iretq layout
 * regardless of the destination bitness; the CPU sign/zero-extends
 * as needed when it pops them into 32-bit registers.
 *
 *   rdi = user_eip   (32-bit entry point; high bits ignored)
 *   rsi = user_esp   (32-bit stack pointer; high bits ignored)
 *
 * Contract is otherwise identical to EnterUserMode:
 *   - caller mapped the code/stack pages with kPageUser
 *   - caller called TssSetRsp0 with the kernel-side stack top
 *
 * No swapgs / wrmsr GSBASE setup here — 32-bit Windows ABIs don't
 * use gs-relative TEB reads the way x64 PEs do (gs:[0x18]). PE32
 * code uses fs-relative reads on the TEB instead (`fs:[18h]`), and
 * those go through the standard segment-descriptor base, not the
 * MSR. The 32-bit DLL preload slice will set FSBASE via wrmsr the
 * same way EnterUserModeWithGs does for the 64-bit path.
 *
 * Layer 2 of 32-bit PE support — Layers 3+ (32-bit syscall ABI,
 * 32-bit DLL set, pointer marshalling) still required before this
 * is reachable from a real PE32 spawn path. Today's caller is the
 * pe32_smoke hand-built test PE.
 */
.global EnterUserMode32
.type EnterUserMode32, @function
EnterUserMode32:
    endbr64

    cli

    /* Load user data selector. Use the 32-bit user data segment
     * (0x43) for DS/ES/FS/GS so the segment-descriptor base + limit
     * cached by the load matches the 32-bit segment shape. SS is
     * set by iretq from the frame.
     *
     * No swapgs: 32-bit code can't use the MSR-based GSBASE anyway
     * (compat-mode `mov rax, gs:[...]` decodes as a 32-bit move),
     * and clearing the kernel's GSBASE here would mean we couldn't
     * find per-CPU state on the next kernel entry. The matching
     * isr_common swapgs on user→kernel transition does NOT fire for
     * compat-mode CS unless we add it — see the syscall ABI Layer 3
     * notes for the route. */
    mov     ax, 0x43                /* kUserData32Selector */
    mov     ds, ax
    mov     es, ax
    mov     fs, ax
    mov     gs, ax

    /* Build the iretq frame:
     *   [rsp+0]  : EIP    <- user entry point (low 32)
     *   [rsp+8]  : CS     <- kUserCode32Selector (0x3B)
     *   [rsp+16] : RFLAGS <- 0x202 (IF=1 + reserved)
     *   [rsp+24] : ESP    <- user stack (low 32)
     *   [rsp+32] : SS     <- kUserData32Selector (0x43)
     *
     * The push order is reverse — SS first (highest addr), RIP
     * last (lowest). */
    push    0x43                    /* SS = kUserData32Selector */
    push    rsi                     /* user ESP (low 32 used) */
    push    0x202                   /* RFLAGS */
    push    0x3B                    /* CS = kUserCode32Selector */
    push    rdi                     /* user EIP (low 32 used) */

    /* Zero all GPRs for clean ring-3 entry. */
    xor     eax, eax
    xor     ebx, ebx
    xor     ecx, ecx
    xor     edx, edx
    xor     ebp, ebp
    xor     esi, esi
    xor     edi, edi
    xor     r8d,  r8d
    xor     r9d,  r9d
    xor     r10d, r10d
    xor     r11d, r11d
    xor     r12d, r12d
    xor     r13d, r13d
    xor     r14d, r14d
    xor     r15d, r15d

    iretq

    ud2
.size EnterUserMode32, . - EnterUserMode32

/* NX stack — silence lld's PT_GNU_STACK warning. */
.section .note.GNU-stack, "", @progbits
