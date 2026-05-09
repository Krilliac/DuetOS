/*
 * DuetOS — Win32 thread entry thunk.
 *
 *   void Win32ThreadEntryThunk(LPTHREAD_START_ROUTINE start, LPVOID arg);
 *
 * Bridges between the kernel's iretq-to-user thread launch path
 * (which leaves arguments in SysV positions: RDI, RSI) and the
 * Microsoft x64 ABI a user-supplied ThreadProc expects (first arg
 * in RCX, 32-byte shadow space below RSP, 16-byte alignment of
 * RSP at the moment of `call`).
 *
 * The PE entry point itself (`mainCRTStartup` / `WinMainCRTStartup`)
 * takes no register args, so kernel/arch/x86_64/usermode.S can zero
 * every GPR before iretq and the entry runs correctly. Thread
 * start routines are different — Microsoft's contract requires
 * `start(arg)` to be called with `arg` in RCX, the call to be a
 * `call` (not `jmp`) so the return address is on the stack at
 * function entry, and 32 bytes of shadow space.
 *
 * Architecturally this thunk runs in user mode. v0 plants it in a
 * shared kernel-mapped read-execute region whose virtual address is
 * exposed to every Win32 process at thread create — analogous to
 * Linux's vDSO. A future slice that loads ntdll's own thread
 * trampoline can replace it without changing the kernel's CreateThread
 * code path.
 *
 * On thread exit the thunk issues SYS_THREAD_EXIT directly via int
 * 0x80, threading the ThreadProc's return value (EAX) into the exit
 * code. This avoids a dependency on ntdll's `ExitThread` symbol
 * being resolved before the thunk can be entered.
 *
 * Calling convention for the thunk itself: SysV (RDI = start,
 * RSI = arg) — the natural register positions the kernel iretq
 * stub leaves on the very first user-mode instruction.
 */

.intel_syntax noprefix

.section .text
.align 16
.global Win32ThreadEntryThunk
.type Win32ThreadEntryThunk, @function
Win32ThreadEntryThunk:
    endbr64

    /* RSP is 16-byte aligned at iretq-to-user. The MS-ABI wants
     * RSP+8 mod 16 == 0 at the function-entry boundary inside
     * `start`. The 0x28 here = 0x20 (shadow space) + 0x08 (align
     * bias). The `call` consumes the 0x08 by pushing the return
     * RIP, leaving the callee with [RSP..RSP+0x20) shadow + the
     * pushed return RIP at [RSP+0x20], which is the layout MS
     * code generators emit prologues against. */
    sub     rsp, 0x28
    mov     rcx, rsi              /* MS-ABI arg0 = arg */
    call    rdi                   /* start(arg) */
    add     rsp, 0x28

    /* SYS_THREAD_EXIT via int 0x80. exit_code = ThreadProc's EAX
     * return. The DuetOS native syscall number for thread exit is
     * carried at runtime from a kernel-supplied trampoline-data
     * table mapped alongside this thunk; v0 uses SYS_EXIT (0) as
     * the placeholder so a stand-alone thunk run is observably
     * "exited" rather than wandering off the end. */
    mov     edi, eax              /* exit code */
    xor     eax, eax              /* SYS_EXIT */
    int     0x80
    /* SYS_EXIT does not return; trap if it ever does. */
    ud2

    .size Win32ThreadEntryThunk, . - Win32ThreadEntryThunk

.section .note.GNU-stack, "", @progbits
