/*
 * userland/libs/ntdll/ki_user_dispatchers.S
 *
 * ntdll.dll's Ki* user-mode dispatcher trampolines — peers of
 * KiUserExceptionDispatcher (which lives in seh_trampolines.S).
 *
 *   - KiUserApcDispatcher: kernel resumes a thread here after
 *     queueing a user-mode APC. The kernel-side push-delivery
 *     path (rewriting the trap frame on return-to-user so RIP =
 *     this entry) is GAP today — Process::apc_slots[] uses a
 *     poll-based drain via SYS_DRAIN_USER_APC instead. This
 *     trampoline lays down the ABI surface so a future kernel
 *     slice can route APC delivery through it without touching
 *     userland.
 *
 *   - KiUserCallbackDispatcher: kernel resumes a thread here for
 *     a kernel→user callback (real Windows uses this for user32's
 *     WndProc invocations from win32k.sys). DuetOS has no
 *     win32k-equivalent yet, so this is a hard-stop STUB —
 *     terminate the process loudly via NtTerminateProcess if
 *     anything actually lands here. // STUB: kernel→user
 *     callback delivery — needs a win32k-style kernel-side
 *     graphics subsystem that calls into user32 from ring 0.
 *
 * Both trampolines must be naked (the prologue would perturb
 * the carefully-arranged frame the kernel landed us on) and both
 * must be reachable by name from the kernel-side resume path —
 * Process::ki_user_apc_dispatcher_va etc. record the absolute VA
 * after image load, so the kernel can stamp the trap frame's
 * RIP without per-process lookup.
 *
 * ABI (Microsoft x64, on entry from kernel resume):
 *
 *   KiUserApcDispatcher:
 *     [rsp +  0] ApcRoutine          (PKNORMAL_ROUTINE)
 *     [rsp +  8] ApcArg1             (PVOID)
 *     [rsp + 16] ApcArg2             (PVOID)
 *     [rsp + 24] ApcArg3             (PVOID)
 *     [rsp + 32] CONTEXT*            (resume target)
 *
 *   KiUserCallbackDispatcher:
 *     rsp pre-aligned post-CALL ((rsp & 0xF) == 8); args via
 *     a per-callback-index table that DuetOS doesn't ship.
 *
 * The KiUserApcDispatcher convention matches Windows: NTAPI's
 * PKNORMAL_ROUTINE takes (PVOID arg1, PVOID arg2, PVOID arg3)
 * so we load rcx/rdx/r8 before the call, reserve 32 bytes of
 * shadow space, and call. After it returns we pass the CONTEXT*
 * to NtContinue to resume the interrupted code.
 */

    .text

/* -------------------------------------------------------------------------
 * KiUserApcDispatcher
 *
 * On entry, RSP points at the 5-element block laid out above.
 * RFLAGS already in a sensible state (kernel set it via iretq's
 * synthetic frame). No CONTEXT register-restore is done here —
 * the routine runs on the user-mode stack as-is; the CONTEXT
 * snapshot is what we resume from at the end.
 *
 * The MS x64 ABI requires a 16-byte-aligned RSP just before any
 * call — but RSP already has 8 bytes of CONTEXT* at the top,
 * not a return address, so the alignment is (RSP & 0xF) == 0
 * here (not the post-CALL 8). We `sub $0x28, %rsp` (32 bytes
 * shadow + 8 to flip alignment to the post-CALL shape) before
 * the routine call.
 * ------------------------------------------------------------------------- */
    .globl  KiUserApcDispatcher
    .def    KiUserApcDispatcher; .scl 2; .type 32; .endef
KiUserApcDispatcher:
    movq    (%rsp),    %rax             /* rax = ApcRoutine */
    movq    8(%rsp),   %rcx             /* rcx = ApcArg1 */
    movq    16(%rsp),  %rdx             /* rdx = ApcArg2 */
    movq    24(%rsp),  %r8              /* r8  = ApcArg3 */
    movq    32(%rsp),  %rbx             /* rbx = CONTEXT* (preserved across the call) */
    subq    $0x28, %rsp                 /* 0x20 shadow + 8 for 16-align */
    callq   *%rax                       /* ApcRoutine(arg1, arg2, arg3) */
    addq    $0x28, %rsp                 /* pop shadow */
    /* Resume via NtContinue. Real Windows checks bTestAlert and
     * may dispatch another queued APC before resuming; v0
     * resumes directly. NtContinue(rcx = CONTEXT*, rdx =
     * bTestAlert=FALSE) never returns. */
    movq    %rbx, %rcx                  /* rcx = CONTEXT* */
    xorl    %edx, %edx                  /* rdx = FALSE (no alert test) */
    callq   NtContinue                  /* noreturn */
    ud2                                 /* unreachable */

/* -------------------------------------------------------------------------
 * KiUserCallbackDispatcher
 *
 * STUB: DuetOS has no kernel-side graphics subsystem that calls
 * back into user32 from ring 0 today, so a thread that lands
 * here is a kernel bug — terminate loudly rather than silently
 * wander. NtTerminateProcess(NULL, STATUS_INVALID_PROCEDURE_CALL).
 * ------------------------------------------------------------------------- */
    .globl  KiUserCallbackDispatcher
    .def    KiUserCallbackDispatcher; .scl 2; .type 32; .endef
KiUserCallbackDispatcher:
    /* Args for NtTerminateProcess(HANDLE, NTSTATUS).
     * rcx = NULL (self), rdx = STATUS_INVALID_PROCEDURE_CALL
     * = 0xC0000031. */
    subq    $0x28, %rsp                 /* shadow + align */
    xorl    %ecx, %ecx
    movl    $0xC0000031, %edx
    callq   NtTerminateProcess          /* noreturn on success */
    ud2                                 /* unreachable */
