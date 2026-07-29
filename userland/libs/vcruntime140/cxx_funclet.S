/*
 * userland/libs/vcruntime140/cxx_funclet.S
 *
 * Invokes an MSVC catch / destructor funclet on behalf of
 * __CxxFrameHandler3.
 *
 * Two things make this a hand-written, unwind-described function
 * rather than inline C:
 *
 * 1. The MSVC funclet ABI.  x64 funclets take the establisher frame
 *    in rdx (parameter 2), BUT also expect it spilled to the r8 home
 *    slot — `[rsp+0x10]` from the funclet's own view — because
 *    MSVC-generated catch funclets reload it from there rather than
 *    trusting rdx across nested calls inside the funclet body.
 *    cxxeh_pe's catch funclets literally open with
 *    `mov rdx, [rsp+0x10]`; without the spill they read a previous
 *    caller's r8 and address locals through a garbage rbp.
 *
 * 2. A catch body may rethrow.  `throw;` raises a NEW exception from
 *    inside the funclet, and the unwinder then has to walk back out
 *    THROUGH this frame to reach the handler that will catch it.  A
 *    frame with no .pdata is treated as a leaf (RIP = [RSP],
 *    RSP += 8), which is wrong for anything with a prologue — the
 *    walk desynchronizes and resumes at garbage.  So the frame is
 *    described: rbp is established as the frame register, which lets
 *    the unwinder recover RSP even though the body realigns the
 *    stack after the prologue.
 */

    .text

    .globl  cxx_call_funclet
    .def    cxx_call_funclet; .scl 2; .type 32; .endef
    .seh_proc cxx_call_funclet
cxx_call_funclet:
    pushq   %rbp
    .seh_pushreg %rbp
    movq    %rsp, %rbp
    .seh_setframe %rbp, 0
    .seh_endprologue

    /* rcx = handler, rdx = establisher frame on entry. */
    subq    $0x20, %rsp
    andq    $-16, %rsp
    movq    %rdx, %r8           /* r8 = frame (establisher) */
    movq    %rcx, %rax          /* rax = handler */
    xorl    %ecx, %ecx
    movq    %r8, %rdx           /* rdx = frame (ABI arg 2) */
    /* The CALL below pushes 8 bytes (return address), so the
     * funclet's `[rsp+0x10]` from its view is `[rsp+0x08]` from ours
     * pre-call. Store the establisher there. */
    movq    %r8, 0x08(%rsp)
    call    *%rax

    movq    %rbp, %rsp
    popq    %rbp
    retq
    .seh_endproc
