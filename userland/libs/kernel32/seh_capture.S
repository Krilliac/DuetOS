/*
 * userland/libs/kernel32/seh_capture.S
 *
 * kernel32.dll's RtlCaptureContext export. Real Windows
 * kernel32.dll carries its own copy of RtlCaptureContext alongside
 * ntdll.dll's — whichever the importer resolves against, the body
 * must be present and behave identically. This file is the
 * kernel32-side body; the canonical implementation lives in
 * ../ntdll/seh_trampolines.S (with full ABI commentary).
 *
 * If you change one, audit both — they MUST stay byte-identical.
 * The disasm cross-check (objdump -d on each obj) catches drift.
 *
 * ABI (Microsoft x64, naked): rcx = CONTEXT*. Snapshots caller's
 * register state into the record. Rip = our return address, Rsp =
 * caller's RSP after we return. Restores rax before ret so the
 * caller's rax is preserved.
 */

    .text
    .globl  RtlCaptureContext
    .def    RtlCaptureContext; .scl 2; .type 32; .endef
RtlCaptureContext:
    movq    %rax, 0x78(%rcx)
    movq    %rdx, 0x88(%rcx)
    movq    %rbx, 0x90(%rcx)
    movq    %rbp, 0xA0(%rcx)
    movq    %rsi, 0xA8(%rcx)
    movq    %rdi, 0xB0(%rcx)
    movq    %r8,  0xB8(%rcx)
    movq    %r9,  0xC0(%rcx)
    movq    %r10, 0xC8(%rcx)
    movq    %r11, 0xD0(%rcx)
    movq    %r12, 0xD8(%rcx)
    movq    %r13, 0xE0(%rcx)
    movq    %r14, 0xE8(%rcx)
    movq    %r15, 0xF0(%rcx)
    movq    %rcx, 0x80(%rcx)            /* captured Rcx = the record ptr arg */
    leaq    8(%rsp), %rax
    movq    %rax, 0x98(%rcx)            /* Rsp the caller sees after we return */
    movq    (%rsp), %rax
    movq    %rax, 0xF8(%rcx)            /* Rip = our return address */
    pushfq
    popq    %rax
    movl    %eax, 0x44(%rcx)            /* EFlags */
    movl    $0x0010000F, 0x30(%rcx)     /* ContextFlags = INTEGER|CONTROL|SEGMENTS|DEBUG_REGS */
    movq    0x78(%rcx), %rax            /* restore rax so caller sees its original value */
    retq
