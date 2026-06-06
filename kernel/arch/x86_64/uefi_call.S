/*
 * DuetOS — hand-written thunk to call a UEFI Runtime Service.
 *
 * Calling firmware code requires an indirect call to a target OUTSIDE
 * kernel text (the firmware lives in the low identity map). The kernel's
 * compiler-emitted indirect calls all route through the validating
 * retpoline thunk (retpoline_thunks.S), which panics on a target outside
 * [_text_start,_text_end) — exactly what a firmware address is. This
 * thunk issues a RAW `call *rax`, which the compiler does not rewrite, so
 * it bypasses that guard for this one deliberately-external call.
 *
 * It also bridges the calling convention: the kernel is System V, the
 * firmware is Microsoft x64. GetVariable takes 5 args, so we shuffle the
 * SysV argument registers into the MS x64 ones and place the 5th arg on
 * the stack above the mandatory 32-byte shadow space.
 *
 *   System V in:  rdi=fn  rsi=name  rdx=guid  rcx=attrs  r8=data_size  r9=data
 *   MS x64 wants: rcx=name rdx=guid r8=attrs r9=data_size [rsp+0x20]=data
 *   returns: rax = EFI_STATUS
 *
 * extern "C" u64 EfiCallGetVariable(void* fn, const u16* name,
 *     const void* guid, u32* attrs, u64* data_size, void* data);
 *
 * The caller masks interrupts around this (firmware runs in physical mode
 * and does not expect kernel-IRQ re-entry).
 */

    .text
    .globl  EfiCallGetVariable
    .type   EfiCallGetVariable, @function
EfiCallGetVariable:
    push    %rbp
    mov     %rsp, %rbp

    mov     %rdi, %rax          /* rax = fn pointer (call target)        */
    mov     %rcx, %r10          /* r10 = attrs (SysV rcx, before we stomp rcx) */
    mov     %r9,  %r11          /* r11 = data  (SysV r9, before we stomp r9)   */
    mov     %rsi, %rcx          /* MS arg1: rcx = name                    */
    /* rdx already = guid (SysV rdx == MS rdx)                            */
    mov     %r8,  %r9           /* MS arg4: r9 = data_size (SysV r8)      */
    mov     %r10, %r8           /* MS arg3: r8 = attrs                    */

    sub     $0x30, %rsp         /* 0x20 shadow + 0x08 arg5 + 0x08 pad (16-aligned) */
    mov     %r11, 0x20(%rsp)    /* MS arg5 (data) above the shadow space  */
    call    *%rax               /* raw indirect call — bypasses retpoline guard */
    add     $0x30, %rsp

    pop     %rbp
    ret
    .size   EfiCallGetVariable, . - EfiCallGetVariable

/* No executable stack. */
    .section .note.GNU-stack, "", @progbits
