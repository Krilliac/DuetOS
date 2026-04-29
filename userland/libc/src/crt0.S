/*
 * DuetOS — userland `_start`, v0.
 *
 * Sets up an empty stack frame, calls `main()`, then issues
 * SYS_EXIT with main's return value. No argc/argv/envp — the
 * kernel's process spawner doesn't push them today; main()'s
 * signature is `int main(void)`.
 *
 * `int 0x80` is the canonical DuetOS userland syscall ABI:
 *   eax = syscall number, rdi/rsi/rdx/r10/r8/r9 = args.
 */

    .text
    .globl _start
    .type _start, @function
_start:
    xorq    %rbp, %rbp           /* clear frame pointer */
    andq    $-16, %rsp           /* align stack to 16 bytes */
    callq   main                 /* main returns int in eax */

    /* Fall through into exit(rax). */
    movl    %eax, %edi           /* exit code */
    movl    $0, %eax             /* SYS_EXIT */
    int     $0x80
    /* SYS_EXIT does not return; trap if it ever does. */
    ud2

    .size _start, .-_start

    .section .note.GNU-stack,"",@progbits
