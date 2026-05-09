/*
 * DuetOS — userland string primitives.
 *
 *   void* memcpy (void* dst, const void* src, size_t n);
 *   void* memmove(void* dst, const void* src, size_t n);
 *   void* memset (void* dst, int c, size_t n);
 *   size_t strlen(const char* s);
 *   int   strcmp (const char* a, const char* b);
 *
 * SysV AMD64 calling convention throughout — these match what
 * userland code expects from a hosted libc (`memcpy(dst, src, n)`
 * with rdi/rsi/rdx). Replaces the byte-loop C helpers that lived
 * in syscall.c — `rep movsb` / `rep stosb` is a single-microcoded
 * instruction on Ivy Bridge and later silicon (the ERMS feature)
 * and outperforms a C byte loop by ~4×.
 *
 * memmove handles overlap by direction: forward copy when
 * dst < src, backward copy otherwise. memcpy assumes the regions
 * don't overlap (per the ISO C contract).
 *
 * No floating-point or vector instructions — these run in any
 * task, including ones that haven't initialised their FPU state
 * (DuetOS userland does not yet enable SSE in user mode by
 * default; see kernel/arch/x86_64/fpu.cpp).
 */

    .intel_syntax noprefix
    .text

/* ------------------------------------------------------------------------- */
    .align 16
    .globl memcpy
    .type memcpy, @function
memcpy:
    endbr64
    /* rax = dst (return value); rdi/rsi/rcx are the rep operands. */
    mov     rax, rdi
    mov     rcx, rdx
    rep movsb
    ret
    .size memcpy, . - memcpy


/* -------------------------------------------------------------------------
 * memmove(dst, src, n)
 *
 * If dst and src don't overlap or dst < src, forward `rep movsb`
 * is correct. If dst > src AND the regions overlap, we copy
 * backwards: set DF, point rdi/rsi at the end-1 of each region,
 * `rep movsb` runs decrementing.
 * ------------------------------------------------------------------------- */
    .align 16
    .globl memmove
    .type memmove, @function
memmove:
    endbr64
    mov     rax, rdi              /* return value */
    cmp     rdi, rsi
    je      .Lmemmove_done        /* same buffer — nothing to do */
    jb      .Lmemmove_forward     /* dst < src: forward copy is safe */

    /* dst > src: backward copy. */
    lea     rdi, [rdi + rdx - 1]
    lea     rsi, [rsi + rdx - 1]
    mov     rcx, rdx
    std
    rep movsb
    cld                            /* SysV ABI: DF must be 0 on return */
    ret

.Lmemmove_forward:
    mov     rcx, rdx
    rep movsb
.Lmemmove_done:
    ret
    .size memmove, . - memmove


/* ------------------------------------------------------------------------- */
    .align 16
    .globl memset
    .type memset, @function
memset:
    endbr64
    mov     rax, rdi              /* return value */
    /* sil holds the low byte of `c`. mov al, sil + rep stosb: */
    mov     rcx, rdx
    push    rdi                   /* preserve dst — rdi is the rep target */
    movzx   eax, sil
    mov     rdi, [rsp]
    rep stosb
    pop     rax                   /* restore dst as return value */
    ret
    .size memset, . - memset


/* -------------------------------------------------------------------------
 * strlen(s)
 *
 * Scan-byte path. `repne scasb` decrements rcx for every byte not
 * matching al; we set rcx to a huge value, scan to NUL, and the
 * length is (start - end - 1).
 * ------------------------------------------------------------------------- */
    .align 16
    .globl strlen
    .type strlen, @function
strlen:
    endbr64
    mov     rax, rdi              /* save start pointer */
    xor     ecx, ecx
    not     rcx                   /* rcx = -1 = SIZE_MAX */
    xor     al, al                /* scan target = NUL */
    repne scasb
    /* rdi now points one past the NUL. Length = (rdi - 1) - start. */
    sub     rdi, rax
    lea     rax, [rdi - 1]
    ret
    .size strlen, . - strlen


/* -------------------------------------------------------------------------
 * strcmp(a, b)
 *
 * Compare byte-by-byte until either a mismatch or a NUL on both
 * sides. Returns the same sign as the first differing byte's
 * (unsigned) difference.
 * ------------------------------------------------------------------------- */
    .align 16
    .globl strcmp
    .type strcmp, @function
strcmp:
    endbr64
.Lstrcmp_loop:
    mov     al, [rdi]
    mov     dl, [rsi]
    cmp     al, dl
    jne     .Lstrcmp_diff
    test    al, al
    jz      .Lstrcmp_eq
    inc     rdi
    inc     rsi
    jmp     .Lstrcmp_loop

.Lstrcmp_diff:
    movzx   eax, al
    movzx   edx, dl
    sub     eax, edx
    ret

.Lstrcmp_eq:
    xor     eax, eax
    ret
    .size strcmp, . - strcmp


    .section .note.GNU-stack, "", @progbits
