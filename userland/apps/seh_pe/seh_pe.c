/*
 * seh_pe — verifies the DuetOS SEH engine (T6-02).
 *
 * Slices 1-2 (still checked here as a regression): real
 * RtlCaptureContext, table-based RtlLookupFunctionEntry, and the
 * RtlVirtualUnwind frame walk.
 *
 * Slice 3 (the kernel fault -> user __except dispatch) is exercised
 * by taking REAL CPU faults inside __try blocks:
 *
 *   3a. A null write (*(volatile int*)0 = 1) #PFs. The kernel
 *       builds an EXCEPTION_RECORD/CONTEXT and resumes us at
 *       ntdll!KiUserExceptionDispatcher, which walks to our
 *       __except, whose filter (1 = EXCEPTION_EXECUTE_HANDLER)
 *       runs the handler block. We verify GetExceptionCode() ==
 *       STATUS_ACCESS_VIOLATION and that execution continues.
 *
 *   3b. An integer divide-by-zero (#DE) caught the same way, with
 *       GetExceptionCode() == STATUS_INTEGER_DIVIDE_BY_ZERO.
 *
 * Exit code 0 on full PASS, 1 on any FAIL.
 */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutHex(unsigned long long v)
{
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
        buf[2 + i] = "0123456789abcdef"[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = 0;
    Out(buf);
}

/* Force a non-trivial frame so this function gets its own
 * .pdata RUNTIME_FUNCTION (a leaf with no prologue might be
 * folded). The volatile array + barrier keep a real prologue. */
__attribute__((noinline)) static int capture_and_check(void)
{
    volatile char guard[64];
    for (int i = 0; i < 64; ++i)
        guard[i] = (char)i;

    CONTEXT ctx;
    RtlCaptureContext(&ctx);

    int fail = 0;
    if (ctx.Rip == 0 || ctx.Rsp == 0)
    {
        Out("[seh_pe] capture: FAIL (Rip/Rsp zero)\r\n");
        return 1;
    }
    Out("[seh_pe] capture Rip=");
    OutHex(ctx.Rip);
    Out(" Rsp=");
    OutHex(ctx.Rsp);
    Out("\r\n");

    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION rf = RtlLookupFunctionEntry(ctx.Rip, &image_base, NULL);
    if (rf == NULL)
    {
        Out("[seh_pe] lookup: FAIL (no RUNTIME_FUNCTION for Rip)\r\n");
        return 1;
    }
    if (image_base == 0 || ctx.Rip < image_base)
    {
        Out("[seh_pe] lookup: FAIL (bad image base)\r\n");
        return 1;
    }
    const DWORD off = (DWORD)(ctx.Rip - image_base);
    Out("[seh_pe] base=");
    OutHex(image_base);
    Out(" rva=");
    OutHex(off);
    Out(" [Begin=");
    OutHex(rf->BeginAddress);
    Out(" End=");
    OutHex(rf->EndAddress);
    Out(")\r\n");
    if (off >= rf->BeginAddress && off < rf->EndAddress)
    {
        Out("[seh_pe] lookup-covers-rip: PASS\r\n");
    }
    else
    {
        Out("[seh_pe] lookup-covers-rip: FAIL (Rip outside RUNTIME_FUNCTION)\r\n");
        fail = 1;
    }
    (void)guard;
    return fail;
}

/* Nested non-leaf frames so the unwinder has real RUNTIME_FUNCTIONs
 * to walk. Each does a little volatile work to keep a prologue. */
static DWORD64 g_base_for_check;

/* Walk this EXE's own call chain with RtlLookupFunctionEntry +
 * RtlVirtualUnwind, starting from a context captured *here* (so
 * the first Rip is in seh_pe, not kernel32 — cross-module
 * RtlCaptureStackBackTrace is a documented follow-on). Expect to
 * unwind bt_leaf -> bt_b -> bt_a -> mainCRTStartup, i.e. >=3
 * frames, each Rip staying inside the EXE image and strictly
 * moving. */
__attribute__((noinline)) static int bt_leaf(void)
{
    volatile int s = 0;
    for (int i = 0; i < 8; ++i)
        s += i;
    CONTEXT c;
    RtlCaptureContext(&c);
    int frames = 0;
    int sane = 1;
    for (int k = 0; k < 12; ++k)
    {
        DWORD64 ib = 0;
        PRUNTIME_FUNCTION fe = RtlLookupFunctionEntry(c.Rip, &ib, NULL);
        if (fe == NULL)
            break; /* left the EXE .pdata (CRT/loader frame) — stop */
        DWORD64 prev = c.Rip, est = 0;
        RtlVirtualUnwind(0, ib, c.Rip, fe, &c, NULL, &est, NULL);
        if (c.Rip == 0 || c.Rip == prev)
            break;
        if (c.Rip < g_base_for_check)
            break; /* unwound out of the image — fine, stop counting */
        ++frames;
    }
    Out("[seh_pe] virtual-unwind frames=");
    OutHex((unsigned long long)frames);
    Out("\r\n");
    if (frames < 3)
        sane = 0;
    Out(sane ? "[seh_pe] virtual-unwind-depth: PASS\r\n" : "[seh_pe] virtual-unwind-depth: FAIL\r\n");
    (void)s;
    return sane ? 0 : 1;
}
__attribute__((noinline)) static int bt_b(void)
{
    volatile int t = 1;
    int r = bt_leaf();
    return r + (t - 1);
}
__attribute__((noinline)) static int bt_a(void)
{
    volatile int u = 2;
    int r = bt_b();
    return r + (u - 2);
}

/* ---- Slice 3: real CPU faults delivered to a user handler.
 *
 * This mingw-w64 GCC build does not implement the MSVC __try /
 * __except keywords in C (only the degenerate __try1/__except1
 * macros), so the end-to-end kernel-fault → user-SEH path is
 * exercised via a Vectored Exception Handler instead. VEH proves
 * exactly the high-risk machinery this slice adds: the kernel
 * builds an EXCEPTION_RECORD + CONTEXT on the faulting user
 * stack, resumes the thread at ntdll!KiUserExceptionDispatcher,
 * which runs our handler; the handler edits the CONTEXT to make
 * the faulting instruction succeed and asks to continue;
 * RtlRestoreContext resumes the corrected context. The
 * frame-based __try/__except engine (__C_specific_handler /
 * RtlUnwindEx) ships and is exported for real MSVC-toolchain PEs
 * (Chrome's vcruntime) but cannot be smoke-tested under mingw —
 * see the T6-02 GAP note.
 *
 * CONTEXT offsets (Microsoft x64): Rcx=0x80, R11=0xD0. ---- */

extern void* RtlAddVectoredExceptionHandler(unsigned long First, void* Handler);
extern unsigned long RtlRemoveVectoredExceptionHandler(void* Handle);

#define EXC_AV 0xC0000005UL
#define EXC_DIV0 0xC0000094UL
#define VEH_CONTINUE_EXECUTION (-1)
#define VEH_CONTINUE_SEARCH (0)

static volatile int g_av_landing;
static volatile int g_veh_av_hits;
static volatile int g_veh_div_hits;
static volatile unsigned long g_veh_last_code;

/* PEXCEPTION_POINTERS = { PEXCEPTION_RECORD; PCONTEXT } */
static long __attribute__((ms_abi)) veh_fixup(void* ExceptionInfo)
{
    void** ep = (void**)ExceptionInfo;
    unsigned char* rec = (unsigned char*)ep[0];
    unsigned char* ctx = (unsigned char*)ep[1];
    unsigned long code = *(unsigned int*)(rec + 0x00);
    g_veh_last_code = code;
    if (code == EXC_AV)
    {
        /* Redirect the faulting `mov [r11], imm` at a valid int so
         * the retried instruction succeeds. */
        *(unsigned long long*)(ctx + 0xD0) = (unsigned long long)(void*)&g_av_landing;
        ++g_veh_av_hits;
        return VEH_CONTINUE_EXECUTION;
    }
    if (code == EXC_DIV0)
    {
        /* Make the divisor (rcx) 1 so the retried idiv succeeds. */
        *(unsigned long long*)(ctx + 0x80) = 1ULL;
        ++g_veh_div_hits;
        return VEH_CONTINUE_EXECUTION;
    }
    return VEH_CONTINUE_SEARCH;
}

__attribute__((noinline)) static int veh_null_write(void)
{
    void* bad = (void*)0;
    /* Write through r11 so the handler can repoint exactly that
     * register; barrier keeps the store from being elided. */
    __asm__ __volatile__("movq %0, %%r11\n\t"
                         "movl $0x1234, (%%r11)\n\t"
                         :
                         : "r"(bad)
                         : "r11", "memory");
    if (g_veh_av_hits >= 1 && g_veh_last_code == EXC_AV)
    {
        Out("[seh_pe] veh-access-violation: PASS\r\n");
        return 0;
    }
    Out("[seh_pe] veh-access-violation: FAIL\r\n");
    return 1;
}

__attribute__((noinline)) static int veh_div_zero(void)
{
    unsigned long long q = 0;
    __asm__ __volatile__("xorq %%rcx, %%rcx\n\t"
                         "movq $100, %%rax\n\t"
                         "cqo\n\t"
                         "idivq %%rcx\n\t" /* #DE: divide by zero */
                         "movq %%rax, %0\n\t"
                         : "=r"(q)
                         :
                         : "rax", "rcx", "rdx", "memory");
    if (g_veh_div_hits >= 1 && q == 100)
    {
        Out("[seh_pe] veh-divide-by-zero: PASS\r\n");
        return 0;
    }
    Out("[seh_pe] veh-divide-by-zero: FAIL\r\n");
    return 1;
}

/* Repeatable: a second, independent fault is delivered and
 * recovered after the first — proves delivery is not one-shot
 * and that RtlRestoreContext returns cleanly into normal flow. */
__attribute__((noinline)) static int veh_repeatable(void)
{
    int before = g_veh_av_hits;
    for (int i = 0; i < 3; ++i)
    {
        void* bad = (void*)0;
        __asm__ __volatile__("movq %0, %%r11\n\t"
                             "movl $7, (%%r11)\n\t"
                             :
                             : "r"(bad)
                             : "r11", "memory");
    }
    if (g_veh_av_hits - before == 3)
    {
        Out("[seh_pe] veh-repeatable: PASS\r\n");
        return 0;
    }
    Out("[seh_pe] veh-repeatable: FAIL\r\n");
    return 1;
}

void __cdecl mainCRTStartup(void)
{
    Out("[seh_pe] starting\r\n");
    int fail = capture_and_check();

    /* Establish the EXE base for the backtrace sanity bound. */
    {
        CONTEXT c;
        RtlCaptureContext(&c);
        DWORD64 ib = 0;
        (void)RtlLookupFunctionEntry(c.Rip, &ib, NULL);
        g_base_for_check = ib;
    }
    int bt = bt_a();
    Out(bt ? "[seh_pe] virtual-unwind-walk: FAIL\r\n" : "[seh_pe] virtual-unwind-walk: PASS\r\n");
    fail |= bt;

    /* Slice 3: real CPU faults delivered to a Vectored Exception
     * Handler via the kernel → KiUserExceptionDispatcher path. */
    {
        void* h = RtlAddVectoredExceptionHandler(1u, (void*)&veh_fixup);
        if (h == 0)
        {
            Out("[seh_pe] veh-register: FAIL\r\n");
            fail |= 1;
        }
        else
        {
            fail |= veh_null_write();
            fail |= veh_div_zero();
            fail |= veh_repeatable();
            RtlRemoveVectoredExceptionHandler(h);
        }
    }

    Out(fail ? "[seh_pe] RESULT FAIL\r\n" : "[seh_pe] RESULT PASS\r\n");
    Out("[seh_pe] done\r\n");
    ExitProcess(fail ? 1u : 0u);
}
