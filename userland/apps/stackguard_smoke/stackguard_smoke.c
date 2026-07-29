/*
 * stackguard_smoke — prove the guard region below the demand-grown
 * ring-3 stack is still fatal.
 *
 * The companion fixture (stackgrow_smoke) proves the stack GROWS.
 * This one proves growth did not remove the safety net it replaced:
 * a runaway recursion must still die, and die nameably, rather than
 * quietly consuming address space one committed page at a time.
 *
 * It recurses without a base case. Growth services every step until
 * the committed edge reaches reserve_lo; the next step lands in the
 * guard region, which the classifier refuses to grow into
 * (kernel/proc/user_stack.h). The kernel logs
 *
 *   [W] mm/ustack : *** RING-3 STACK OVERFLOW ***  verdict="Guard"
 *
 * fires the mm.user_stack_guard_hit probe, and delivers
 * STATUS_STACK_OVERFLOW (0xC00000FD) rather than a generic access
 * violation — so the boot log distinguishes "the stack ran out" from
 * "a pointer went wild". With no __except installed, ntdll's
 * unhandled-exception path ends the process with that code as its
 * exit status.
 *
 * THIS FIXTURE IS EXPECTED TO DIE. It is a battery row with
 * expects_verdict = false (same shape as ring3-pe32-miss, which also
 * exits through a non-standard path by design) — the depth line it
 * prints before dying is the observable evidence, and the exit code
 * 0xC00000FD is the assertion.
 */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutDec(unsigned long long v)
{
    char buf[24];
    int i = 24;
    buf[--i] = '\0';
    if (v == 0)
        buf[--i] = '0';
    while (v > 0 && i > 0)
    {
        buf[--i] = (char)('0' + (v % 10));
        v /= 10;
    }
    Out(&buf[i]);
}

static volatile unsigned long g_depth;

/* ~2 KiB per frame: well under a page, so every step walks the stack
 * down sequentially (the only pattern growth accepts) while keeping
 * the total number of frames small enough to reach the guard quickly.
 * noinline + the volatile pad + consuming the result stop the
 * compiler turning this into a loop. */
__declspec(noinline) static unsigned long Runaway(unsigned long level)
{
    volatile char pad[2048];
    pad[0] = (char)level;
    pad[sizeof(pad) - 1] = (char)level;
    g_depth = level;
    return Runaway(level + 1) + (unsigned long)pad[0] - (unsigned long)pad[0];
}

void __cdecl mainCRTStartup(void)
{
    Out("[stackguard] starting — recursing until the guard region stops us\r\n");

    g_depth = 0;
    (void)Runaway(1);

    /* Only reachable if the guard was NOT fatal, i.e. the recursion
     * was allowed to run off the bottom of its reservation. */
    Out("[stackguard] depth = ");
    OutDec(g_depth);
    Out("\r\n[stackguard] FAIL — recursion returned, guard region was not fatal\r\n");
    ExitProcess(1);
}
