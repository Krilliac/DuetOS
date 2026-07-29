/*
 * stackgrow_smoke — prove the ring-3 stack grows on demand.
 *
 * Before demand growth, every PE got a fixed 64 KiB ring-3 stack
 * (kV0StackPages = 16) regardless of what its Optional Header asked
 * for, and a real MSVC app blew through it during CRT startup. The
 * loader now reserves SizeOfStackReserve worth of address space,
 * commits only the top couple of pages, and the #PF handler commits
 * one more page each time the thread's stack pointer walks into the
 * page below the committed edge.
 *
 * This fixture is linked with --stack 1048576,4096 (Windows' own
 * default) and then deliberately consumes far more than 64 KiB of it
 * by recursing with a real local buffer in each frame. If growth is
 * broken the process dies with a #PF long before it reaches the
 * target depth; if growth works it prints the depth and the number of
 * stack bytes it actually walked, and only then reports PASS.
 *
 * The recursion is deliberately shallow-framed (kFrameBytes well
 * under a page) so each step walks the stack down sequentially — the
 * pattern MSVC's __chkstk produces and the only pattern the growth
 * classifier accepts. A frame larger than a page would skip pages and
 * SHOULD be refused; that case is covered in
 * tests/host/test_user_stack.cpp rather than here, because proving it
 * live means killing the task.
 */
#include <windows.h>

/* Bytes of stack each recursion level consumes (buffer + saved regs +
 * return address). Kept well under a 4 KiB page on purpose. */
#define kFrameBytes 512

/* 1024 levels x ~512 B is ~512 KiB — eight times the old fixed 64 KiB
 * stack, and comfortably inside the 1 MiB reservation. */
#define kTargetDepth 1024

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

/* Deepest stack address the recursion actually touched. Written by
 * every level so the compiler cannot fold the frames away. */
static volatile unsigned long long g_deepest_rsp;
static volatile unsigned long g_deepest_level;

/* noinline + a volatile touch of the local buffer stop the compiler
 * turning this into a loop or eliding the frame. The return value is
 * consumed by the caller so the call is not a tail call. */
__declspec(noinline) static unsigned long Descend(unsigned long level)
{
    volatile char pad[kFrameBytes - 64];
    unsigned long long here = (unsigned long long)(unsigned long long*)&pad[0];

    /* Touch both ends of the frame so the whole thing is really
     * resident, not just the return address slot. */
    pad[0] = (char)level;
    pad[sizeof(pad) - 1] = (char)(level >> 8);

    if (here < g_deepest_rsp || g_deepest_rsp == 0)
    {
        g_deepest_rsp = here;
        g_deepest_level = level;
    }

    if (level >= kTargetDepth)
        return level;

    return Descend(level + 1) + (unsigned long)pad[0] - (unsigned long)pad[0];
}

void __cdecl mainCRTStartup(void)
{
    volatile char anchor[16];
    unsigned long long start_rsp = (unsigned long long)(unsigned long long*)&anchor[0];
    anchor[0] = 0;

    Out("[stackgrow] starting\r\n");

    g_deepest_rsp = 0;
    g_deepest_level = 0;
    unsigned long reached = Descend(1);

    unsigned long long walked = start_rsp - g_deepest_rsp;

    Out("[stackgrow] depth reached = ");
    OutDec(reached);
    Out("\r\n[stackgrow] stack bytes walked = ");
    OutDec(walked);
    Out("\r\n");

    /* The bar: more than 128 KiB actually touched. That is twice the
     * old fixed stack, so reaching it is only possible if the kernel
     * committed pages that were not mapped at spawn. */
    if (reached >= kTargetDepth && walked > 128u * 1024u)
    {
        Out("[stackgrow] grew past the old fixed 64 KiB stack: PASS\r\n");
        Out("[ring3-stackgrow-smoke] PASS\r\n");
        ExitProcess(0);
    }

    Out("[stackgrow] did not walk far enough: FAIL\r\n");
    Out("[ring3-stackgrow-smoke] FAIL\r\n");
    ExitProcess(1);
}
