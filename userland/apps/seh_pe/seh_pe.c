/*
 * seh_pe — verifies the DuetOS SEH foundation (T6-02, slice 1):
 * real RtlCaptureContext + table-based RtlLookupFunctionEntry.
 *
 * No CPU fault is taken here — this slice is the unwinder
 * *foundation* (capture + .pdata lookup), not yet the kernel
 * fault -> __except dispatch. Both routines are pure (capture is
 * a register snapshot; lookup is a read of the in-memory .pdata),
 * so a deterministic self-check is the right proof:
 *
 *   1. RtlCaptureContext fills Rip/Rsp with sane values.
 *   2. RtlLookupFunctionEntry(Rip) returns the RUNTIME_FUNCTION
 *      whose [Begin,End) actually covers the captured Rip, and
 *      reports the EXE image base.
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

void __cdecl mainCRTStartup(void)
{
    Out("[seh_pe] starting\r\n");
    int fail = capture_and_check();
    Out(fail ? "[seh_pe] RESULT FAIL\r\n" : "[seh_pe] RESULT PASS\r\n");
    Out("[seh_pe] done\r\n");
    ExitProcess(fail ? 1u : 0u);
}
