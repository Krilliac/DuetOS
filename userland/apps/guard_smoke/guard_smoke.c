/*
 * guard_smoke -- prove STATUS_GUARD_PAGE_VIOLATION delivery to userland.
 *
 * VirtualAlloc a page with PAGE_READWRITE | PAGE_GUARD, then write to
 * it. The kernel must deliver STATUS_GUARD_PAGE_VIOLATION (0x80000001)
 * to our Vectored Exception Handler BEFORE the write retries. The
 * handler verifies the exception code and the ExceptionInformation
 * vector (access type + faulting VA), then returns
 * EXCEPTION_CONTINUE_EXECUTION -- the write retries, succeeds (the
 * guard was one-shot), and control returns to normal flow.
 *
 * A second write to the same page must NOT trigger another exception
 * (the guard was already consumed).
 *
 * Exit 0 + "[ring3-guard-smoke] PASS" on success.
 */
#include <windows.h>

extern void* RtlAddVectoredExceptionHandler(unsigned long First, void* Handler);
extern unsigned long RtlRemoveVectoredExceptionHandler(void* Handle);

#define EXC_GUARD_PAGE 0x80000001UL
#define VEH_CONTINUE_EXECUTION (-1)
#define VEH_CONTINUE_SEARCH (0)

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

/* State shared between the main thread and the VEH handler. */
static volatile int g_guard_hits;
static volatile unsigned long g_guard_code;
static volatile unsigned long long g_guard_access_type;
static volatile unsigned long long g_guard_fault_va;

/*
 * VEH handler: only handles STATUS_GUARD_PAGE_VIOLATION. Captures the
 * exception info and returns CONTINUE_EXECUTION so the faulting
 * instruction retries (the guard was already cleared by the kernel).
 */
static long __attribute__((ms_abi)) veh_guard_handler(void* ExceptionInfo)
{
    void** ep = (void**)ExceptionInfo;
    unsigned char* rec = (unsigned char*)ep[0];
    unsigned long code = *(unsigned int*)(rec + 0x00); /* ExceptionCode */

    if (code == EXC_GUARD_PAGE)
    {
        unsigned int nparams = *(unsigned int*)(rec + 0x10); /* NumberParameters */
        g_guard_code = code;
        if (nparams >= 2)
        {
            /* ExceptionInformation is at offset 0x18 in EXCEPTION_RECORD
             * (after ExceptionCode(4) + ExceptionFlags(4) +
             *  ExceptionRecord(8) + ExceptionAddress(8) +
             *  NumberParameters(4) + _alignment(4) = 0x20).
             * Wait -- the struct in seh_dispatch.cpp is:
             *   ExceptionCode       0x00  u32
             *   ExceptionFlags      0x04  u32
             *   ExceptionRecordPtr  0x08  u64
             *   ExceptionAddress    0x10  u64
             *   NumberParameters    0x18  u32
             *   _alignment          0x1C  u32
             *   ExceptionInformation 0x20 u64[15]
             */
            g_guard_access_type = *(unsigned long long*)(rec + 0x20);
            g_guard_fault_va = *(unsigned long long*)(rec + 0x28);
        }
        ++g_guard_hits;
        return VEH_CONTINUE_EXECUTION;
    }
    return VEH_CONTINUE_SEARCH;
}

void __cdecl mainCRTStartup(void)
{
    Out("[guard_smoke] starting\r\n");
    int fail = 0;

    /* Register our Vectored Exception Handler first-in-line. */
    void* veh = RtlAddVectoredExceptionHandler(1u, (void*)&veh_guard_handler);
    if (veh == 0)
    {
        Out("[guard_smoke] VEH register failed\r\n");
        Out("[ring3-guard-smoke] FAIL\r\n");
        ExitProcess(1);
    }

    /* Allocate a single page with PAGE_GUARD. */
    volatile int* ptr =
        (volatile int*)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE | 0x100 /* PAGE_GUARD */);
    if (ptr == NULL)
    {
        Out("[guard_smoke] VirtualAlloc failed\r\n");
        Out("[ring3-guard-smoke] FAIL\r\n");
        ExitProcess(1);
    }
    Out("[guard_smoke] guard page at ");
    OutHex((unsigned long long)ptr);
    Out("\r\n");

    /* ---- Test 1: write triggers STATUS_GUARD_PAGE_VIOLATION ---- */
    g_guard_hits = 0;
    g_guard_code = 0;
    g_guard_access_type = 0xFFFFFFFF; /* sentinel */
    g_guard_fault_va = 0;

    *ptr = 0x42; /* triggers the guard */

    if (g_guard_hits == 1 && g_guard_code == EXC_GUARD_PAGE)
    {
        Out("[guard_smoke] guard-exception-delivered: PASS\r\n");
    }
    else
    {
        Out("[guard_smoke] guard-exception-delivered: FAIL (hits=");
        OutHex((unsigned long long)g_guard_hits);
        Out(" code=");
        OutHex((unsigned long long)g_guard_code);
        Out(")\r\n");
        fail = 1;
    }

    /* Verify the access type (1 = write). */
    if (g_guard_access_type == 1)
    {
        Out("[guard_smoke] access-type-write: PASS\r\n");
    }
    else
    {
        Out("[guard_smoke] access-type-write: FAIL (got ");
        OutHex(g_guard_access_type);
        Out(")\r\n");
        fail = 1;
    }

    /* Verify the faulting VA is inside our guard page. */
    {
        unsigned long long va = g_guard_fault_va;
        unsigned long long base = (unsigned long long)ptr;
        if (va >= base && va < base + 4096)
        {
            Out("[guard_smoke] fault-va: PASS\r\n");
        }
        else
        {
            Out("[guard_smoke] fault-va: FAIL (va=");
            OutHex(va);
            Out(" base=");
            OutHex(base);
            Out(")\r\n");
            fail = 1;
        }
    }

    /* Verify the value was actually written. */
    if (*ptr == 0x42)
    {
        Out("[guard_smoke] value-written: PASS\r\n");
    }
    else
    {
        Out("[guard_smoke] value-written: FAIL\r\n");
        fail = 1;
    }

    /* ---- Test 2: second write must NOT trigger another guard ---- */
    int before = g_guard_hits;
    *ptr = 0x43;
    if (g_guard_hits == before)
    {
        Out("[guard_smoke] guard-one-shot: PASS\r\n");
    }
    else
    {
        Out("[guard_smoke] guard-one-shot: FAIL (guard fired twice)\r\n");
        fail = 1;
    }

    RtlRemoveVectoredExceptionHandler(veh);
    VirtualFree((void*)ptr, 0, MEM_RELEASE);

    Out(fail ? "[guard_smoke] RESULT FAIL\r\n" : "[guard_smoke] RESULT PASS\r\n");
    Out(fail ? "[ring3-guard-smoke] FAIL\r\n" : "[ring3-guard-smoke] PASS\r\n");
    ExitProcess(fail ? 1u : 0u);
}
