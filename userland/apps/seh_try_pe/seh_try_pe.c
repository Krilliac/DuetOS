/*
 * seh_try_pe — real MSVC __try / __except / __finally over CPU
 * faults, built with clang --target=x86_64-pc-windows-msvc
 * -fasync-exceptions (which emits .pdata/.xdata + the
 * __C_specific_handler personality). This is the test the
 * mingw-w64 smoke toolchain could NOT express: it exercises the
 * frame-based SEH engine end-to-end —
 *
 *   kernel #PF/#DE  →  ntdll!KiUserExceptionDispatcher
 *                   →  __C_specific_handler (scope-table walk)
 *                   →  __except filter
 *                   →  RtlUnwindEx (runs __finally on the way)
 *                   →  RtlRestoreContext into the __except block
 *
 * Freestanding: no CRT, entry = mainCRTStartup, imports resolved
 * from our own kernel32.lib / ntdll.lib. Exit 0 = full PASS.
 */

typedef unsigned long DWORD;
typedef unsigned long long ULONG64;
typedef int BOOL;
typedef void* HANDLE;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define EXCEPTION_EXECUTE_HANDLER 1
#define EXCEPTION_ACCESS_VIOLATION 0xC0000005UL
#define EXCEPTION_INT_DIVIDE_BY_ZERO 0xC0000094UL

/* An arbitrary application-defined code (customer bit set, as
 * Windows requires for non-system exception codes). */
#define RAISE_TEST_CODE 0xE0BADC0DUL

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE h, const void* buf, DWORD len, DWORD* written, void* resv);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int code);
__declspec(dllimport) void __stdcall RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags,
                                                    DWORD nNumberOfArguments, const ULONG64* lpArguments);

/* MSVC SEH intrinsics — recover the current exception's NTSTATUS and
 * its EXCEPTION_POINTERS inside an __except filter. Recognised by
 * clang in MSVC mode. */
unsigned long __cdecl _exception_code(void);
void* __cdecl _exception_info(void);
#define GetExceptionInformation() ((EXCEPTION_POINTERS*)_exception_info())

/* Just enough of EXCEPTION_RECORD / EXCEPTION_POINTERS to read the
 * argument vector back out of a RaiseException. */
typedef struct
{
    DWORD ExceptionCode;
    DWORD ExceptionFlags;
    void* ExceptionRecord;
    void* ExceptionAddress;
    DWORD NumberParameters;
    DWORD _align;
    ULONG64 ExceptionInformation[15];
} EXCEPTION_RECORD_T;

typedef struct
{
    EXCEPTION_RECORD_T* ExceptionRecord;
    void* ContextRecord;
} EXCEPTION_POINTERS;

/* Filter-time helper: pull the parameter count and first two
 * parameters out of the live record. Kept out of the __except body
 * because the record is only guaranteed live during the filter. */
static DWORD ExFilterParams(EXCEPTION_POINTERS* ep, ULONG64* p0, ULONG64* p1)
{
    if (ep == 0 || ep->ExceptionRecord == 0)
        return 0;
    const EXCEPTION_RECORD_T* r = ep->ExceptionRecord;
    if (r->NumberParameters >= 1)
        *p0 = r->ExceptionInformation[0];
    if (r->NumberParameters >= 2)
        *p1 = r->ExceptionInformation[1];
    return r->NumberParameters;
}

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutHex(ULONG64 v)
{
    char buf[19];
    buf[0] = '0';
    buf[1] = 'x';
    for (int i = 0; i < 16; ++i)
        buf[2 + i] = "0123456789abcdef"[(v >> ((15 - i) * 4)) & 0xF];
    buf[18] = 0;
    Out(buf);
}

static volatile int* g_null = 0;
static volatile int g_zero = 0;
static volatile int g_sink;

/* 1. Null write (#PF) caught by __except, code verified. */
__declspec(noinline) static int t_null_write(void)
{
    unsigned long code = 0;
    int caught = 0;
    __try
    {
        *g_null = 0x1234;
        Out("[seh_try] null-write: FAIL (no fault)\r\n");
    }
    __except ((code = _exception_code()), EXCEPTION_EXECUTE_HANDLER)
    {
        caught = 1;
        Out("[seh_try] null-write __except code=");
        OutHex(code);
        Out("\r\n");
    }
    if (caught && code == EXCEPTION_ACCESS_VIOLATION)
    {
        Out("[seh_try] except-null-write: PASS\r\n");
        return 0;
    }
    Out("[seh_try] except-null-write: FAIL\r\n");
    return 1;
}

/* 2. Integer divide-by-zero (#DE) caught by __except. */
__declspec(noinline) static int t_div_zero(void)
{
    unsigned long code = 0;
    int caught = 0;
    __try
    {
        int d = g_zero;
        g_sink = 100 / d;
        Out("[seh_try] div-zero: FAIL (no fault)\r\n");
    }
    __except ((code = _exception_code()), EXCEPTION_EXECUTE_HANDLER)
    {
        caught = 1;
        Out("[seh_try] div-zero __except code=");
        OutHex(code);
        Out("\r\n");
    }
    if (caught && code == EXCEPTION_INT_DIVIDE_BY_ZERO)
    {
        Out("[seh_try] except-div-zero: PASS\r\n");
        return 0;
    }
    Out("[seh_try] except-div-zero: FAIL\r\n");
    return 1;
}

/* 3. __finally must run while RtlUnwindEx walks from the fault
 *    frame out to the __except frame. */
static volatile int g_finally_ran;
__declspec(noinline) static void inner_fault(void)
{
    __try
    {
        *g_null = 7;
    }
    __finally
    {
        g_finally_ran = 1;
    }
}
__declspec(noinline) static int t_finally_on_unwind(void)
{
    g_finally_ran = 0;
    __try
    {
        inner_fault();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    if (g_finally_ran)
    {
        Out("[seh_try] finally-on-unwind: PASS\r\n");
        return 0;
    }
    Out("[seh_try] finally-on-unwind: FAIL\r\n");
    return 1;
}

/* 4. Repeatable: a second independent fault is also caught — the
 *    handler returned cleanly and execution continued. */
__declspec(noinline) static int t_repeatable(void)
{
    int hits = 0;
    for (int i = 0; i < 3; ++i)
    {
        __try
        {
            *g_null = i;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ++hits;
        }
    }
    if (hits == 3)
    {
        Out("[seh_try] repeatable: PASS\r\n");
        return 0;
    }
    Out("[seh_try] repeatable: FAIL\r\n");
    return 1;
}

/* 5. Software exception: RaiseException must dispatch through the
 *    same engine a CPU fault does, and deliver its argument vector
 *    intact. This is the path a statically-linked MSVC CRT's
 *    `throw` takes — its own _CxxThrowException copy calls
 *    kernel32!RaiseException(0xE06D7363, ...) rather than our
 *    vcruntime140 export. While kernel32!RaiseException was a
 *    SYS_EXIT stub, every such throw ended the process with the
 *    exception code as its exit status. */
__declspec(noinline) static int t_raise_exception(void)
{
    ULONG64 args[2] = {0x1122334455667788ULL, 0x99AABBCCDDEEFF00ULL};
    unsigned long code = 0;
    ULONG64 seen0 = 0, seen1 = 0;
    unsigned long nparams = 0;
    int caught = 0;
    __try
    {
        RaiseException(RAISE_TEST_CODE, 0, 2, args);
        Out("[seh_try] raise-exception: FAIL (returned)\r\n");
    }
    __except ((code = _exception_code()), (nparams = ExFilterParams(GetExceptionInformation(), &seen0, &seen1)),
              EXCEPTION_EXECUTE_HANDLER)
    {
        caught = 1;
        Out("[seh_try] raise __except code=");
        OutHex(code);
        Out("\r\n");
    }
    if (caught && code == RAISE_TEST_CODE && nparams == 2 && seen0 == args[0] && seen1 == args[1])
    {
        Out("[seh_try] raise-exception: PASS\r\n");
        return 0;
    }
    Out("[seh_try] raise-exception: FAIL\r\n");
    return 1;
}

void __cdecl mainCRTStartup(void)
{
    Out("[seh_try] starting\r\n");
    int fail = 0;
    fail |= t_null_write();
    fail |= t_div_zero();
    fail |= t_finally_on_unwind();
    fail |= t_repeatable();
    fail |= t_raise_exception();
    Out(fail ? "[seh_try] RESULT FAIL\r\n" : "[seh_try] RESULT PASS\r\n");
    Out("[seh_try] done\r\n");
    ExitProcess(fail ? 1u : 0u);
}
