/*
 * cxxeh_pe — real MSVC C++ exception handling smoke.
 *
 * Freestanding clang-windows-msvc PE (no CRT, entry =
 * mainCRTStartup). Exercises the vcruntime140 C++ EH personality
 * (__CxxFrameHandler3 + _CxxThrowException) wired onto the ntdll
 * two-pass dispatch/unwind engine:
 *
 *   1. throw / catch an `int`            — scalar catch-by-value
 *   2. throw / catch a class by `&`      — type match across the
 *                                          CatchableTypeArray
 *   3. a stack object's destructor must  — in-frame unwind funclet
 *      run while the exception unwinds
 *   4. catch (...)                       — catch-all
 *
 * Prints `[cxxeh] RESULT PASS` and exits 0 only if all four hold;
 * any miss prints FAIL and exits 1.
 */

typedef unsigned long DWORD;
typedef int BOOL;
typedef void* HANDLE;

extern "C"
{
    __declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
    __declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE h, const void* buf, DWORD len, DWORD* written,
                                                       void* resv);
    __declspec(dllimport) void __stdcall ExitProcess(unsigned int code);
}

static void put(const char* s)
{
    DWORD n = 0;
    const char* p = s;
    while (*p)
        ++p;
    WriteConsoleA(GetStdHandle((DWORD)-11), s, (DWORD)(p - s), &n, 0);
}

struct Oops
{
    int code;
};

static int g_dtor_ran = 0;

struct Guard
{
    ~Guard() { g_dtor_ran = 1; }
};

static int test_int_throw()
{
    try
    {
        throw 0x2A;
    }
    catch (int v)
    {
        return v == 0x2A ? 1 : 0;
    }
    return 0;
}

static int test_class_throw()
{
    try
    {
        Oops o;
        o.code = 7;
        throw o;
    }
    catch (Oops& e)
    {
        return e.code == 7 ? 1 : 0;
    }
    catch (...)
    {
        return 0;
    }
}

static int throws_through_dtor()
{
    Guard g; /* dtor must fire as the exception unwinds this frame */
    throw 1;
    (void)g;
    return 0;
}

static int test_unwind_dtor()
{
    g_dtor_ran = 0;
    try
    {
        throws_through_dtor();
    }
    catch (int)
    {
        return g_dtor_ran == 1 ? 1 : 0;
    }
    return 0;
}

static int test_catch_all()
{
    try
    {
        throw 3.14;
    }
    catch (...)
    {
        return 1;
    }
    return 0;
}

extern "C" int mainCRTStartup(void)
{
    int ok = 1;
    ok &= test_int_throw();
    ok &= test_class_throw();
    ok &= test_unwind_dtor();
    ok &= test_catch_all();

    if (ok)
    {
        put("[cxxeh] RESULT PASS\n");
        ExitProcess(0);
    }
    put("[cxxeh] RESULT FAIL\n");
    ExitProcess(1);
    return ok ? 0 : 1;
}
