/*
 * rsrc_pe — PE32 (i386) test image for the `.rsrc` rung of the PE32
 * ladder. Loads strings and binary resources out of its OWN embedded
 * resource section, which windres laid out (see rsrc_pe.rc).
 *
 * The point of this image is the one thing neither the compile nor the
 * hosted unit test can prove: that the walker works on a resource
 * section produced by a real Windows toolchain, reached through the
 * kernel's live image mapping, from ring 3, via the normal IAT.
 * tests/host/test_pe_resources.cpp pins the parser against synthetic
 * blobs; this pins it against windres output.
 *
 * What each step proves:
 *
 *   1. LoadStringW returns the app's real string for id 1 -- not the
 *      "DuetOS" placeholder the export used to return for every id.
 *   2/3. ids 15 and 16 straddle a string-bundle boundary. They live in
 *      DIFFERENT RT_STRING resources ((id/16)+1 == 1 vs 2), so an
 *      off-by-one in either half of the bundling formula returns the
 *      wrong text rather than nothing.
 *   4. id 4242 is far enough out (bundle 266) that finding it is a real
 *      tree search, not a first-entry accident.
 *   5. A missing id returns 0 and leaves the buffer alone.
 *   6. LoadStringW with cchBufferMax == 0 returns a pointer to the
 *      resource itself -- the documented form apps use to avoid a copy.
 *   7. FindResourceW + SizeofResource + LoadResource + LockResource on
 *      a NAMED RT_RCDATA, which exercises the high-bit directory entry
 *      and the IMAGE_RESOURCE_DIR_STRING_U decode.
 *   8. The same chain on an INTEGER-id RT_RCDATA.
 *   9. A missing resource returns NULL, and SizeofResource on a
 *      fabricated handle returns 0 instead of faulting -- the handle
 *      re-validation path.
 *
 * Built with i686-w64-mingw32-gcc + i686-w64-mingw32-windres,
 * freestanding, entry mainCRTStartup. Reports the standardized battery
 * verdict line.
 */

typedef void* HANDLE;
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef int INT;
typedef unsigned short WCHAR;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define MAKEINTRESOURCEW(i) ((const WCHAR*)(unsigned long)(unsigned short)(i))
#define RT_RCDATA MAKEINTRESOURCEW(10)

/* kernel32 */
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE, const void*, DWORD, DWORD*, void*);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleW(const WCHAR*);
__declspec(dllimport) HANDLE __stdcall FindResourceW(HANDLE, const WCHAR*, const WCHAR*);
__declspec(dllimport) HANDLE __stdcall LoadResource(HANDLE, HANDLE);
__declspec(dllimport) void* __stdcall LockResource(HANDLE);
__declspec(dllimport) DWORD __stdcall SizeofResource(HANDLE, HANDLE);

/* user32 */
__declspec(dllimport) INT __stdcall LoadStringW(HANDLE, UINT, WCHAR*, INT);

static int g_failures = 0;

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void Check(const char* what, int ok)
{
    Out("[rsrc_pe] ");
    Out(what);
    Out(ok ? " = PASS\r\n" : " = FAIL\r\n");
    if (!ok)
        ++g_failures;
}

/* Compare a UTF-16 buffer against an ASCII literal. */
static int WEqualsA(const WCHAR* w, const char* a)
{
    unsigned i = 0;
    for (; a[i] != '\0'; ++i)
    {
        if (w[i] != (WCHAR)(unsigned char)a[i])
            return 0;
    }
    return w[i] == 0;
}

/* Compare `n` bytes against an ASCII literal (resource payloads are
 * raw bytes, not UTF-16). */
static int BytesEqualA(const char* b, const char* a, unsigned n)
{
    unsigned i = 0;
    for (; a[i] != '\0'; ++i)
    {
        if (i >= n || b[i] != a[i])
            return 0;
    }
    return 1;
}

/* Fetch one string resource and compare it against the .rc text. */
static void CheckString(const char* what, UINT id, const char* expect)
{
    WCHAR buf[64];
    INT n;
    buf[0] = 0;
    n = LoadStringW(0, id, buf, 64);
    Check(what, n > 0 && WEqualsA(buf, expect));
}

/* Find + size + load + lock one resource and compare its bytes. */
static void CheckRcData(const char* what, const WCHAR* name, const char* expect)
{
    HANDLE me = GetModuleHandleW(0);
    HANDLE hrsrc = FindResourceW(me, name, RT_RCDATA);
    DWORD size;
    HANDLE hglobal;
    const char* bytes;

    if (hrsrc == 0)
    {
        Check(what, 0);
        return;
    }
    size = SizeofResource(me, hrsrc);
    hglobal = LoadResource(me, hrsrc);
    bytes = (const char*)LockResource(hglobal);
    Check(what, size > 0 && bytes != 0 && BytesEqualA(bytes, expect, size));
}

void __cdecl mainCRTStartup(void)
{
    Out("[rsrc_pe] starting\r\n");

    /* 1-4: string-table lookups, including a bundle boundary. */
    CheckString("LoadStringW(1)      ", 1, "duetos-string-one");
    CheckString("LoadStringW(15)     ", 15, "bundle1-slot15");
    CheckString("LoadStringW(16)     ", 16, "bundle2-slot0");
    CheckString("LoadStringW(4242)   ", 4242, "far-bundle-4242");

    /* 5: a missing id must return 0 and not touch the buffer. */
    {
        WCHAR buf[8];
        INT n;
        buf[0] = 0xBEEF;
        n = LoadStringW(0, 9999, buf, 8);
        Check("LoadStringW(missing)", n == 0 && buf[0] == (WCHAR)0xBEEF);
    }

    /* 6: cchBufferMax == 0 hands back a pointer to the resource. */
    {
        const WCHAR* direct = 0;
        INT n = LoadStringW(0, 1, (WCHAR*)&direct, 0);
        Check("LoadStringW(len=0)  ", n == 17 && direct != 0 && direct[0] == (WCHAR)'d' && direct[16] == (WCHAR)'e');
    }

    /* 7-8: named and integer-id binary resources. */
    CheckRcData("FindResourceW(named)", (const WCHAR*)L"DUETPAYLOAD", "DUETOS-RCDATA-OK");
    CheckRcData("FindResourceW(id101)", MAKEINTRESOURCEW(101), "DUETOS-ID101");

    /* 9: misses and a fabricated handle both fail closed. */
    {
        HANDLE me = GetModuleHandleW(0);
        HANDLE miss = FindResourceW(me, MAKEINTRESOURCEW(4321), RT_RCDATA);
        DWORD bogus = SizeofResource(me, (HANDLE)0x1234);
        Check("FindResourceW(miss) ", miss == 0);
        Check("SizeofResource(bad) ", bogus == 0);
    }

    if (g_failures == 0)
        Out("[ring3-rsrc-pe] PASS\r\n");
    else
        Out("[ring3-rsrc-pe] FAIL resource checks did not all pass\r\n");
    ExitProcess(g_failures == 0 ? 0x42 : 1);
}
