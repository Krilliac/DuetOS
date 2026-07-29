/*
 * delayload_pe — proves the PE loader binds
 * IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT (directory 13) at load time.
 *
 * Built with clang --target=x86_64-pc-windows-msvc and linked by
 * lld-link with `/delayload:user32.dll`, so the user32 imports go
 * through a real MSVC-shaped delay-load directory: an ImgDelayDescr
 * array, a delay IAT seeded by the linker with the addresses of its
 * own `__tailMerge` stubs, and a delay INT naming each function.
 *
 * On Windows nothing in the OS binds those slots. The first call
 * lands in the linker's thunk, which calls the image's OWN
 * `__delayLoadHelper2` (normally supplied by delayimp.lib), and the
 * helper does LoadLibrary + GetProcAddress and overwrites the slot.
 *
 * We supply that helper ourselves — and it is a TRIPWIRE, not a
 * resolver. If it ever runs, the loader did NOT bind the slot. That
 * makes the test unambiguous in both directions:
 *
 *   1. helper-not-invoked — g_helper_calls stays 0 across every
 *      delay-loaded call. Positive proof the slot was pre-bound.
 *   2. slot-points-outside-image — the delay IAT entry
 *      (`__imp_IsCharAlphaA`) no longer holds an address inside
 *      this image, where the linker's thunk lives, but one in the
 *      preloaded user32.dll. This is the loader's write, observed
 *      directly.
 *   3. delay-call-works — the delay-loaded functions return the
 *      values user32 defines, so the slot points at the RIGHT
 *      export and not merely at something outside the image.
 *
 * Check 1 alone would also pass if the delay call crashed before
 * reaching the helper, and check 2 alone would pass if the slot
 * were bound to the wrong export; together they pin the behaviour.
 *
 * Exit code: 0 on full PASS, 1 on any FAIL.
 */

typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned long long ULONGLONG;
typedef int (*FARPROC)(void);

#define STD_OUTPUT_HANDLE ((DWORD) - 11)

__declspec(dllimport) HANDLE GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL WriteConsoleA(HANDLE h, const void* buf, DWORD n, DWORD* written, void* reserved);
__declspec(dllimport) void ExitProcess(unsigned int code);

/* Delay-loaded (see /delayload:user32.dll in the build script).
 * Both are pure predicates in DuetOS's user32 — no syscall, no
 * window state — so their return values are deterministic and a
 * wrong binding shows up as a wrong answer rather than a hang. */
__declspec(dllimport) BOOL IsCharAlphaA(char c);
__declspec(dllimport) BOOL IsCharAlphaNumericA(char c);

/* The delay IAT slot for IsCharAlphaA. lld-link names a delay
 * import's slot exactly like a static one, so taking its address
 * reads the very qword the loader is supposed to have rewritten. */
extern void* __imp_IsCharAlphaA;

/* lld-link defines this at the image's load base. */
extern char __ImageBase;

static volatile DWORD g_helper_calls = 0;

static int DelayHelperTripwire(void)
{
    return 0;
}

/* Signature per delayimp.h: FARPROC WINAPI __delayLoadHelper2(
 *     PCImgDelayDescr pidd, FARPROC* ppfnIATEntry). On x64 there is
 * only one calling convention, so the plain declaration matches
 * what lld-link's tail-merge thunk calls. */
FARPROC __delayLoadHelper2(void* pidd, FARPROC* ppfnIATEntry)
{
    (void)pidd;
    ++g_helper_calls;
    /* Keep the process alive so the harness reports FAIL rather
     * than a fault: hand back a callable no-op and cache it. */
    if (ppfnIATEntry != 0)
        *ppfnIATEntry = (FARPROC)&DelayHelperTripwire;
    return (FARPROC)&DelayHelperTripwire;
}

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0, len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static unsigned int rd32(const unsigned char* p)
{
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/* SizeOfImage out of our own mapped optional header, so the
 * "outside the image" test uses the real extent instead of a
 * guessed constant. */
static unsigned int ImageSize(void)
{
    const unsigned char* base = (const unsigned char*)&__ImageBase;
    unsigned int e_lfanew = rd32(base + 0x3C);
    const unsigned char* opt = base + e_lfanew + 24;
    return rd32(opt + 56); /* OptionalHeader.SizeOfImage */
}

void __cdecl mainCRTStartup(void)
{
    int fail = 0;
    Out("[delayload_pe] starting\r\n");

    /* 1. Was the slot rewritten? Read it BEFORE the first call so
     *    a lazily-resolving loader can't retroactively pass. */
    {
        ULONGLONG slot = (ULONGLONG)__imp_IsCharAlphaA;
        ULONGLONG base = (ULONGLONG)&__ImageBase;
        ULONGLONG size = (ULONGLONG)ImageSize();
        if (slot != 0 && (slot < base || slot >= base + size))
        {
            Out("[delayload_pe] delay-iat-bound-outside-image: PASS\r\n");
        }
        else
        {
            Out("[delayload_pe] delay-iat-bound-outside-image: FAIL\r\n");
            fail = 1;
        }
    }

    /* 2. The delay-loaded calls must return user32's answers. */
    if (IsCharAlphaA('Q') && !IsCharAlphaA('7') && IsCharAlphaNumericA('7') && !IsCharAlphaNumericA('-'))
    {
        Out("[delayload_pe] delay-call-returns-real-values: PASS\r\n");
    }
    else
    {
        Out("[delayload_pe] delay-call-returns-real-values: FAIL\r\n");
        fail = 1;
    }

    /* 3. The image's own helper must never have run. */
    if (g_helper_calls == 0)
    {
        Out("[delayload_pe] helper-not-invoked: PASS\r\n");
    }
    else
    {
        Out("[delayload_pe] helper-not-invoked: FAIL\r\n");
        fail = 1;
    }

    Out(fail ? "[delayload_pe] RESULT FAIL\r\n" : "[delayload_pe] RESULT PASS\r\n");
    ExitProcess(fail ? 1u : 0u);
}
