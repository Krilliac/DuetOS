/*
 * pe32_miss — PE32 that calls an UNRESOLVED Win32 import to
 * validate the 32-bit Win32 thunks page. SetWindowsHookExA is in
 * user32 but NOT in our v0 user32_32 stubs; the PE32 IAT walker
 * therefore points the slot at kWin32Thunks32UnresolvedVa
 * (= 0x60100000), the i386 stub does SYS_EXIT(0xDEAD0042), and
 * the process destroys cleanly with that exit code in the
 * [proc] destroy log line.
 *
 * Compare against pe32_rich, which exercises only RESOLVED
 * imports. Pairing the two proves both branches of the via-DLL
 * resolver work: the via-DLL hit path (pe32_rich) AND the
 * catch-all fall-through path (pe32_miss).
 */
typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)

__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE, const void*, DWORD, DWORD*, void*);

/* user32: SetWindowsHookExA — NOT in our v0 user32_32 stubs.
 * Calling it routes through the 32-bit unresolved-import thunk. */
__declspec(dllimport) HANDLE __stdcall SetWindowsHookExA(int idHook, void* lpfn, HANDLE hMod, DWORD dwThreadId);

static void say(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, (void*)0);
}

void __cdecl mainCRTStartup(void)
{
    say("[pe32-miss] starting — about to call unresolved import\r\n");

    /* This call lands in the 32-bit unresolved-import stub at
     * kWin32Thunks32Va (0x60100000). The stub does
     * SYS_EXIT(0xDEAD0042). We never return here. */
    (void)SetWindowsHookExA(0, (void*)0, (HANDLE)0, 0);

    /* Unreachable on a working setup. If the kernel didn't wire
     * the 32-bit thunk page, the indirect call would page-fault
     * before we got here, and this exit code wouldn't run. */
    say("[pe32-miss] UNEXPECTED: returned from unresolved import\r\n");
    ExitProcess(0xBADC0DE);
}
