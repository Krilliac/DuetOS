/*
 * pe32_rich — PE32 (i386) test image that imports from every
 * preloaded 32-bit DLL. The PE32 IAT resolver walks one import
 * per DLL, and the boot transcript shows a "[pe-resolve] via-dll"
 * line for each — proving the entire 13-DLL preload set works.
 *
 * Built with i686-w64-mingw32-gcc. Bigger than pe32_smoke (~14 KB
 * vs 6 KB) because each `__declspec(dllimport)` adds an IAT slot
 * + a thunk into the .text. The execution path runs straight
 * through and exits with rc=0x42 so the boot scraper has a
 * deterministic success signature.
 */
typedef void* HANDLE;
typedef unsigned long DWORD;
typedef int BOOL;
typedef int INT;
typedef unsigned short USHORT;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define CRYPT_VERIFYCONTEXT 0xF0000000u

/* kernel32 */
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE, const void*, DWORD, DWORD*, void*);
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) HANDLE __stdcall GetProcessHeap(void);
__declspec(dllimport) void* __stdcall HeapAlloc(HANDLE, DWORD, unsigned);
__declspec(dllimport) BOOL __stdcall HeapFree(HANDLE, DWORD, void*);
__declspec(dllimport) DWORD __stdcall GetTickCount(void);
__declspec(dllimport) void __stdcall Sleep(DWORD);
__declspec(dllimport) HANDLE __stdcall GetModuleHandleA(const char*);

/* msvcrt */
__declspec(dllimport) unsigned __cdecl strlen(const char*);
__declspec(dllimport) int __cdecl atoi(const char*);
__declspec(dllimport) void* __cdecl memset(void*, int, unsigned);

/* user32 */
__declspec(dllimport) int __stdcall GetSystemMetrics(int);
__declspec(dllimport) HANDLE __stdcall GetDesktopWindow(void);

/* gdi32 */
__declspec(dllimport) HANDLE __stdcall GetStockObject(int);

/* advapi32 */
__declspec(dllimport) BOOL __stdcall CryptAcquireContextA(HANDLE*, const char*, const char*, DWORD, DWORD);

/* comctl32 */
__declspec(dllimport) BOOL __stdcall InitCommonControlsEx(const void*);

/* comdlg32 */
__declspec(dllimport) BOOL __stdcall ChooseFontA(void*);

/* crypt32 */
__declspec(dllimport) HANDLE __stdcall CertOpenSystemStoreA(HANDLE, const char*);

/* iphlpapi */
__declspec(dllimport) DWORD __stdcall GetAdaptersAddresses(DWORD, DWORD, void*, void*, DWORD*);

/* shell32 */
__declspec(dllimport) int __stdcall SHGetFolderPathA(HANDLE, INT, HANDLE, DWORD, char*);

/* shlwapi */
__declspec(dllimport) BOOL __stdcall PathAppendA(char*, const char*);

/* ws2_32 */
__declspec(dllimport) INT __stdcall WSAStartup(USHORT, void*);
__declspec(dllimport) INT __stdcall WSACleanup(void);
__declspec(dllimport) USHORT __stdcall htons(USHORT);

/* bcrypt */
__declspec(dllimport) int __stdcall BCryptGenRandom(HANDLE, unsigned char*, DWORD, DWORD);

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
    say("[pe32-rich] starting\r\n");

    /* Exercise each DLL's preload + IAT resolution path. The
     * goal isn't real functionality — most of these are stubs —
     * just that the indirect call doesn't fault, the args land
     * correctly via the 32-bit syscall remap, and the return
     * value comes back. */

    /* kernel32: GetProcessHeap + HeapAlloc + HeapFree round-trip. */
    HANDLE heap = GetProcessHeap();
    void* mem = HeapAlloc(heap, 0, 256);
    if (mem)
    {
        memset(mem, 0xAA, 256);
        HeapFree(heap, 0, mem);
    }
    say("[pe32-rich] kernel32 ok\r\n");

    /* msvcrt: strlen + atoi. */
    unsigned slen = strlen("hello");
    int ival = atoi("42");
    if (slen == 5 && ival == 42)
        say("[pe32-rich] msvcrt ok\r\n");
    else
        say("[pe32-rich] msvcrt FAIL\r\n");

    /* user32: GetSystemMetrics + GetDesktopWindow. */
    int cx = GetSystemMetrics(0);
    (void)cx;
    (void)GetDesktopWindow();
    say("[pe32-rich] user32 ok\r\n");

    /* gdi32: GetStockObject. */
    (void)GetStockObject(0);
    say("[pe32-rich] gdi32 ok\r\n");

    /* advapi32: CryptAcquireContextA (returns 0/fail in v0 — fine). */
    HANDLE hprov = (HANDLE)0;
    (void)CryptAcquireContextA(&hprov, (const char*)0, (const char*)0, 1, CRYPT_VERIFYCONTEXT);
    say("[pe32-rich] advapi32 ok\r\n");

    /* comctl32: InitCommonControlsEx. */
    (void)InitCommonControlsEx((const void*)0);
    say("[pe32-rich] comctl32 ok\r\n");

    /* comdlg32: ChooseFontA (returns 0 in v0). */
    (void)ChooseFontA((void*)0);
    say("[pe32-rich] comdlg32 ok\r\n");

    /* crypt32: CertOpenSystemStoreA. */
    (void)CertOpenSystemStoreA((HANDLE)0, "MY");
    say("[pe32-rich] crypt32 ok\r\n");

    /* iphlpapi: GetAdaptersAddresses. */
    DWORD sz = 0;
    (void)GetAdaptersAddresses(0, 0, (void*)0, (void*)0, &sz);
    say("[pe32-rich] iphlpapi ok\r\n");

    /* shell32: SHGetFolderPathA. */
    char path[260];
    (void)SHGetFolderPathA((HANDLE)0, 0, (HANDLE)0, 0, path);
    say("[pe32-rich] shell32 ok\r\n");

    /* shlwapi: PathAppendA. */
    char p[64] = "C:\\Foo";
    /* memset first 7 bytes were filled by the literal above. */
    PathAppendA(p, "bar");
    say("[pe32-rich] shlwapi ok\r\n");

    /* ws2_32: WSAStartup + htons + WSACleanup. The htons should
     * return a byte-swapped value; this DOES test the real impl. */
    char wsa_data[408];
    (void)WSAStartup(0x0202, wsa_data);
    USHORT swap = htons(0x1234);
    (void)WSACleanup();
    if (swap == 0x3412)
        say("[pe32-rich] ws2_32 ok (htons real)\r\n");
    else
        say("[pe32-rich] ws2_32 FAIL\r\n");

    /* bcrypt: BCryptGenRandom — fills buf with entropy. */
    unsigned char rb[16];
    (void)BCryptGenRandom((HANDLE)0, rb, sizeof(rb), 0);
    say("[pe32-rich] bcrypt ok\r\n");

    /* kernel32: GetTickCount (touch the timer surface) + GetModuleHandleA. */
    DWORD t = GetTickCount();
    (void)t;
    HANDLE k32 = GetModuleHandleA("KERNEL32.dll");
    (void)k32;
    say("[pe32-rich] timer + module ok\r\n");

    say("[pe32-rich] all 13 DLLs exercised — exit rc=0x42\r\n");
    ExitProcess(0x42);
}
