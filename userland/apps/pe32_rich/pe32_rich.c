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
__declspec(dllimport) unsigned __stdcall HeapSize(HANDLE, DWORD, const void*);
__declspec(dllimport) void* __stdcall HeapReAlloc(HANDLE, DWORD, void*, unsigned);
__declspec(dllimport) void* __stdcall GetProcAddress(HANDLE, const char*);

/* kernel32 file I/O (kernel32_32_fs.c) */
__declspec(dllimport) HANDLE __stdcall CreateFileA(const char*, DWORD, DWORD, void*, DWORD, DWORD, HANDLE);
__declspec(dllimport) BOOL __stdcall ReadFile(HANDLE, void*, DWORD, DWORD*, void*);
__declspec(dllimport) DWORD __stdcall SetFilePointer(HANDLE, int, int*, DWORD);
__declspec(dllimport) DWORD __stdcall GetFileSize(HANDLE, DWORD*);
__declspec(dllimport) DWORD __stdcall GetFileType(HANDLE);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE);
__declspec(dllimport) DWORD __stdcall GetLastError(void);

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

#define INVALID_HANDLE_VALUE ((HANDLE)(unsigned long)0xFFFFFFFFu)
#define INVALID_SET_FILE_POINTER 0xFFFFFFFFu
#define GENERIC_READ 0x80000000u
#define OPEN_EXISTING 3u
#define FILE_BEGIN 0u
#define FILE_END 2u
#define FILE_TYPE_DISK 1u
#define ERROR_INVALID_PARAMETER 87u

static int IsOpaqueFileHandle(HANDLE handle)
{
    const unsigned raw = (unsigned)(unsigned long)handle;
    const unsigned tag = raw & 0xFFFu;
    const unsigned generation = raw >> 12;
    return raw <= 0x7FFFFFFFu && generation != 0u && tag >= 0x100u && tag < 0x110u;
}

/*
 * Real file I/O against the ramfs file every trusted-root process
 * sees. Unlike the rest of this image — which only proves the IAT
 * resolves — every assertion below pins observable kernel state:
 * the opaque handle identity, the cursor SetFilePointer claims to have moved,
 * the short read that proves it moved there, and the fact that
 * CloseHandle actually frees the slot.
 *
 * Deliberately relational, not byte-exact: the file's contents are
 * ramfs.cpp's business, so asserting them here would make this test
 * fail for the wrong reason when that string changes.
 *
 * Returns 0 on success, or the number of the step that failed.
 */
static int FileIoProbe(void)
{
    const char* kPath = "/etc/version";
    char buf[16];
    DWORD hi = 0;
    DWORD got = 0;
    DWORD size;
    HANDLE f;

    f = CreateFileA(kPath, GENERIC_READ, 0, (void*)0, OPEN_EXISTING, 0, (HANDLE)0);
    if (f == INVALID_HANDLE_VALUE)
        return 1;
    /* The low tag selects the file slot; the non-zero high generation
     * proves this is the new stale-safe ABI rather than the legacy raw slot. */
    if (!IsOpaqueFileHandle(f))
        return 2;
    if (GetFileType(f) != FILE_TYPE_DISK)
        return 3;

    size = GetFileSize(f, &hi);
    if (size == 0xFFFFFFFFu || size <= 8 || hi != 0)
        return 4;

    if (!ReadFile(f, buf, 8, &got, (void*)0) || got != 8)
        return 5;

    /* Backwards seek from EOF. The 32-bit syscall ABI zero-extends
     * its arguments, so this only lands correctly because the DLL
     * resolves the negative distance to an absolute offset first. */
    if (SetFilePointer(f, -4, (int*)0, FILE_END) != size - 4)
        return 6;
    /* ...and the short read proves the cursor really is at size-4,
     * not merely that the call returned a plausible number. */
    if (!ReadFile(f, buf, 8, &got, (void*)0) || got != 4)
        return 7;

    if (SetFilePointer(f, 0, (int*)0, FILE_BEGIN) != 0)
        return 8;
    /* Win32 rejects a negative distance from the start. */
    if (SetFilePointer(f, -1, (int*)0, FILE_BEGIN) != INVALID_SET_FILE_POINTER)
        return 9;

    if (!CloseHandle(f))
        return 10;
    /* The handle slot must actually be gone. Before the CloseHandle
     * wrong-syscall fix (it dispatched SYS_STAT, not SYS_FILE_CLOSE)
     * this read still succeeded. */
    if (ReadFile(f, buf, 4, &got, (void*)0))
        return 11;

    /* A miss must be an honest failure, not a bogus handle. */
    if (CreateFileA("/no/such/file", GENERIC_READ, 0, (void*)0, OPEN_EXISTING, 0, (HANDLE)0) != INVALID_HANDLE_VALUE)
        return 12;

    /* Unknown creation dispositions fail instead of silently behaving
     * as OPEN_EXISTING. */
    if (CreateFileA(kPath, GENERIC_READ, 0, (void*)0, 99u, 0, (HANDLE)0) != INVALID_HANDLE_VALUE)
        return 13;
    if (GetLastError() != ERROR_INVALID_PARAMETER)
        return 14;

    return 0;
}

#define PROCESS_HEAP_VA 0x50000000u

/*
 * Heap / timing / module-resolution probe.
 *
 * Every one of these exports called the WRONG syscall until
 * 2026-07-26 (Sleep->SYS_HEAP_ALLOC, GetTickCount->SYS_WIN_GET_RECT,
 * HeapAlloc->SYS_WIN_SET_TEXT, HeapFree->SYS_WIN_TIMER_SET,
 * GetProcAddress->SYS_WIN_SET_CAPTURE), and the old "kernel32 ok"
 * line below still printed, because it only did `if (mem) {...}` —
 * a NULL allocation skipped the body and reported success.
 *
 * So every assertion here is written to FAIL against the old
 * behaviour, not merely to exercise the call.
 *
 * Returns 0 on success, or the number of the step that failed.
 */
static int HeapTimeProbe(void)
{
    HANDLE heap;
    unsigned char* p;
    unsigned char* q;
    unsigned sz;
    DWORD t0;
    DWORD t1;
    void* fn;
    unsigned i;

    /* The heap handle is the heap's base VA — Win32HeapResolveHandle
     * only accepts proc->heap_base / 0 / kWin32HeapVa. The old
     * 0x12340000 sentinel resolved to nothing. */
    heap = GetProcessHeap();
    if ((unsigned long)heap != PROCESS_HEAP_VA)
        return 1;

    /* Real allocation: must be non-NULL and writable. */
    p = (unsigned char*)HeapAlloc(heap, 0, 256);
    if (p == (unsigned char*)0)
        return 2;
    for (i = 0; i < 256; ++i)
        p[i] = (unsigned char)(i & 0xFF);

    /* HeapSize used to be hardcoded to 0. */
    sz = HeapSize(heap, 0, p);
    if (sz < 256)
        return 3;

    /* HeapReAlloc used to allocate a fresh block and NOT copy,
     * silently losing the caller's data on every CRT realloc. */
    q = (unsigned char*)HeapReAlloc(heap, 0, p, 512);
    if (q == (unsigned char*)0)
        return 4;
    for (i = 0; i < 256; ++i)
        if (q[i] != (unsigned char)(i & 0xFF))
            return 5; /* contents did not survive the grow */
    if (HeapSize(heap, 0, q) < 512)
        return 6;
    if (!HeapFree(heap, 0, q))
        return 7;

    /* HEAP_ZERO_MEMORY (0x8) is honoured in the DLL. */
    p = (unsigned char*)HeapAlloc(heap, 0x8, 64);
    if (p == (unsigned char*)0)
        return 8;
    for (i = 0; i < 64; ++i)
        if (p[i] != 0)
            return 9;
    HeapFree(heap, 0, p);

    /* Sleep must actually block, and GetTickCount must report
     * milliseconds that advance. Before the fix Sleep returned
     * immediately and GetTickCount returned a constant status flag,
     * so the delta was 0 — this is the discriminating assertion.
     * Tick granularity is 10 ms, so a 50 ms sleep must show at
     * least one tick. */
    t0 = GetTickCount();
    Sleep(50);
    t1 = GetTickCount();
    if (t1 < t0)
        return 10; /* time went backwards */
    if (t1 - t0 < 10)
        return 11; /* Sleep did not block / tick did not advance */

    /* GetProcAddress must resolve a real export from a real module.
     * Before the fix it grabbed mouse capture and returned an HWND
     * cast to FARPROC. */
    fn = GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "Sleep");
    if (fn == (void*)0)
        return 12;
    /* A miss must be an honest NULL, not a captured-window handle. */
    if (GetProcAddress(GetModuleHandleA("KERNEL32.dll"), "NoSuchExportZZ") != (void*)0)
        return 13;

    return 0;
}

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

    /* kernel32: GetProcessHeap + HeapAlloc + HeapFree round-trip.
     * The allocation must succeed — this used to be wrapped in
     * `if (mem)`, which let a totally broken HeapAlloc report
     * success. HeapTimeProbe below asserts the rest. */
    HANDLE heap = GetProcessHeap();
    void* mem = HeapAlloc(heap, 0, 256);
    if (!mem)
    {
        say("[pe32-rich] kernel32 FAIL HeapAlloc\r\n");
        say("[ring3-pe32-rich] FAIL kernel32-heap\r\n");
        ExitProcess(1);
    }
    memset(mem, 0xAA, 256);
    HeapFree(heap, 0, mem);
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

    /* kernel32 heap / timing / module resolution — five exports that
     * called the wrong syscall until 2026-07-26. */
    {
        const int step = HeapTimeProbe();
        if (step != 0)
        {
            char msg[] = "[pe32-rich] kernel32-heaptime FAIL step=NN\r\n";
            msg[40] = (char)('0' + (step / 10));
            msg[41] = (char)('0' + (step % 10));
            say(msg);
            say("[ring3-pe32-rich] FAIL kernel32-heaptime\r\n");
            ExitProcess(1);
        }
        say("[pe32-rich] kernel32-heaptime ok\r\n");
    }

    /* kernel32 file I/O — the only block here that asserts real
     * kernel semantics rather than "the IAT resolved". */
    {
        const int step = FileIoProbe();
        if (step != 0)
        {
            char msg[] = "[pe32-rich] kernel32-fileio FAIL step=NN\r\n";
            msg[38] = (char)('0' + (step / 10));
            msg[39] = (char)('0' + (step % 10));
            say(msg);
            say("[ring3-pe32-rich] FAIL kernel32-fileio\r\n");
            ExitProcess(1);
        }
        say("[pe32-rich] kernel32-fileio ok\r\n");
    }

    say("[pe32-rich] all 13 DLLs exercised — exit rc=0x42\r\n");
    say("[ring3-pe32-rich] PASS\r\n");
    ExitProcess(0x42);
}
