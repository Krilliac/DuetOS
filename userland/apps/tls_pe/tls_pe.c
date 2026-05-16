/*
 * tls_pe — verifies DuetOS PE-loader static-TLS + TLS-callback
 * support (roadmap T6-01).
 *
 * Freestanding PE (no CRT), so the IMAGE_TLS_DIRECTORY64 is
 * hand-authored: the symbol `_tls_used` is what lld/ld populate
 * the PE's TLS data directory from, independent of any CRT. We
 * point AddressOfCallBacks at our own explicit NULL-terminated
 * array so the layout is unambiguous (no .CRT$XL* merge-order
 * dependence).
 *
 * Two things are checked, both the exact mechanics MSVC-built
 * binaries (Chrome included) rely on:
 *
 *   1. The TLS callback runs BEFORE the entry point. It stamps a
 *      sentinel into a global; main verifies it.
 *   2. Static-TLS data is live: the loader copied the .tls
 *      template into a per-thread block and wired
 *      TEB.ThreadLocalStoragePointer (gs:[0x58]). We read it the
 *      same way compiler-emitted __declspec(thread) code does:
 *      block = *(void**)((*(void***)(gs:[0x58]))[_tls_index]);
 *      and check the template sentinel survived the copy.
 *
 * Exit code: 0 on full PASS, 1 on any FAIL.
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

/* .tls raw template. First 4 bytes are the sentinel 0xAABBCCDD
 * (little-endian) so a correct loader copy is observable. */
__attribute__((section(".tls"))) volatile unsigned char g_tls_template[8] = {0xDD, 0xCC, 0xBB, 0xAA, 0, 0, 0, 0};

/* Module TLS index. The loader writes 0 here (single module). */
ULONG _tls_index = 0xFFFFFFFFu;

static volatile DWORD g_cb_ran = 0;
static volatile DWORD g_cb_reason = 0xFFFFFFFFu;

static void __stdcall TlsCallback(PVOID inst, DWORD reason, PVOID resv)
{
    (void)inst;
    (void)resv;
    g_cb_reason = reason;
    if (reason == DLL_PROCESS_ATTACH)
        g_cb_ran = 0xC0DEu;
}

/* Explicit NULL-terminated callback array. */
PIMAGE_TLS_CALLBACK g_tls_cbs[2] = {TlsCallback, 0};

/* lld/ld fill IMAGE_DIRECTORY_ENTRY_TLS from the `_tls_used`
 * symbol. Fields are absolute VAs (relocated by the loader). */
const IMAGE_TLS_DIRECTORY64 _tls_used = {
    (ULONGLONG)(ULONG_PTR)&g_tls_template[0], /* StartAddressOfRawData */
    (ULONGLONG)(ULONG_PTR)&g_tls_template[8], /* EndAddressOfRawData   */
    (ULONGLONG)(ULONG_PTR)&_tls_index,        /* AddressOfIndex        */
    (ULONGLONG)(ULONG_PTR)&g_tls_cbs[0],      /* AddressOfCallBacks    */
    0,                                        /* SizeOfZeroFill        */
    0                                         /* Characteristics       */
};

void __cdecl mainCRTStartup(void)
{
    int fail = 0;
    Out("[tls_pe] starting\r\n");

    /* 1. TLS callback ran before entry? */
    if (g_cb_ran == 0xC0DEu && g_cb_reason == DLL_PROCESS_ATTACH)
    {
        Out("[tls_pe] tls-callback-before-entry: PASS\r\n");
    }
    else
    {
        Out("[tls_pe] tls-callback-before-entry: FAIL\r\n");
        fail = 1;
    }

    /* 2. Static-TLS data live via TEB.ThreadLocalStoragePointer.
     *    Mirrors compiler __declspec(thread) access exactly. */
    void** tls_array = (void**)__readgsqword(0x58);
    if (tls_array == 0)
    {
        Out("[tls_pe] static-tls: FAIL (TEB+0x58 null)\r\n");
        fail = 1;
    }
    else
    {
        unsigned char* block = (unsigned char*)tls_array[_tls_index];
        if (block == 0)
        {
            Out("[tls_pe] static-tls: FAIL (slot null)\r\n");
            fail = 1;
        }
        else
        {
            unsigned int got = (unsigned int)block[0] | ((unsigned int)block[1] << 8) | ((unsigned int)block[2] << 16) |
                               ((unsigned int)block[3] << 24);
            if (got == 0xAABBCCDDu)
            {
                Out("[tls_pe] static-tls-template-copied: PASS\r\n");
            }
            else
            {
                Out("[tls_pe] static-tls-template-copied: FAIL\r\n");
                fail = 1;
            }
        }
    }

    Out(fail ? "[tls_pe] RESULT FAIL\r\n" : "[tls_pe] RESULT PASS\r\n");
    Out("[tls_pe] done\r\n");
    ExitProcess(fail ? 1u : 0u);
}
