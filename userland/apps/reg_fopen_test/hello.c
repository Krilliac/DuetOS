/*
 * userland/apps/reg_fopen_test/hello.c
 *
 * End-to-end test. This PE exercises two
 * subsystems that upgraded from "return stub" to
 * "real implementation":
 *
 *   1. The real in-memory registry in advapi32.dll. Looks up
 *      HKLM\Software\Microsoft\Windows NT\CurrentVersion +
 *      queries "ProductName" (REG_SZ). Expects "DuetOS".
 *
 *   2. The real fopen / fread / fclose in ucrtbase.dll.
 *      Opens /bin/hello.exe (a freestanding ~2 KiB ramfs PE
 *      that has been in the tree since the ramfs landed),
 *      reads the first 2 bytes, and checks they're "MZ" — the
 *      DOS PE magic.
 *
 * Exit code encodes which checks passed:
 *   0x00000000 — everything passed
 *   0x00000001 — registry open failed
 *   0x00000002 — registry query failed
 *   0x00000003 — registry value was not "DuetOS"
 *   0x00000011 — fopen failed
 *   0x00000012 — fread failed
 *   0x00000013 — bytes weren't "MZ"
 *
 * On success also calls ExitProcess(0) which prints
 * `[I] sys : exit rc val=0x0` — easy to spot in the live boot log.
 */

typedef int BOOL;
typedef unsigned int UINT;
typedef unsigned int DWORD;
typedef long LONG;
typedef void* HANDLE;
typedef HANDLE HKEY;
typedef HKEY* PHKEY;
typedef unsigned long long size_t;

typedef struct ucrt_FILE
{
    long long handle;
    int eof;
    int err;
} FILE;

#define HKEY_LOCAL_MACHINE ((HKEY)0x80000002)

#define ERROR_SUCCESS 0L

__declspec(dllimport) LONG __stdcall RegOpenKeyExA(HKEY hKey, const char* subkey, DWORD opts, DWORD access,
                                                   PHKEY result);
__declspec(dllimport) LONG __stdcall RegQueryValueExA(HKEY hKey, const char* name, DWORD* reserved, DWORD* type,
                                                      unsigned char* data, DWORD* cb);
__declspec(dllimport) LONG __stdcall RegCloseKey(HKEY hKey);

__declspec(dllimport) FILE* __cdecl fopen(const char* path, const char* mode);
__declspec(dllimport) size_t __cdecl fread(void* ptr, size_t sz, size_t nmemb, FILE* f);
__declspec(dllimport) int __cdecl fclose(FILE* f);
__declspec(dllimport) int __cdecl printf(const char* fmt, ...);

__declspec(dllimport) void __stdcall ExitProcess(UINT code);

static int ascii_eq(const char* a, const char* b)
{
    while (*a && *b && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == *b;
}

void _start(void)
{
    /* --- Registry test --- */
    HKEY hk = (HKEY)0;
    LONG ro = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", 0, 0x20019, &hk);
    if (ro != ERROR_SUCCESS)
    {
        printf("[reg-fopen-test] RegOpenKeyEx failed rc=%ld\n", ro);
        ExitProcess(0x00000001);
    }

    char name_buf[32];
    DWORD name_cb = sizeof(name_buf);
    DWORD type = 0;
    LONG rq = RegQueryValueExA(hk, "ProductName", 0, &type, (unsigned char*)name_buf, &name_cb);
    if (rq != ERROR_SUCCESS)
    {
        printf("[reg-fopen-test] RegQueryValueEx failed rc=%ld\n", rq);
        ExitProcess(0x00000002);
    }
    printf("[reg-fopen-test] ProductName=\"%s\" (type=%u, size=%u)\n", name_buf, type, name_cb);
    if (!ascii_eq(name_buf, "DuetOS"))
        ExitProcess(0x00000003);

    RegCloseKey(hk);

    /* --- fopen + fread test --- */
    FILE* f = fopen("/bin/hello.exe", "rb");
    if (!f)
    {
        printf("[reg-fopen-test] fopen(/bin/hello.exe) returned NULL\n");
        ExitProcess(0x00000011);
    }
    unsigned char mz[2] = {0, 0};
    size_t got = fread(mz, 1, 2, f);
    if (got != 2)
    {
        printf("[reg-fopen-test] fread got %u bytes, expected 2\n", (unsigned)got);
        fclose(f);
        ExitProcess(0x00000012);
    }
    printf("[reg-fopen-test] /bin/hello.exe first two bytes: 0x%02x 0x%02x\n", mz[0], mz[1]);
    if (mz[0] != 'M' || mz[1] != 'Z')
    {
        fclose(f);
        ExitProcess(0x00000013);
    }
    fclose(f);

    printf("[reg-fopen-test] all checks passed\n");
    ExitProcess(0);
}
