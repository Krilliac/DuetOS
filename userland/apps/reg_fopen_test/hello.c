/*
 * userland/apps/reg_fopen_test/hello.c
 *
 * End-to-end test. This PE exercises three
 * subsystems that upgraded from "return stub" to
 * "real implementation":
 *
 *   1. The real in-memory registry in advapi32.dll. Looks up
 *      HKLM\Software\Microsoft\Windows NT\CurrentVersion +
 *      queries "ProductName" (REG_SZ). Expects "DuetOS".
 *
 *   2. ntdll.dll's NtOpenKey + NtQueryValueKey going directly
 *      to SYS_REGISTRY (kernel-side static tree). Same key,
 *      same value — but bypasses advapi32 entirely so the
 *      kernel-side tree is exercised end-to-end through the
 *      Win32 NT ABI.
 *
 *   3. The real fopen / fread / fclose in ucrtbase.dll.
 *      Opens /bin/hello.exe (a freestanding ~2 KiB ramfs PE
 *      that has been in the tree since the ramfs landed),
 *      reads the first 2 bytes, and checks they're "MZ" — the
 *      DOS PE magic.
 *
 * Exit code encodes which checks passed:
 *   0x00000000 — everything passed
 *   0x00000001 — advapi32 RegOpenKeyEx failed
 *   0x00000002 — advapi32 RegQueryValueEx failed
 *   0x00000003 — advapi32 ProductName != "DuetOS"
 *   0x00000004 — ntdll NtOpenKey failed
 *   0x00000005 — ntdll NtQueryValueKey failed
 *   0x00000006 — ntdll ProductName != "DuetOS"
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
typedef unsigned long ULONG;
typedef long LONG;
typedef unsigned long NTSTATUS;
typedef unsigned short USHORT;
typedef unsigned short wchar_t16;
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

/* NT registry surface — only what this test uses. */
typedef struct
{
    USHORT Length;
    USHORT MaximumLength;
    wchar_t16* Buffer;
} UNICODE_STRING;

typedef struct
{
    ULONG Length;
    HANDLE RootDirectory;
    UNICODE_STRING* ObjectName;
    ULONG Attributes;
    void* SecurityDescriptor;
    void* SecurityQualityOfService;
} OBJECT_ATTRIBUTES;

#define KeyValuePartialInformation 2

__declspec(dllimport) LONG __stdcall RegOpenKeyExA(HKEY hKey, const char* subkey, DWORD opts, DWORD access,
                                                   PHKEY result);
__declspec(dllimport) LONG __stdcall RegQueryValueExA(HKEY hKey, const char* name, DWORD* reserved, DWORD* type,
                                                      unsigned char* data, DWORD* cb);
__declspec(dllimport) LONG __stdcall RegCloseKey(HKEY hKey);

__declspec(dllimport) NTSTATUS __stdcall NtOpenKey(HANDLE* KeyHandle, ULONG DesiredAccess, OBJECT_ATTRIBUTES* attrs);
__declspec(dllimport) NTSTATUS __stdcall NtQueryValueKey(HANDLE KeyHandle, UNICODE_STRING* ValueName, ULONG InfoClass,
                                                         void* KeyValueInformation, ULONG Length, ULONG* ResultLength);
__declspec(dllimport) NTSTATUS __stdcall NtClose(HANDLE h);

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

    /* --- ntdll NtOpenKey + NtQueryValueKey test --- */
    /* Build the wide registry path:
     *   "\Registry\Machine\Software\Microsoft\Windows NT\CurrentVersion"
     * — same key the advapi32 path opened, but routed through the NT
     * ABI directly. v0 ntdll resolves the leading "\Registry\Machine\"
     * prefix to HKEY_LOCAL_MACHINE before crossing the syscall gate. */
    static wchar_t16 nt_path[] = {'\\', 'R',  'e', 'g', 'i',  's', 't', 'r', 'y', '\\', 'M',  'a', 'c', 'h', 'i', 'n',
                                  'e',  '\\', 'S', 'o', 'f',  't', 'w', 'a', 'r', 'e',  '\\', 'M', 'i', 'c', 'r', 'o',
                                  's',  'o',  'f', 't', '\\', 'W', 'i', 'n', 'd', 'o',  'w',  's', ' ', 'N', 'T', '\\',
                                  'C',  'u',  'r', 'r', 'e',  'n', 't', 'V', 'e', 'r',  's',  'i', 'o', 'n', 0};
    UNICODE_STRING nt_path_us;
    nt_path_us.Length = (USHORT)((sizeof(nt_path) / 2 - 1) * 2);
    nt_path_us.MaximumLength = (USHORT)sizeof(nt_path);
    nt_path_us.Buffer = nt_path;

    OBJECT_ATTRIBUTES attrs;
    attrs.Length = (ULONG)sizeof(attrs);
    attrs.RootDirectory = (HANDLE)0;
    attrs.ObjectName = &nt_path_us;
    attrs.Attributes = 0;
    attrs.SecurityDescriptor = (void*)0;
    attrs.SecurityQualityOfService = (void*)0;

    HANDLE nt_hk = (HANDLE)0;
    NTSTATUS no = NtOpenKey(&nt_hk, 0x20019, &attrs);
    if (no != 0)
    {
        printf("[reg-fopen-test] NtOpenKey failed status=0x%08lx\n", no);
        ExitProcess(0x00000004);
    }

    static wchar_t16 nt_value[] = {'P', 'r', 'o', 'd', 'u', 'c', 't', 'N', 'a', 'm', 'e', 0};
    UNICODE_STRING nt_value_us;
    nt_value_us.Length = (USHORT)((sizeof(nt_value) / 2 - 1) * 2);
    nt_value_us.MaximumLength = (USHORT)sizeof(nt_value);
    nt_value_us.Buffer = nt_value;

    /* KEY_VALUE_PARTIAL_INFORMATION fits "DuetOS\0" (7 B data) + 12 B
     * header in 32 bytes with headroom. */
    unsigned char nt_buf[32] = {0};
    ULONG nt_len = 0;
    NTSTATUS nq = NtQueryValueKey(nt_hk, &nt_value_us, KeyValuePartialInformation, nt_buf, sizeof(nt_buf), &nt_len);
    if (nq != 0)
    {
        printf("[reg-fopen-test] NtQueryValueKey failed status=0x%08lx\n", nq);
        NtClose(nt_hk);
        ExitProcess(0x00000005);
    }
    /* Header layout: u32 TitleIndex; u32 Type; u32 DataLength; u8 Data[]. */
    const char* nt_data = (const char*)(nt_buf + 12);
    printf("[reg-fopen-test] NtQueryValueKey ProductName=\"%s\" (result_len=%lu)\n", nt_data, nt_len);
    if (!ascii_eq(nt_data, "DuetOS"))
    {
        NtClose(nt_hk);
        ExitProcess(0x00000006);
    }
    NtClose(nt_hk);

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
