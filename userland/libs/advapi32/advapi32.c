/*
 * userland/libs/advapi32/advapi32.c
 *
 * Freestanding CustomOS advapi32.dll. 25 exports:
 *  - Registry (14): all report "key/value not found" or
 *    "invalid handle"; mostly ERROR_FILE_NOT_FOUND (= 2).
 *  - Token/privilege (4): pretend success (OpenProcessToken,
 *    AdjustTokenPrivileges, LookupPrivilegeValueA/W).
 *  - User name (2): return "CUSTOMOS\\user".
 *  - SystemFunction036 (RtlGenRandom): fill buffer with a
 *    deterministic counter. No real entropy in v0.
 *
 * Build: tools/build-advapi32-dll.sh at /base:0x100A0000.
 */

typedef int           BOOL;
typedef unsigned int  DWORD;
typedef void*         HANDLE;
typedef unsigned long LONG;
typedef unsigned long LSTATUS; /* 32-bit Win32 error code */

#define ERROR_SUCCESS           0UL
#define ERROR_FILE_NOT_FOUND    2UL
#define ERROR_INVALID_HANDLE    6UL
#define ERROR_MORE_DATA         234UL

typedef unsigned short wchar_t16;

/* ------------------------------------------------------------------
 * Registry — every operation reports "not found" or "not
 * supported" in v0. Callers that check return codes handle
 * this gracefully.
 * ------------------------------------------------------------------ */

__declspec(dllexport) LSTATUS RegOpenKeyExA(HANDLE hKey, const char* subkey, DWORD opts, DWORD access, HANDLE* out)
{
    (void) hKey;
    (void) subkey;
    (void) opts;
    (void) access;
    if (out != (HANDLE*) 0)
        *out = (HANDLE) 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegOpenKeyExW(HANDLE hKey, const wchar_t16* subkey, DWORD opts, DWORD access,
                                           HANDLE* out)
{
    (void) hKey;
    (void) subkey;
    (void) opts;
    (void) access;
    if (out != (HANDLE*) 0)
        *out = (HANDLE) 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegOpenKeyA(HANDLE hKey, const char* subkey, HANDLE* out)
{
    return RegOpenKeyExA(hKey, subkey, 0, 0, out);
}

__declspec(dllexport) LSTATUS RegOpenKeyW(HANDLE hKey, const wchar_t16* subkey, HANDLE* out)
{
    return RegOpenKeyExW(hKey, subkey, 0, 0, out);
}

__declspec(dllexport) LSTATUS RegCloseKey(HANDLE hKey)
{
    (void) hKey;
    return ERROR_SUCCESS; /* no-op close */
}

__declspec(dllexport) LSTATUS RegCreateKeyW(HANDLE hKey, const wchar_t16* subkey, HANDLE* out)
{
    (void) hKey;
    (void) subkey;
    if (out != (HANDLE*) 0)
        *out = (HANDLE) 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegCreateKeyExW(HANDLE hKey, const wchar_t16* subkey, DWORD reserved,
                                             const wchar_t16* cls, DWORD opts, DWORD access, void* sec, HANDLE* out,
                                             DWORD* disp)
{
    (void) hKey;
    (void) subkey;
    (void) reserved;
    (void) cls;
    (void) opts;
    (void) access;
    (void) sec;
    if (out != (HANDLE*) 0)
        *out = (HANDLE) 0;
    if (disp != (DWORD*) 0)
        *disp = 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegDeleteKeyW(HANDLE hKey, const wchar_t16* subkey)
{
    (void) hKey;
    (void) subkey;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegDeleteValueW(HANDLE hKey, const wchar_t16* name)
{
    (void) hKey;
    (void) name;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegEnumKeyW(HANDLE hKey, DWORD idx, wchar_t16* name, DWORD cb)
{
    (void) hKey;
    (void) idx;
    (void) name;
    (void) cb;
    return ERROR_FILE_NOT_FOUND; /* "no more keys" */
}

__declspec(dllexport) LSTATUS RegEnumKeyExW(HANDLE hKey, DWORD idx, wchar_t16* name, DWORD* cb, DWORD* reserved,
                                           wchar_t16* cls, DWORD* cls_cb, void* last_write)
{
    (void) hKey;
    (void) idx;
    (void) name;
    (void) cb;
    (void) reserved;
    (void) cls;
    (void) cls_cb;
    (void) last_write;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegEnumValueW(HANDLE hKey, DWORD idx, wchar_t16* name, DWORD* name_cb, DWORD* reserved,
                                           DWORD* type, unsigned char* data, DWORD* data_cb)
{
    (void) hKey;
    (void) idx;
    (void) name;
    (void) name_cb;
    (void) reserved;
    (void) type;
    (void) data;
    (void) data_cb;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegQueryValueA(HANDLE hKey, const char* subkey, char* value, LONG* cb)
{
    (void) hKey;
    (void) subkey;
    (void) value;
    if (cb != (LONG*) 0)
        *cb = 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegQueryValueW(HANDLE hKey, const wchar_t16* subkey, wchar_t16* value, LONG* cb)
{
    (void) hKey;
    (void) subkey;
    (void) value;
    if (cb != (LONG*) 0)
        *cb = 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegQueryValueExA(HANDLE hKey, const char* name, DWORD* reserved, DWORD* type,
                                              unsigned char* data, DWORD* cb)
{
    (void) hKey;
    (void) name;
    (void) reserved;
    (void) type;
    (void) data;
    if (cb != (DWORD*) 0)
        *cb = 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegQueryValueExW(HANDLE hKey, const wchar_t16* name, DWORD* reserved, DWORD* type,
                                              unsigned char* data, DWORD* cb)
{
    (void) hKey;
    (void) name;
    (void) reserved;
    (void) type;
    (void) data;
    if (cb != (DWORD*) 0)
        *cb = 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegSetValueW(HANDLE hKey, const wchar_t16* subkey, DWORD type,
                                          const wchar_t16* data, DWORD cb)
{
    (void) hKey;
    (void) subkey;
    (void) type;
    (void) data;
    (void) cb;
    return ERROR_SUCCESS; /* pretend it worked */
}

__declspec(dllexport) LSTATUS RegSetValueExW(HANDLE hKey, const wchar_t16* name, DWORD reserved, DWORD type,
                                            const unsigned char* data, DWORD cb)
{
    (void) hKey;
    (void) name;
    (void) reserved;
    (void) type;
    (void) data;
    (void) cb;
    return ERROR_SUCCESS;
}

/* ------------------------------------------------------------------
 * Tokens / privileges — pretend success. The caller has no way
 * to distinguish a successful privilege-adjust from ours.
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL OpenProcessToken(HANDLE hProcess, DWORD access, HANDLE* token)
{
    (void) hProcess;
    (void) access;
    if (token != (HANDLE*) 0)
        *token = (HANDLE) 0x1000; /* Sentinel; caller only checks non-NULL */
    return 1;
}

__declspec(dllexport) BOOL AdjustTokenPrivileges(HANDLE token, BOOL disable_all, void* new_state, DWORD buf_len,
                                                void* prev_state, DWORD* ret_len)
{
    (void) token;
    (void) disable_all;
    (void) new_state;
    (void) buf_len;
    (void) prev_state;
    if (ret_len != (DWORD*) 0)
        *ret_len = 0;
    return 1;
}

__declspec(dllexport) BOOL LookupPrivilegeValueA(const char* system, const char* name, long long* luid)
{
    (void) system;
    (void) name;
    if (luid != (long long*) 0)
        *luid = 1; /* Any non-zero LUID will do */
    return 1;
}

__declspec(dllexport) BOOL LookupPrivilegeValueW(const wchar_t16* system, const wchar_t16* name, long long* luid)
{
    (void) system;
    (void) name;
    if (luid != (long long*) 0)
        *luid = 1;
    return 1;
}

/* ------------------------------------------------------------------
 * User name — fixed "CUSTOMOS\user".
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL GetUserNameA(char* buffer, DWORD* cb)
{
    static const char name[] = "user";
    DWORD             want   = sizeof(name); /* includes NUL */
    if (cb == (DWORD*) 0)
        return 0;
    if (buffer == (char*) 0 || *cb < want)
    {
        *cb = want;
        return 0;
    }
    for (DWORD i = 0; i < want; ++i)
        buffer[i] = name[i];
    *cb = want;
    return 1;
}

__declspec(dllexport) BOOL GetUserNameW(wchar_t16* buffer, DWORD* cb)
{
    static const char name[] = "user";
    DWORD             want   = sizeof(name); /* same count for wide (each wchar is 1 ASCII byte) */
    if (cb == (DWORD*) 0)
        return 0;
    if (buffer == (wchar_t16*) 0 || *cb < want)
    {
        *cb = want;
        return 0;
    }
    for (DWORD i = 0; i < want; ++i)
        buffer[i] = (wchar_t16) (unsigned char) name[i];
    *cb = want;
    return 1;
}

/* ------------------------------------------------------------------
 * SystemFunction036 — RtlGenRandom. Fill `buf` with `len`
 * bytes of "random" data. v0 uses a deterministic counter;
 * cryptographic callers MUST NOT rely on this for real keys.
 * ------------------------------------------------------------------ */

static unsigned long long g_rand_ctr = 0x9E3779B97F4A7C15ULL;

__declspec(dllexport) BOOL SystemFunction036(void* buf, DWORD len)
{
    unsigned char* p = (unsigned char*) buf;
    for (DWORD i = 0; i < len; ++i)
    {
        g_rand_ctr = g_rand_ctr * 6364136223846793005ULL + 1442695040888963407ULL;
        p[i]       = (unsigned char) (g_rand_ctr >> 56);
    }
    return 1;
}
