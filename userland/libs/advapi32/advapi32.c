/*
 * userland/libs/advapi32/advapi32.c
 *
 * Freestanding DuetOS advapi32.dll. Stage-2 slice 34
 * upgrades this from the all-stubs slice-27 version to a real
 * in-memory registry:
 *
 *   - HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, HKEY_CLASSES_ROOT,
 *     HKEY_USERS, HKEY_CURRENT_CONFIG — the five standard
 *     predefined HKEY sentinels as Win32 API contract.
 *
 *   - A static tree of well-known keys + values that real-world
 *     PEs frequently query:
 *       HKLM\Software\Microsoft\Windows NT\CurrentVersion
 *         ProductName      = "DuetOS"
 *         CurrentVersion   = "10.0"
 *         CurrentBuild     = "19041"
 *         CurrentBuildNumber = "19041"
 *       HKLM\Software\Microsoft\Windows\CurrentVersion
 *         (same subset — some programs look here instead)
 *       HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings
 *         ProxyEnable      = DWORD 0
 *       HKCU\Volatile Environment
 *         USERNAME         = "user"
 *
 *   - Real RegOpenKeyExA/W, RegQueryValueExA/W, RegCloseKey
 *     walking the static tree. Unknown keys return
 *     ERROR_FILE_NOT_FOUND; open succeeds on any known prefix
 *     and returns a 16-bit integer handle that RegClose then
 *     accepts.
 *
 *   - RegSetValue*, RegCreateKey*, RegDeleteKey/Value — still
 *     pretend-success (read-only registry in v0); callers
 *     that write keys get told "yes it worked" but the value
 *     isn't stored.
 *
 * Remaining non-registry entries (tokens, GetUserName,
 * SystemFunction036) kept from slice 27 unchanged.
 *
 * Build: tools/build-advapi32-dll.sh.
 */

typedef int                BOOL;
typedef unsigned int       DWORD;
typedef void*              HANDLE;
typedef unsigned long long UINT_PTR;
typedef unsigned short     wchar_t16;
typedef unsigned long      LONG;
typedef unsigned long      LSTATUS; /* 32-bit Win32 error code */

#define ERROR_SUCCESS           0UL
#define ERROR_FILE_NOT_FOUND    2UL
#define ERROR_INVALID_HANDLE    6UL
#define ERROR_MORE_DATA         234UL

/* Standard predefined HKEY values (per Win32 API). Casting a
 * sentinel integer to HKEY matches what Windows hands out and
 * what every Win32 program compares against. */
#define HKEY_CLASSES_ROOT   ((HANDLE) (UINT_PTR) 0x80000000ULL)
#define HKEY_CURRENT_USER   ((HANDLE) (UINT_PTR) 0x80000001ULL)
#define HKEY_LOCAL_MACHINE  ((HANDLE) (UINT_PTR) 0x80000002ULL)
#define HKEY_USERS          ((HANDLE) (UINT_PTR) 0x80000003ULL)
#define HKEY_CURRENT_CONFIG ((HANDLE) (UINT_PTR) 0x80000005ULL)

/* Registry value types. */
#define REG_NONE        0UL
#define REG_SZ          1UL
#define REG_EXPAND_SZ   2UL
#define REG_BINARY      3UL
#define REG_DWORD       4UL
#define REG_MULTI_SZ    7UL
#define REG_QWORD       11UL

/* ------------------------------------------------------------------
 * Static in-memory registry tree.
 *
 * Each key has a canonical path (HKEY root + "\"-separated
 * subkey chain) and a list of named values. A real Windows
 * registry is a COW hive with millions of keys; v0 ships a
 * hand-curated set covering the startup-probe paths MSVC PEs
 * touch during init.
 *
 * Handles are small integers in [0x100, 0x100 + kKeyCount).
 * Predefined HKEYs (0x80000000+) are treated as "open handle
 * to the root of that hive" — callers that pass them directly
 * to RegQueryValueEx without first opening a subkey hit the
 * top-of-hive path.
 * ------------------------------------------------------------------ */

typedef struct RegValue
{
    const char*   name;       /* ASCII name (ASCII-only in our tree; RegQuery compares after wide->narrow strip) */
    DWORD         type;       /* REG_SZ / REG_DWORD / etc. */
    const void*   data;       /* Bytes */
    DWORD         size;       /* Byte count (for REG_SZ: includes trailing NUL pair for wide, or NUL for narrow) */
    unsigned long dword_imm;  /* Immediate value for REG_DWORD/REG_QWORD; `data` points at this slot */
} RegValue;

typedef struct RegKey
{
    HANDLE           root;           /* HKLM/HKCU/... */
    const char*      path;           /* Subkey path with '\\' separators */
    const RegValue*  values;         /* Array of named values */
    DWORD            value_count;
} RegKey;

/* DWORD immediates need storage so we can hand a pointer out.
 * File-local statics, zero-initialised explicitly. */
static DWORD g_reg_dword_proxy_enable = 0;
static DWORD g_reg_dword_version_major = 10;

static const RegValue k_hklm_winnt_values[] = {
    {"ProductName",        REG_SZ,    "DuetOS\0",           7,  0},
    {"CurrentVersion",     REG_SZ,    "10.0\0",             5,  0},
    {"CurrentBuild",       REG_SZ,    "19041\0",            6,  0},
    {"CurrentBuildNumber", REG_SZ,    "19041\0",            6,  0},
    {"BuildLab",           REG_SZ,    "19041.duetos\0",    13, 0},
    {"InstallationType",   REG_SZ,    "Client\0",           7,  0},
    {"ReleaseId",          REG_SZ,    "2004\0",             5,  0},
    {"EditionID",          REG_SZ,    "Professional\0",     13, 0},
    {"CurrentMajorVersionNumber", REG_DWORD, &g_reg_dword_version_major, 4, 10},
};

static const RegValue k_hkcu_internet_values[] = {
    {"ProxyEnable", REG_DWORD, &g_reg_dword_proxy_enable, 4, 0},
};

static const RegValue k_hkcu_volatile_env_values[] = {
    {"USERNAME", REG_SZ, "user\0", 5, 0},
    {"USERDOMAIN", REG_SZ, "DUETOS\0", 7, 0},
};

static const RegKey k_reg_keys[] = {
    /* Both Windows NT and Windows paths point at the same data —
     * different callers look in different places. */
    {HKEY_LOCAL_MACHINE,  "Software\\Microsoft\\Windows NT\\CurrentVersion", k_hklm_winnt_values,
     (DWORD) (sizeof(k_hklm_winnt_values) / sizeof(k_hklm_winnt_values[0]))},
    {HKEY_LOCAL_MACHINE,  "Software\\Microsoft\\Windows\\CurrentVersion", k_hklm_winnt_values,
     (DWORD) (sizeof(k_hklm_winnt_values) / sizeof(k_hklm_winnt_values[0]))},
    {HKEY_CURRENT_USER,   "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", k_hkcu_internet_values,
     (DWORD) (sizeof(k_hkcu_internet_values) / sizeof(k_hkcu_internet_values[0]))},
    {HKEY_CURRENT_USER,   "Volatile Environment", k_hkcu_volatile_env_values,
     (DWORD) (sizeof(k_hkcu_volatile_env_values) / sizeof(k_hkcu_volatile_env_values[0]))},
};

#define REG_KEY_COUNT (sizeof(k_reg_keys) / sizeof(k_reg_keys[0]))

/* Handle space: we hand out 0x100 + key_index. No-op close
 * on these; clients never see the integer, just treat HKEY as
 * opaque. */
#define REG_HANDLE_BASE 0x100UL

static const RegKey* reg_key_from_handle(HANDLE h)
{
    UINT_PTR v = (UINT_PTR) h;
    if (v < REG_HANDLE_BASE || v >= REG_HANDLE_BASE + REG_KEY_COUNT)
        return (const RegKey*) 0;
    return &k_reg_keys[v - REG_HANDLE_BASE];
}

/* Case-insensitive ASCII strcmp. Registry paths are case-
 * insensitive per Win32 contract. */
static int reg_ascii_casecmp(const char* a, const char* b)
{
    while (*a && *b)
    {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char) (ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char) (cb + ('a' - 'A'));
        if (ca != cb)
            return (int) (unsigned char) ca - (int) (unsigned char) cb;
        ++a;
        ++b;
    }
    return (int) (unsigned char) *a - (int) (unsigned char) *b;
}

/* Convert a UTF-16 subkey path to ASCII on a caller buffer.
 * Low-byte strip — good enough for all the ASCII keys we
 * serve. */
static void reg_w_to_a(const wchar_t16* src, char* dst, DWORD cap)
{
    DWORD i = 0;
    if (src)
    {
        while (i + 1 < cap && src[i])
        {
            dst[i] = (char) (src[i] & 0xFF);
            ++i;
        }
    }
    if (cap > 0)
        dst[i] = 0;
}

static const RegKey* reg_lookup_key_a(HANDLE root, const char* subkey)
{
    if (subkey == (const char*) 0)
        return (const RegKey*) 0;
    for (DWORD i = 0; i < REG_KEY_COUNT; ++i)
    {
        if (k_reg_keys[i].root != root)
            continue;
        if (reg_ascii_casecmp(k_reg_keys[i].path, subkey) == 0)
            return &k_reg_keys[i];
    }
    return (const RegKey*) 0;
}

static HANDLE reg_handle_for_key(const RegKey* k)
{
    if (!k)
        return (HANDLE) 0;
    UINT_PTR index = (UINT_PTR) (k - k_reg_keys);
    return (HANDLE) (UINT_PTR) (REG_HANDLE_BASE + index);
}

/* ------------------------------------------------------------------
 * Registry API (real, read-only)
 * ------------------------------------------------------------------ */

__declspec(dllexport) LSTATUS RegOpenKeyExA(HANDLE hKey, const char* subkey, DWORD opts, DWORD access, HANDLE* out)
{
    (void) opts;
    (void) access;
    if (out == (HANDLE*) 0)
        return ERROR_FILE_NOT_FOUND;
    *out                 = (HANDLE) 0;
    const RegKey* target = reg_lookup_key_a(hKey, subkey);
    if (!target)
        return ERROR_FILE_NOT_FOUND;
    *out = reg_handle_for_key(target);
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegOpenKeyExW(HANDLE hKey, const wchar_t16* subkey, DWORD opts, DWORD access,
                                           HANDLE* out)
{
    char abuf[256];
    reg_w_to_a(subkey, abuf, sizeof(abuf));
    return RegOpenKeyExA(hKey, abuf, opts, access, out);
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

static LSTATUS reg_query_value(const RegKey* key, const char* name, DWORD* type, unsigned char* data, DWORD* cb)
{
    if (!key)
        return ERROR_FILE_NOT_FOUND;
    for (DWORD i = 0; i < key->value_count; ++i)
    {
        const RegValue* v = &key->values[i];
        if (reg_ascii_casecmp(v->name, name) != 0)
            continue;
        if (type)
            *type = v->type;
        DWORD cap  = cb ? *cb : 0;
        DWORD want = v->size;
        if (cb)
            *cb = want;
        if (data == (unsigned char*) 0)
            return ERROR_SUCCESS; /* size-only query */
        if (cap < want)
            return ERROR_MORE_DATA;
        const unsigned char* src = (const unsigned char*) v->data;
        for (DWORD j = 0; j < want; ++j)
            data[j] = src[j];
        return ERROR_SUCCESS;
    }
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegQueryValueExA(HANDLE hKey, const char* name, DWORD* reserved, DWORD* type,
                                              unsigned char* data, DWORD* cb)
{
    (void) reserved;
    const RegKey* key = reg_key_from_handle(hKey);
    return reg_query_value(key, name ? name : "", type, data, cb);
}

__declspec(dllexport) LSTATUS RegQueryValueExW(HANDLE hKey, const wchar_t16* name, DWORD* reserved, DWORD* type,
                                              unsigned char* data, DWORD* cb)
{
    (void) reserved;
    const RegKey* key = reg_key_from_handle(hKey);
    char          abuf[128];
    reg_w_to_a(name, abuf, sizeof(abuf));
    return reg_query_value(key, abuf, type, data, cb);
}

/* Default-value queries — Win32 treats `NULL subkey + NULL
 * name` as "default value of this key". v0 reports "not set"
 * for every key. */
__declspec(dllexport) LSTATUS RegQueryValueA(HANDLE hKey, const char* subkey, char* value, LONG* cb)
{
    (void) hKey;
    (void) subkey;
    (void) value;
    if (cb)
        *cb = 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegQueryValueW(HANDLE hKey, const wchar_t16* subkey, wchar_t16* value, LONG* cb)
{
    (void) hKey;
    (void) subkey;
    (void) value;
    if (cb)
        *cb = 0;
    return ERROR_FILE_NOT_FOUND;
}

/* Write path — pretend-success. The registry is in-memory and
 * read-only in v0; claiming success keeps programs on their
 * happy-path writing behaviour, same as a FS-backed "wrote it"
 * cache flush that never hits disk. */

__declspec(dllexport) LSTATUS RegCreateKeyW(HANDLE hKey, const wchar_t16* subkey, HANDLE* out)
{
    (void) hKey;
    (void) subkey;
    if (out)
        *out = (HANDLE) 0x200; /* sentinel, read-only */
    return ERROR_SUCCESS;
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
    if (out)
        *out = (HANDLE) 0x200;
    if (disp)
        *disp = 2; /* REG_OPENED_EXISTING_KEY */
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegDeleteKeyW(HANDLE hKey, const wchar_t16* subkey)
{
    (void) hKey;
    (void) subkey;
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegDeleteValueW(HANDLE hKey, const wchar_t16* name)
{
    (void) hKey;
    (void) name;
    return ERROR_SUCCESS;
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
    const RegKey* key = reg_key_from_handle(hKey);
    (void) reserved;
    if (!key || idx >= key->value_count)
        return ERROR_FILE_NOT_FOUND;
    const RegValue* v = &key->values[idx];
    /* Write name in wide form. */
    DWORD name_cap = name_cb ? *name_cb : 0;
    DWORD name_len = 0;
    while (v->name[name_len])
        ++name_len;
    if (name_cb)
        *name_cb = name_len;
    if (name)
    {
        if (name_cap < name_len + 1)
            return ERROR_MORE_DATA;
        for (DWORD i = 0; i <= name_len; ++i)
            name[i] = (wchar_t16) (unsigned char) v->name[i];
    }
    if (type)
        *type = v->type;
    /* Copy data if buffer provided. */
    DWORD data_cap = data_cb ? *data_cb : 0;
    if (data_cb)
        *data_cb = v->size;
    if (data)
    {
        if (data_cap < v->size)
            return ERROR_MORE_DATA;
        const unsigned char* src = (const unsigned char*) v->data;
        for (DWORD i = 0; i < v->size; ++i)
            data[i] = src[i];
    }
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegSetValueW(HANDLE hKey, const wchar_t16* subkey, DWORD type,
                                          const wchar_t16* data, DWORD cb)
{
    (void) hKey;
    (void) subkey;
    (void) type;
    (void) data;
    (void) cb;
    return ERROR_SUCCESS;
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
 * Tokens / privileges — unchanged from slice 27 (pretend
 * success). GetUserName + SystemFunction036 likewise.
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL OpenProcessToken(HANDLE hProcess, DWORD access, HANDLE* token)
{
    (void) hProcess;
    (void) access;
    if (token != (HANDLE*) 0)
        *token = (HANDLE) 0x1000;
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
        *luid = 1;
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

__declspec(dllexport) BOOL GetUserNameA(char* buffer, DWORD* cb)
{
    static const char name[] = "user";
    DWORD             want   = sizeof(name);
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
    DWORD             want   = sizeof(name);
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
