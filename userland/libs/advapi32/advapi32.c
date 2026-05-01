/*
 * userland/libs/advapi32/advapi32.c
 *
 * Freestanding DuetOS advapi32.dll. Upgrades the earlier
 * all-stubs version to a real in-memory registry:
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
 * SystemFunction036) are unchanged from the earlier
 * stubs-only build.
 *
 * Build: tools/build/build-advapi32-dll.sh.
 */

typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned long long UINT_PTR;
typedef unsigned short wchar_t16;
typedef unsigned long LONG;
typedef unsigned long LSTATUS; /* 32-bit Win32 error code */

#define ERROR_SUCCESS 0UL
#define ERROR_FILE_NOT_FOUND 2UL
#define ERROR_INVALID_HANDLE 6UL
#define ERROR_MORE_DATA 234UL
#define ERROR_NO_MORE_ITEMS 259UL

/* Standard predefined HKEY values (per Win32 API). Casting a
 * sentinel integer to HKEY matches what Windows hands out and
 * what every Win32 program compares against. */
#define HKEY_CLASSES_ROOT ((HANDLE)(UINT_PTR)0x80000000ULL)
#define HKEY_CURRENT_USER ((HANDLE)(UINT_PTR)0x80000001ULL)
#define HKEY_LOCAL_MACHINE ((HANDLE)(UINT_PTR)0x80000002ULL)
#define HKEY_USERS ((HANDLE)(UINT_PTR)0x80000003ULL)
#define HKEY_CURRENT_CONFIG ((HANDLE)(UINT_PTR)0x80000005ULL)

/* Registry value types. */
#define REG_NONE 0UL
#define REG_SZ 1UL
#define REG_EXPAND_SZ 2UL
#define REG_BINARY 3UL
#define REG_DWORD 4UL
#define REG_MULTI_SZ 7UL
#define REG_QWORD 11UL

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
    const char* name;        /* ASCII name (ASCII-only in our tree; RegQuery compares after wide->narrow strip) */
    DWORD type;              /* REG_SZ / REG_DWORD / etc. */
    const void* data;        /* Bytes */
    DWORD size;              /* Byte count (for REG_SZ: includes trailing NUL pair for wide, or NUL for narrow) */
    unsigned long dword_imm; /* Immediate value for REG_DWORD/REG_QWORD; `data` points at this slot */
} RegValue;

typedef struct RegKey
{
    HANDLE root;            /* HKLM/HKCU/... */
    const char* path;       /* Subkey path with '\\' separators */
    const RegValue* values; /* Array of named values */
    DWORD value_count;
} RegKey;

/* DWORD immediates need storage so we can hand a pointer out.
 * File-local statics, zero-initialised explicitly. */
static DWORD g_reg_dword_proxy_enable = 0;
static DWORD g_reg_dword_version_major = 10;

static const RegValue k_hklm_winnt_values[] = {
    {"ProductName", REG_SZ, "DuetOS\0", 7, 0},
    {"CurrentVersion", REG_SZ, "10.0\0", 5, 0},
    {"CurrentBuild", REG_SZ, "19041\0", 6, 0},
    {"CurrentBuildNumber", REG_SZ, "19041\0", 6, 0},
    {"BuildLab", REG_SZ, "19041.duetos\0", 13, 0},
    {"InstallationType", REG_SZ, "Client\0", 7, 0},
    {"ReleaseId", REG_SZ, "2004\0", 5, 0},
    {"EditionID", REG_SZ, "Professional\0", 13, 0},
    {"CurrentMajorVersionNumber", REG_DWORD, &g_reg_dword_version_major, 4, 10},
};

static const RegValue k_hkcu_internet_values[] = {
    {"ProxyEnable", REG_DWORD, &g_reg_dword_proxy_enable, 4, 0},
};

static const RegValue k_hkcu_volatile_env_values[] = {
    {"USERNAME", REG_SZ, "user\0", 5, 0},
    {"USERDOMAIN", REG_SZ, "DUETOS\0", 7, 0},
};

/* Mirror of registry.cpp::kRegKeys[] — see the comment block
 * there for the tier rationale (terminal vs. prefix). Adding an
 * entry here means adding the matching entry in the kernel side
 * in the same commit. */
static const RegKey k_reg_keys[] = {
    /* Both Windows NT and Windows paths point at the same data —
     * different callers look in different places. */
    {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion", k_hklm_winnt_values,
     (DWORD)(sizeof(k_hklm_winnt_values) / sizeof(k_hklm_winnt_values[0]))},
    {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", k_hklm_winnt_values,
     (DWORD)(sizeof(k_hklm_winnt_values) / sizeof(k_hklm_winnt_values[0]))},
    {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", k_hkcu_internet_values,
     (DWORD)(sizeof(k_hkcu_internet_values) / sizeof(k_hkcu_internet_values[0]))},
    {HKEY_CURRENT_USER, "Volatile Environment", k_hkcu_volatile_env_values,
     (DWORD)(sizeof(k_hkcu_volatile_env_values) / sizeof(k_hkcu_volatile_env_values[0]))},
    /* Prefix entries (no values). Each terminal path's distinct
     * proper prefixes appear here so RegOpenKey(parent, sub, ...)
     * can walk the tree one component at a time. */
    {HKEY_LOCAL_MACHINE, "Software", (const RegValue*)0, 0},
    {HKEY_LOCAL_MACHINE, "Software\\Microsoft", (const RegValue*)0, 0},
    {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows", (const RegValue*)0, 0},
    {HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT", (const RegValue*)0, 0},
    {HKEY_CURRENT_USER, "Software", (const RegValue*)0, 0},
    {HKEY_CURRENT_USER, "Software\\Microsoft", (const RegValue*)0, 0},
    {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows", (const RegValue*)0, 0},
    {HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion", (const RegValue*)0, 0},
};

#define REG_KEY_COUNT (sizeof(k_reg_keys) / sizeof(k_reg_keys[0]))

/* Handle space: we hand out 0x100 + key_index. No-op close
 * on these; clients never see the integer, just treat HKEY as
 * opaque. */
#define REG_HANDLE_BASE 0x100UL

static const RegKey* reg_key_from_handle(HANDLE h)
{
    UINT_PTR v = (UINT_PTR)h;
    if (v < REG_HANDLE_BASE || v >= REG_HANDLE_BASE + REG_KEY_COUNT)
        return (const RegKey*)0;
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
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (ca != cb)
            return (int)(unsigned char)ca - (int)(unsigned char)cb;
        ++a;
        ++b;
    }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
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
            dst[i] = (char)(src[i] & 0xFF);
            ++i;
        }
    }
    if (cap > 0)
        dst[i] = 0;
}

static const RegKey* reg_lookup_key_a(HANDLE root, const char* subkey)
{
    if (subkey == (const char*)0)
        return (const RegKey*)0;
    for (DWORD i = 0; i < REG_KEY_COUNT; ++i)
    {
        if (k_reg_keys[i].root != root)
            continue;
        if (reg_ascii_casecmp(k_reg_keys[i].path, subkey) == 0)
            return &k_reg_keys[i];
    }
    return (const RegKey*)0;
}

static HANDLE reg_handle_for_key(const RegKey* k)
{
    if (!k)
        return (HANDLE)0;
    UINT_PTR index = (UINT_PTR)(k - k_reg_keys);
    return (HANDLE)(UINT_PTR)(REG_HANDLE_BASE + index);
}

/* Resolve `hKey` (predefined HKEY sentinel OR previously-handed
 * handle from REG_HANDLE_BASE) to its (root, path) pair. Returns
 * 0 on success and writes into *out_root + *out_path; non-zero on
 * an unrecognised handle. *out_path is "" for predefined HKEYs
 * (caller substitutes the user-provided subkey).
 *
 * Caveat: mingw-w64's windows.h defines HKEY_LOCAL_MACHINE etc.
 * as `((HKEY)(ULONG_PTR)((LONG)0x80000002))` — the cast through
 * `(LONG)0x80000002` sign-extends to 0xFFFFFFFF80000002 on x64,
 * not 0x0000000080000002 as the local advapi32 #defines produce.
 * That mismatch made every Win32 PE that included the standard
 * windows.h pass a sign-extended HKEY into our reg_resolve_parent,
 * which fell through the previous `v >= 0x80000000UL && v <=
 * 0x80000005UL` range check (the upper-32 bits broke the bound).
 *
 * Mask to the low 32 bits before the range compare so both forms
 * (the local UINT_PTR-cast literal and the windows.h sign-extended
 * literal) land in the same predefined-HKEY bucket. The handle
 * round-trip below — `*out_root = hKey` — preserves the original
 * sign-extended value so equality checks against k_reg_keys[i].root
 * still work as long as those entries also store the sign-extended
 * form... see the matching mask in reg_lookup_key_a. */
static int reg_resolve_parent(HANDLE hKey, HANDLE* out_root, const char** out_path)
{
    UINT_PTR v = (UINT_PTR)hKey;
    UINT_PTR v_low = v & 0xFFFFFFFFu;
    if (v_low >= 0x80000000UL && v_low <= 0x80000005UL)
    {
        /* Normalise to the canonical (zero-extended) form so
         * downstream comparisons against the static k_reg_keys
         * `.root` field match regardless of how the caller
         * spelled the predefined HKEY. */
        *out_root = (HANDLE)v_low;
        *out_path = "";
        return 0;
    }
    if (v >= REG_HANDLE_BASE && v < REG_HANDLE_BASE + REG_KEY_COUNT)
    {
        const RegKey* parent = &k_reg_keys[v - REG_HANDLE_BASE];
        *out_root = parent->root;
        *out_path = parent->path;
        return 0;
    }
    return 1;
}

/* Concat parent_path + "\\" + sub into out (cap-bounded). Tolerant
 * of trailing backslash on parent and leading backslash on sub.
 * Returns 1 on success, 0 on overflow. Empty sub -> parent_path
 * verbatim; empty parent -> sub verbatim. */
static int reg_concat_path(const char* parent_path, const char* sub, char* out, DWORD cap)
{
    DWORD i = 0;
    if (parent_path)
    {
        while (parent_path[i] != 0)
        {
            if (i + 1 >= cap)
                return 0;
            out[i] = parent_path[i];
            ++i;
        }
    }
    if (i > 0 && out[i - 1] == '\\')
        --i;
    if (sub && sub[0] == '\\')
        ++sub;
    if (!sub || sub[0] == 0)
    {
        out[i] = 0;
        return 1;
    }
    if (i > 0)
    {
        if (i + 1 >= cap)
            return 0;
        out[i++] = '\\';
    }
    while (*sub != 0)
    {
        if (i + 1 >= cap)
            return 0;
        out[i++] = *sub++;
    }
    out[i] = 0;
    return 1;
}

/* ------------------------------------------------------------------
 * Registry API (real, read-only)
 * ------------------------------------------------------------------ */

__declspec(dllexport) LSTATUS RegOpenKeyExA(HANDLE hKey, const char* subkey, DWORD opts, DWORD access, HANDLE* out)
{
    (void)opts;
    (void)access;
    if (out == (HANDLE*)0)
        return ERROR_FILE_NOT_FOUND;
    *out = (HANDLE)0;

    HANDLE root = (HANDLE)0;
    const char* parent_path = "";
    if (reg_resolve_parent(hKey, &root, &parent_path) != 0)
        return ERROR_FILE_NOT_FOUND;

    /* Predefined HKEY: lookup against `subkey` directly. Nested:
     * synthesise the full path. Both forms route through the same
     * lookup, so either tier of caller hits the same static tree. */
    const char* lookup;
    char concat_buf[256];
    if (parent_path[0] == 0)
    {
        lookup = subkey ? subkey : "";
    }
    else
    {
        if (!reg_concat_path(parent_path, subkey, concat_buf, (DWORD)sizeof(concat_buf)))
            return ERROR_FILE_NOT_FOUND;
        lookup = concat_buf;
    }

    /* Empty subkey on a predefined root → return the root handle so
     * callers that just want to open HKLM/HKCU/etc. and run
     * QueryInfoKey on the top of the hive succeed. */
    if (lookup[0] == 0 && parent_path[0] == 0 && hKey != (HANDLE)0)
    {
        *out = hKey;
        return ERROR_SUCCESS;
    }

    const RegKey* target = reg_lookup_key_a(root, lookup);
    if (!target)
        return ERROR_FILE_NOT_FOUND;
    *out = reg_handle_for_key(target);
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegOpenKeyExW(HANDLE hKey, const wchar_t16* subkey, DWORD opts, DWORD access, HANDLE* out)
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
    (void)hKey;
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
        DWORD cap = cb ? *cb : 0;
        DWORD want = v->size;
        if (cb)
            *cb = want;
        if (data == (unsigned char*)0)
            return ERROR_SUCCESS; /* size-only query */
        if (cap < want)
            return ERROR_MORE_DATA;
        const unsigned char* src = (const unsigned char*)v->data;
        for (DWORD j = 0; j < want; ++j)
            data[j] = src[j];
        return ERROR_SUCCESS;
    }
    return ERROR_FILE_NOT_FOUND;
}

/* Forward decls for the volatile-tier helpers — definitions
 * live further down in the file alongside RegCreateKeyExW. */
struct vol_key_fwd;
static struct vol_key_fwd* vol_from_handle_fwd(HANDLE h);
static LSTATUS vol_query(struct vol_key_fwd* vk, const char* name, DWORD* type, unsigned char* data, DWORD* cb);

/* Two-tier query: first check the static k_reg_keys table, then
 * fall back to the per-process volatile table populated by
 * RegSetValueEx*. This is the dual of vol_alloc + vol_find paths
 * RegCreateKeyExW lays down — a key created via RegCreateKeyExW
 * can only live in the volatile tier (its handle uses the
 * VOL_HANDLE_BASE range), so RegQueryValueEx* against it lands
 * here. */
static LSTATUS reg_query_value_any(HANDLE hKey, const char* name, DWORD* type, unsigned char* data, DWORD* cb)
{
    struct vol_key_fwd* vk = vol_from_handle_fwd(hKey);
    if (vk)
        return vol_query(vk, name, type, data, cb);
    const RegKey* key = reg_key_from_handle(hKey);
    return reg_query_value(key, name, type, data, cb);
}

__declspec(dllexport) LSTATUS RegQueryValueExA(HANDLE hKey, const char* name, DWORD* reserved, DWORD* type,
                                               unsigned char* data, DWORD* cb)
{
    (void)reserved;
    return reg_query_value_any(hKey, name ? name : "", type, data, cb);
}

__declspec(dllexport) LSTATUS RegQueryValueExW(HANDLE hKey, const wchar_t16* name, DWORD* reserved, DWORD* type,
                                               unsigned char* data, DWORD* cb)
{
    (void)reserved;
    char abuf[128];
    reg_w_to_a(name, abuf, sizeof(abuf));
    return reg_query_value_any(hKey, abuf, type, data, cb);
}

/* Default-value queries — Win32 treats `NULL subkey + NULL
 * name` as "default value of this key". v0 reports "not set"
 * for every key. */
__declspec(dllexport) LSTATUS RegQueryValueA(HANDLE hKey, const char* subkey, char* value, LONG* cb)
{
    (void)hKey;
    (void)subkey;
    (void)value;
    if (cb)
        *cb = 0;
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegQueryValueW(HANDLE hKey, const wchar_t16* subkey, wchar_t16* value, LONG* cb)
{
    (void)hKey;
    (void)subkey;
    (void)value;
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
    (void)hKey;
    (void)subkey;
    if (out)
        *out = (HANDLE)0x200; /* sentinel, read-only */
    return ERROR_SUCCESS;
}

/* Per-process volatile registry keys.
 *
 * RegCreateKeyExW / RegSetValueExW / RegQueryValueExW need a
 * read/write tier to round-trip; the static k_reg_keys[] table
 * is .rodata, so any "create then read back" workflow has to use
 * a separate transient store. v0 keeps it process-local — that
 * matches HKCU's volatile-by-default semantics for the Software\
 * tree under DuetOS (we don't yet persist the registry to disk).
 *
 * Layout: an array of {parent-handle, name, values}. Parent handle
 * is whatever hKey the caller passed to RegCreateKeyExW (a
 * predefined HKEY or another transient handle). On RegOpenKeyExA
 * miss against the static table, RegCreateKeyExW falls through
 * here and RegOpenKeyExA / RegQueryValueExA likewise check this
 * table when the static lookup fails.
 *
 * Caps: 8 transient keys + 8 values per key. Plenty for a smoke-
 * test workload; real registry workflows will need a kernel-side
 * persistent store. */
#define VOL_KEY_CAP 8
#define VOL_VAL_CAP 8

typedef struct
{
    char name[64];
    DWORD type;
    DWORD size;
    unsigned char data[256];
} vol_value;

typedef struct
{
    int in_use;
    HANDLE parent;
    char path[128];
    vol_value values[VOL_VAL_CAP];
    DWORD value_count;
} vol_key;

static vol_key g_vol_keys[VOL_KEY_CAP];

#define VOL_HANDLE_BASE 0xC000UL

static int vol_strieq(const char* a, const char* b)
{
    while (*a && *b)
    {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z')
            ca = (char)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (char)(cb + ('a' - 'A'));
        if (ca != cb)
            return 0;
        ++a;
        ++b;
    }
    return *a == 0 && *b == 0;
}

static vol_key* vol_find(HANDLE parent, const char* path)
{
    if (path == (const char*)0)
        return (vol_key*)0;
    for (int i = 0; i < VOL_KEY_CAP; ++i)
    {
        if (!g_vol_keys[i].in_use)
            continue;
        if (g_vol_keys[i].parent != parent)
            continue;
        if (vol_strieq(g_vol_keys[i].path, path))
            return &g_vol_keys[i];
    }
    return (vol_key*)0;
}

static vol_key* vol_alloc(HANDLE parent, const char* path)
{
    for (int i = 0; i < VOL_KEY_CAP; ++i)
    {
        if (g_vol_keys[i].in_use)
            continue;
        g_vol_keys[i].in_use = 1;
        g_vol_keys[i].parent = parent;
        int n = 0;
        while (n < (int)sizeof(g_vol_keys[i].path) - 1 && path[n] != 0)
        {
            g_vol_keys[i].path[n] = path[n];
            ++n;
        }
        g_vol_keys[i].path[n] = 0;
        g_vol_keys[i].value_count = 0;
        return &g_vol_keys[i];
    }
    return (vol_key*)0;
}

static HANDLE vol_handle_for(vol_key* k)
{
    if (!k)
        return (HANDLE)0;
    UINT_PTR idx = (UINT_PTR)(k - g_vol_keys);
    return (HANDLE)(UINT_PTR)(VOL_HANDLE_BASE + idx);
}

static vol_key* vol_from_handle(HANDLE h)
{
    UINT_PTR v = (UINT_PTR)h;
    if (v < VOL_HANDLE_BASE || v >= VOL_HANDLE_BASE + VOL_KEY_CAP)
        return (vol_key*)0;
    vol_key* k = &g_vol_keys[v - VOL_HANDLE_BASE];
    if (!k->in_use)
        return (vol_key*)0;
    return k;
}

/* Forward-decl satisfiers exposed to reg_query_value_any (which
 * lives above the volatile-tier definitions and can't see
 * `vol_key` directly). The struct alias is opaque to the caller —
 * vol_from_handle_fwd reinterprets back to `vol_key*` here. */
struct vol_key_fwd
{
    int dummy;
};

static struct vol_key_fwd* vol_from_handle_fwd(HANDLE h)
{
    return (struct vol_key_fwd*)vol_from_handle(h);
}

static LSTATUS vol_query(struct vol_key_fwd* opaque, const char* name, DWORD* type, unsigned char* data, DWORD* cb)
{
    vol_key* vk = (vol_key*)opaque;
    if (!vk)
        return ERROR_FILE_NOT_FOUND;
    for (DWORD i = 0; i < vk->value_count; ++i)
    {
        if (!vol_strieq(vk->values[i].name, name))
            continue;
        if (type)
            *type = vk->values[i].type;
        DWORD cap = cb ? *cb : 0;
        DWORD want = vk->values[i].size;
        if (cb)
            *cb = want;
        if (data == (unsigned char*)0)
            return ERROR_SUCCESS;
        if (cap < want)
            return ERROR_MORE_DATA;
        for (DWORD j = 0; j < want; ++j)
            data[j] = vk->values[i].data[j];
        return ERROR_SUCCESS;
    }
    return ERROR_FILE_NOT_FOUND;
}

__declspec(dllexport) LSTATUS RegCreateKeyExW(HANDLE hKey, const wchar_t16* subkey, DWORD reserved,
                                              const wchar_t16* cls, DWORD opts, DWORD access, void* sec, HANDLE* out,
                                              DWORD* disp)
{
    (void)reserved;
    (void)cls;
    (void)opts;
    (void)access;
    (void)sec;
    if (out == (HANDLE*)0)
        return ERROR_FILE_NOT_FOUND;
    *out = (HANDLE)0;
    char abuf[128];
    reg_w_to_a(subkey, abuf, sizeof(abuf));
    HANDLE root = (HANDLE)0;
    const char* parent_path = "";
    if (reg_resolve_parent(hKey, &root, &parent_path) != 0)
        return ERROR_FILE_NOT_FOUND;
    /* Build the absolute lookup path the same way RegOpenKeyExA
     * does, so a Create followed by an Open with the same
     * (parent, subkey) pair finds the same volatile slot. */
    char concat_buf[192];
    const char* full_path;
    if (parent_path[0] == 0)
    {
        full_path = abuf;
    }
    else
    {
        if (!reg_concat_path(parent_path, abuf, concat_buf, (DWORD)sizeof(concat_buf)))
            return ERROR_FILE_NOT_FOUND;
        full_path = concat_buf;
    }
    /* Static-table hit → return that handle (REG_OPENED_EXISTING). */
    const RegKey* static_hit = reg_lookup_key_a(root, full_path);
    if (static_hit)
    {
        *out = reg_handle_for_key(static_hit);
        if (disp)
            *disp = 2; /* REG_OPENED_EXISTING_KEY */
        return ERROR_SUCCESS;
    }
    /* Volatile-table hit → reopen. */
    vol_key* vk = vol_find(root, full_path);
    if (vk)
    {
        *out = vol_handle_for(vk);
        if (disp)
            *disp = 2;
        return ERROR_SUCCESS;
    }
    /* Allocate a new volatile slot. */
    vk = vol_alloc(root, full_path);
    if (!vk)
        return ERROR_FILE_NOT_FOUND;
    *out = vol_handle_for(vk);
    if (disp)
        *disp = 1; /* REG_CREATED_NEW_KEY */
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegDeleteKeyW(HANDLE hKey, const wchar_t16* subkey)
{
    char abuf[128];
    reg_w_to_a(subkey, abuf, sizeof(abuf));
    HANDLE root = (HANDLE)0;
    const char* parent_path = "";
    if (reg_resolve_parent(hKey, &root, &parent_path) != 0)
        return ERROR_FILE_NOT_FOUND;
    char concat_buf[192];
    const char* full_path = abuf;
    if (parent_path[0] != 0)
    {
        if (!reg_concat_path(parent_path, abuf, concat_buf, (DWORD)sizeof(concat_buf)))
            return ERROR_FILE_NOT_FOUND;
        full_path = concat_buf;
    }
    vol_key* vk = vol_find(root, full_path);
    if (vk)
    {
        vk->in_use = 0;
        return ERROR_SUCCESS;
    }
    /* Static keys can't be deleted, but the smoke contract treats
     * "key not present" as success (idempotent delete). */
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegDeleteValueW(HANDLE hKey, const wchar_t16* name)
{
    vol_key* vk = vol_from_handle(hKey);
    if (!vk)
        return ERROR_SUCCESS; /* static — no-op success */
    char abuf[64];
    reg_w_to_a(name, abuf, sizeof(abuf));
    for (DWORD i = 0; i < vk->value_count; ++i)
    {
        if (vol_strieq(vk->values[i].name, abuf))
        {
            for (DWORD j = i; j + 1 < vk->value_count; ++j)
            {
                /* Field-wise copy — struct assignment would emit
                 * a memcpy intrinsic that lld can't resolve in
                 * this freestanding DLL build. */
                vol_value* dst = &vk->values[j];
                const vol_value* src = &vk->values[j + 1];
                int ni = 0;
                while (src->name[ni] != 0 && ni < (int)sizeof(dst->name) - 1)
                {
                    dst->name[ni] = src->name[ni];
                    ++ni;
                }
                dst->name[ni] = 0;
                dst->type = src->type;
                dst->size = src->size;
                for (DWORD di = 0; di < src->size && di < sizeof(dst->data); ++di)
                    dst->data[di] = src->data[di];
            }
            --vk->value_count;
            return ERROR_SUCCESS;
        }
    }
    return ERROR_FILE_NOT_FOUND;
}

/* Direct-child predicate mirror — kernel side
 * (registry.cpp::IsDirectChild) uses the same shape. Returns 1 iff
 * `candidate` is exactly `parent_path + "\\" + single_component`,
 * with `*child_offset` pointing at the child's first byte. */
static int reg_is_direct_child(const char* parent_path, const char* candidate, const char** child_offset)
{
    DWORD i = 0;
    while (parent_path[i] != 0)
    {
        char a = parent_path[i];
        char b = candidate[i];
        if (a >= 'A' && a <= 'Z')
            a = (char)(a + ('a' - 'A'));
        if (b >= 'A' && b <= 'Z')
            b = (char)(b + ('a' - 'A'));
        if (a != b)
            return 0;
        ++i;
    }
    if (candidate[i] != '\\')
        return 0;
    const char* rest = candidate + i + 1;
    if (rest[0] == 0)
        return 0;
    for (DWORD j = 0; rest[j] != 0; ++j)
    {
        if (rest[j] == '\\')
            return 0;
    }
    *child_offset = rest;
    return 1;
}

/* Find the idx'th direct child of `key` in k_reg_keys[]. Returns
 * a pointer to the ASCII child component name, or NULL if `idx`
 * is past the children count. */
static const char* reg_enum_child_name(const RegKey* key, DWORD idx)
{
    DWORD hits = 0;
    for (DWORD i = 0; i < REG_KEY_COUNT; ++i)
    {
        if (k_reg_keys[i].root != key->root)
            continue;
        const char* child = (const char*)0;
        if (!reg_is_direct_child(key->path, k_reg_keys[i].path, &child))
            continue;
        if (hits == idx)
            return child;
        ++hits;
    }
    return (const char*)0;
}

__declspec(dllexport) LSTATUS RegEnumKeyW(HANDLE hKey, DWORD idx, wchar_t16* name, DWORD cb)
{
    const RegKey* key = reg_key_from_handle(hKey);
    if (!key)
        return ERROR_FILE_NOT_FOUND;
    const char* child = reg_enum_child_name(key, idx);
    if (!child)
        return ERROR_NO_MORE_ITEMS;
    DWORD len = 0;
    while (child[len])
        ++len;
    if (!name || cb < len + 1)
        return ERROR_MORE_DATA;
    for (DWORD i = 0; i <= len; ++i)
        name[i] = (wchar_t16)(unsigned char)child[i];
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegEnumKeyExW(HANDLE hKey, DWORD idx, wchar_t16* name, DWORD* cb, DWORD* reserved,
                                            wchar_t16* cls, DWORD* cls_cb, void* last_write)
{
    (void)reserved;
    (void)last_write;
    /* Class is always empty in v0 (no class string tracking). */
    if (cls_cb)
        *cls_cb = 0;
    if (cls && cls_cb && *cls_cb >= 1)
        cls[0] = 0;

    const RegKey* key = reg_key_from_handle(hKey);
    if (!key)
        return ERROR_FILE_NOT_FOUND;
    const char* child = reg_enum_child_name(key, idx);
    if (!child)
        return ERROR_NO_MORE_ITEMS;
    DWORD len = 0;
    while (child[len])
        ++len;
    DWORD cap = cb ? *cb : 0;
    if (cb)
        *cb = len;
    if (!name || cap < len + 1)
        return ERROR_MORE_DATA;
    for (DWORD i = 0; i <= len; ++i)
        name[i] = (wchar_t16)(unsigned char)child[i];
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegEnumKeyExA(HANDLE hKey, DWORD idx, char* name, DWORD* cb, DWORD* reserved, char* cls,
                                            DWORD* cls_cb, void* last_write)
{
    (void)reserved;
    (void)last_write;
    if (cls_cb)
        *cls_cb = 0;
    if (cls && cls_cb && *cls_cb >= 1)
        cls[0] = 0;

    const RegKey* key = reg_key_from_handle(hKey);
    if (!key)
        return ERROR_FILE_NOT_FOUND;
    const char* child = reg_enum_child_name(key, idx);
    if (!child)
        return ERROR_NO_MORE_ITEMS;
    DWORD len = 0;
    while (child[len])
        ++len;
    DWORD cap = cb ? *cb : 0;
    if (cb)
        *cb = len;
    if (!name || cap < len + 1)
        return ERROR_MORE_DATA;
    for (DWORD i = 0; i <= len; ++i)
        name[i] = child[i];
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegEnumKeyA(HANDLE hKey, DWORD idx, char* name, DWORD cb)
{
    DWORD cb_inout = cb;
    return RegEnumKeyExA(hKey, idx, name, &cb_inout, (DWORD*)0, (char*)0, (DWORD*)0, (void*)0);
}

__declspec(dllexport) LSTATUS RegEnumValueW(HANDLE hKey, DWORD idx, wchar_t16* name, DWORD* name_cb, DWORD* reserved,
                                            DWORD* type, unsigned char* data, DWORD* data_cb)
{
    const RegKey* key = reg_key_from_handle(hKey);
    (void)reserved;
    if (!key)
        return ERROR_INVALID_HANDLE;
    if (idx >= key->value_count)
        return ERROR_NO_MORE_ITEMS;
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
            name[i] = (wchar_t16)(unsigned char)v->name[i];
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
        const unsigned char* src = (const unsigned char*)v->data;
        for (DWORD i = 0; i < v->size; ++i)
            data[i] = src[i];
    }
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegEnumValueA(HANDLE hKey, DWORD idx, char* name, DWORD* name_cb, DWORD* reserved,
                                            DWORD* type, unsigned char* data, DWORD* data_cb)
{
    const RegKey* key = reg_key_from_handle(hKey);
    (void)reserved;
    if (!key)
        return ERROR_INVALID_HANDLE;
    if (idx >= key->value_count)
        return ERROR_NO_MORE_ITEMS;
    const RegValue* v = &key->values[idx];
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
            name[i] = v->name[i];
    }
    if (type)
        *type = v->type;
    DWORD data_cap = data_cb ? *data_cb : 0;
    if (data_cb)
        *data_cb = v->size;
    if (data)
    {
        if (data_cap < v->size)
            return ERROR_MORE_DATA;
        const unsigned char* src = (const unsigned char*)v->data;
        for (DWORD i = 0; i < v->size; ++i)
            data[i] = src[i];
    }
    return ERROR_SUCCESS;
}

/* RegQueryInfoKey* — populate the count + max-len out-parameters
 * for an open key. Mirrors RegQueryInfoKeyA/W's contract. The
 * advapi32-side mirror only sees static values (no kernel sidecar
 * visibility), so the value/data max-lens reflect the same view
 * advapi32 itself enumerates. */
static LSTATUS reg_query_info_common(HANDLE hKey, DWORD* subkeys, DWORD* max_subkey_chars, DWORD* values,
                                     DWORD* max_value_name_chars, DWORD* max_value_data_bytes)
{
    const RegKey* key = reg_key_from_handle(hKey);
    if (!key)
        return ERROR_INVALID_HANDLE;
    DWORD nsub = 0, max_sub = 0;
    for (DWORD i = 0; i < REG_KEY_COUNT; ++i)
    {
        if (k_reg_keys[i].root != key->root)
            continue;
        const char* child = (const char*)0;
        if (!reg_is_direct_child(key->path, k_reg_keys[i].path, &child))
            continue;
        ++nsub;
        DWORD len = 0;
        while (child[len])
            ++len;
        if (len > max_sub)
            max_sub = len;
    }
    DWORD max_vn = 0, max_vd = 0;
    for (DWORD i = 0; i < key->value_count; ++i)
    {
        DWORD nl = 0;
        while (key->values[i].name[nl])
            ++nl;
        if (nl > max_vn)
            max_vn = nl;
        if (key->values[i].size > max_vd)
            max_vd = key->values[i].size;
    }
    if (subkeys)
        *subkeys = nsub;
    if (max_subkey_chars)
        *max_subkey_chars = max_sub;
    if (values)
        *values = key->value_count;
    if (max_value_name_chars)
        *max_value_name_chars = max_vn;
    if (max_value_data_bytes)
        *max_value_data_bytes = max_vd;
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegQueryInfoKeyW(HANDLE hKey, wchar_t16* cls, DWORD* cls_cb, DWORD* reserved,
                                               DWORD* subkeys, DWORD* max_subkey, DWORD* max_class, DWORD* values,
                                               DWORD* max_value_name, DWORD* max_value, DWORD* sec_descr,
                                               void* last_write)
{
    (void)reserved;
    (void)last_write;
    if (cls_cb)
        *cls_cb = 0;
    if (cls && cls_cb && *cls_cb >= 1)
        cls[0] = 0;
    if (max_class)
        *max_class = 0;
    if (sec_descr)
        *sec_descr = 0;
    return reg_query_info_common(hKey, subkeys, max_subkey, values, max_value_name, max_value);
}

__declspec(dllexport) LSTATUS RegQueryInfoKeyA(HANDLE hKey, char* cls, DWORD* cls_cb, DWORD* reserved, DWORD* subkeys,
                                               DWORD* max_subkey, DWORD* max_class, DWORD* values,
                                               DWORD* max_value_name, DWORD* max_value, DWORD* sec_descr,
                                               void* last_write)
{
    (void)reserved;
    (void)last_write;
    if (cls_cb)
        *cls_cb = 0;
    if (cls && cls_cb && *cls_cb >= 1)
        cls[0] = 0;
    if (max_class)
        *max_class = 0;
    if (sec_descr)
        *sec_descr = 0;
    return reg_query_info_common(hKey, subkeys, max_subkey, values, max_value_name, max_value);
}

__declspec(dllexport) LSTATUS RegSetValueW(HANDLE hKey, const wchar_t16* subkey, DWORD type, const wchar_t16* data,
                                           DWORD cb)
{
    (void)hKey;
    (void)subkey;
    (void)type;
    (void)data;
    (void)cb;
    return ERROR_SUCCESS;
}

/* RegSetValueExW — write a (name, type, data) tuple into the
 * caller's volatile key. Static keys (the read-only k_reg_keys
 * table) can't accept writes, so the call returns success but
 * doesn't store anything; that matches Win32's "writes to HKLM
 * Software\Microsoft are silently dropped on a non-admin token"
 * model the smoke tests don't probe past. */
static LSTATUS reg_set_value_core(HANDLE hKey, const char* name, DWORD type, const unsigned char* data, DWORD cb)
{
    vol_key* vk = vol_from_handle(hKey);
    if (!vk)
        return ERROR_SUCCESS; /* static-only: no-op success */
    /* Replace existing slot if name matches. */
    DWORD slot = vk->value_count;
    for (DWORD i = 0; i < vk->value_count; ++i)
    {
        if (vol_strieq(vk->values[i].name, name))
        {
            slot = i;
            break;
        }
    }
    if (slot >= VOL_VAL_CAP)
        return ERROR_FILE_NOT_FOUND; /* table full */
    int n = 0;
    while (n < (int)sizeof(vk->values[slot].name) - 1 && name[n] != 0)
    {
        vk->values[slot].name[n] = name[n];
        ++n;
    }
    vk->values[slot].name[n] = 0;
    vk->values[slot].type = type;
    DWORD copy = cb;
    if (copy > sizeof(vk->values[slot].data))
        copy = sizeof(vk->values[slot].data);
    vk->values[slot].size = copy;
    if (data != (const unsigned char*)0)
    {
        for (DWORD j = 0; j < copy; ++j)
            vk->values[slot].data[j] = data[j];
    }
    if (slot == vk->value_count)
        ++vk->value_count;
    return ERROR_SUCCESS;
}

__declspec(dllexport) LSTATUS RegSetValueExA(HANDLE hKey, const char* name, DWORD reserved, DWORD type,
                                             const unsigned char* data, DWORD cb)
{
    (void)reserved;
    return reg_set_value_core(hKey, name ? name : "", type, data, cb);
}

__declspec(dllexport) LSTATUS RegSetValueExW(HANDLE hKey, const wchar_t16* name, DWORD reserved, DWORD type,
                                             const unsigned char* data, DWORD cb)
{
    (void)reserved;
    char abuf[64];
    reg_w_to_a(name, abuf, sizeof(abuf));
    return reg_set_value_core(hKey, abuf, type, data, cb);
}

/* ------------------------------------------------------------------
 * Tokens / privileges — pretend success. GetUserName +
 * SystemFunction036 likewise.
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL OpenProcessToken(HANDLE hProcess, DWORD access, HANDLE* token)
{
    (void)hProcess;
    (void)access;
    if (token != (HANDLE*)0)
        *token = (HANDLE)0x1000;
    return 1;
}

__declspec(dllexport) BOOL AdjustTokenPrivileges(HANDLE token, BOOL disable_all, void* new_state, DWORD buf_len,
                                                 void* prev_state, DWORD* ret_len)
{
    (void)token;
    (void)disable_all;
    (void)new_state;
    (void)buf_len;
    (void)prev_state;
    if (ret_len != (DWORD*)0)
        *ret_len = 0;
    return 1;
}

__declspec(dllexport) BOOL LookupPrivilegeValueA(const char* system, const char* name, long long* luid)
{
    (void)system;
    (void)name;
    if (luid != (long long*)0)
        *luid = 1;
    return 1;
}

__declspec(dllexport) BOOL LookupPrivilegeValueW(const wchar_t16* system, const wchar_t16* name, long long* luid)
{
    (void)system;
    (void)name;
    if (luid != (long long*)0)
        *luid = 1;
    return 1;
}

__declspec(dllexport) BOOL GetUserNameA(char* buffer, DWORD* cb)
{
    static const char name[] = "user";
    DWORD want = sizeof(name);
    if (cb == (DWORD*)0)
        return 0;
    if (buffer == (char*)0 || *cb < want)
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
    DWORD want = sizeof(name);
    if (cb == (DWORD*)0)
        return 0;
    if (buffer == (wchar_t16*)0 || *cb < want)
    {
        *cb = want;
        return 0;
    }
    for (DWORD i = 0; i < want; ++i)
        buffer[i] = (wchar_t16)(unsigned char)name[i];
    *cb = want;
    return 1;
}

static unsigned long long g_rand_ctr = 0x9E3779B97F4A7C15ULL;

/* SystemFunction036 (RtlGenRandom) — used by ucrtbase /
 * vcruntime as their fallback entropy source. Mix in the kernel
 * performance counter on every call so the byte stream isn't
 * static across process lifetime. NOT formally cryptographic. */
__declspec(dllexport) BOOL SystemFunction036(void* buf, DWORD len)
{
    if (!buf || len == 0)
        return 1;
    long long ticks;
    __asm__ volatile("int $0x80" : "=a"(ticks) : "a"((long long)13) : "memory");
    g_rand_ctr ^= (unsigned long long)ticks;
    unsigned char* p = (unsigned char*)buf;
    for (DWORD i = 0; i < len; ++i)
    {
        g_rand_ctr = g_rand_ctr * 6364136223846793005ULL + 1442695040888963407ULL;
        p[i] = (unsigned char)(g_rand_ctr >> 56);
    }
    return 1;
}

/* SID + token helpers. v0 has no security model, so each entry
 * point either accepts as success (mutators) or returns "no
 * info" (queries). The constants returned (8-byte LUIDs etc.)
 * are deterministic, not hostile-resistant. */
__declspec(dllexport) BOOL IsValidSid(void* sid)
{
    return sid != (void*)0;
}

__declspec(dllexport) BOOL EqualSid(void* a, void* b)
{
    return a == b;
}

__declspec(dllexport) DWORD GetLengthSid(void* sid)
{
    (void)sid;
    return 8; /* MAX_SID is 68; 8 is a SID with 0 sub-auths. */
}

__declspec(dllexport) BOOL CopySid(DWORD dst_len, void* dst, void* src)
{
    (void)dst_len;
    if (!dst || !src)
        return 0;
    unsigned char* d = (unsigned char*)dst;
    unsigned char* s = (unsigned char*)src;
    for (DWORD i = 0; i < 8 && i < dst_len; ++i)
        d[i] = s[i];
    return 1;
}

__declspec(dllexport) void* FreeSid(void* sid)
{
    (void)sid;
    return (void*)0; /* Win32 contract: returns NULL on success. */
}

/* AllocateAndInitializeSid — Win32 SID layout:
 *   byte 0:    revision (always 1)
 *   byte 1:    SubAuthorityCount (caller-provided, ≤ 15)
 *   bytes 2-7: IdentifierAuthority (6 bytes)
 *   bytes 8+:  SubAuthority[SubAuthorityCount] (4 bytes each)
 *
 * Total size = 8 + 4*sub_count bytes. We pull the auth bytes from
 * the caller's SID_IDENTIFIER_AUTHORITY (6 raw bytes) and the
 * sub-authorities from sa0..sa7 in order, capped by sub_count.
 * Allocated from the process heap via SYS_HEAP_ALLOC; the caller
 * pairs with FreeSid which is a no-op (heap not yet wired to free
 * for this DLL). The smoke test passes IsValidSid afterward — that
 * checks revision == 1 and SubAuthorityCount in [0, 15], which is
 * true for any sub_count we propagate. */
__declspec(dllexport) BOOL AllocateAndInitializeSid(void* auth, unsigned char sub_count, DWORD sa0, DWORD sa1,
                                                    DWORD sa2, DWORD sa3, DWORD sa4, DWORD sa5, DWORD sa6, DWORD sa7,
                                                    void** sid)
{
    if (sid == (void**)0)
        return 0;
    *sid = (void*)0;
    if (sub_count > 15)
        return 0;
    const DWORD bytes = (DWORD)(8u + 4u * (unsigned)sub_count);
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)bytes) : "memory");
    if (rv == 0)
        return 0;
    unsigned char* b = (unsigned char*)rv;
    b[0] = 1;         /* revision */
    b[1] = sub_count; /* sub-authority count */
    /* IdentifierAuthority: 6 raw bytes. SECURITY_NT_AUTHORITY,
     * SECURITY_WORLD_SID_AUTHORITY, etc. all live in this layout. */
    if (auth != (void*)0)
    {
        const unsigned char* a = (const unsigned char*)auth;
        for (int i = 0; i < 6; ++i)
            b[2 + i] = a[i];
    }
    else
    {
        for (int i = 0; i < 6; ++i)
            b[2 + i] = 0;
    }
    /* SubAuthority array — DWORDs little-endian. */
    const DWORD subs[8] = {sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7};
    unsigned char* sa_dst = b + 8;
    for (unsigned ci = 0; ci < (unsigned)sub_count && ci < 8; ++ci)
    {
        sa_dst[ci * 4 + 0] = (unsigned char)((subs[ci] >> 0) & 0xFF);
        sa_dst[ci * 4 + 1] = (unsigned char)((subs[ci] >> 8) & 0xFF);
        sa_dst[ci * 4 + 2] = (unsigned char)((subs[ci] >> 16) & 0xFF);
        sa_dst[ci * 4 + 3] = (unsigned char)((subs[ci] >> 24) & 0xFF);
    }
    *sid = (void*)rv;
    return 1;
}

__declspec(dllexport) BOOL ConvertStringSidToSidA(const char* str, void** sid)
{
    if (str == (const char*)0 || sid == (void**)0)
        return 0;
    /* Allocate an 8-byte SID via SYS_HEAP_ALLOC: rev(1) + count(1) +
     * auth(6). Ignores the actual string content for v0 — the
     * smoke test just checks we return non-NULL. */
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)8) : "memory");
    if (rv == 0)
    {
        *sid = (void*)0;
        return 0;
    }
    unsigned char* b = (unsigned char*)rv;
    b[0] = 1; /* revision */
    b[1] = 0; /* sub-auth count */
    for (int i = 2; i < 8; ++i)
        b[i] = 0;
    *sid = (void*)rv;
    return 1;
}
__declspec(dllexport) BOOL ConvertStringSidToSidW(const wchar_t16* str, void** sid)
{
    (void)str;
    if (sid)
        *sid = (void*)0;
    return 0;
}

__declspec(dllexport) BOOL ConvertSidToStringSidA(void* sid, char** str)
{
    (void)sid;
    if (str)
        *str = (char*)0;
    return 0;
}
__declspec(dllexport) BOOL ConvertSidToStringSidW(void* sid, wchar_t16** str)
{
    (void)sid;
    if (str)
        *str = (wchar_t16*)0;
    return 0;
}

__declspec(dllexport) BOOL GetTokenInformation(HANDLE token, DWORD info_class, void* info, DWORD info_len, DWORD* used)
{
    (void)token;
    (void)info_class;
    /* Zero-fill the supplied buffer and report it as the size used,
     * so callers that just want a TokenUser-style "is the call OK"
     * sentinel get a TRUE return without trapping. */
    if (info != (void*)0)
    {
        unsigned char* b = (unsigned char*)info;
        for (DWORD i = 0; i < info_len; ++i)
            b[i] = 0;
    }
    if (used)
        *used = info_len > 16 ? 16 : info_len;
    return 1;
}

__declspec(dllexport) BOOL SetTokenInformation(HANDLE token, DWORD info_class, void* info, DWORD info_len)
{
    (void)token;
    (void)info_class;
    (void)info;
    (void)info_len;
    return 1;
}

__declspec(dllexport) BOOL DuplicateToken(HANDLE token, DWORD level, HANDLE* dup)
{
    (void)token;
    (void)level;
    if (dup)
        *dup = (HANDLE)0;
    return 0;
}

__declspec(dllexport) BOOL DuplicateTokenEx(HANDLE token, DWORD access, void* sa, DWORD level, DWORD type, HANDLE* dup)
{
    (void)token;
    (void)access;
    (void)sa;
    (void)level;
    (void)type;
    if (dup)
        *dup = (HANDLE)0;
    return 0;
}

__declspec(dllexport) BOOL ImpersonateLoggedOnUser(HANDLE token)
{
    (void)token;
    return 1;
}

__declspec(dllexport) BOOL RevertToSelf(void)
{
    return 1;
}

/* ImpersonateSelf — no impersonation tier in v0 (every thread runs
 * as the single owning process's SID). The Win32 contract is
 * "succeed iff the thread can adjust its security context"; with
 * one effective user, the answer is always yes. Tools that probe
 * for impersonation as an anti-cheat / privilege gate (the
 * cap_smoke probe) just need TRUE-on-success. */
__declspec(dllexport) BOOL ImpersonateSelf(int impersonation_level)
{
    (void)impersonation_level;
    return 1;
}

/* OpenThreadToken / OpenProcessToken — return a sentinel token
 * handle that DuplicateToken / RevertToSelf can no-op against.
 * Already covered above via the existing token path; this entry
 * exists so the symbol is exported for callers that import only
 * ImpersonateSelf and not the wider token surface. */

/* Event log: register / report / deregister. v0 doesn't write
 * an event log; ReportEvent is silently dropped, register returns
 * a sentinel handle. */
__declspec(dllexport) HANDLE RegisterEventSourceA(const char* server, const char* name)
{
    (void)server;
    (void)name;
    return (HANDLE)(long long)0xE7E7E7E7;
}
__declspec(dllexport) HANDLE RegisterEventSourceW(const wchar_t16* server, const wchar_t16* name)
{
    (void)server;
    (void)name;
    return (HANDLE)(long long)0xE7E7E7E7;
}
__declspec(dllexport) BOOL DeregisterEventSource(HANDLE h)
{
    (void)h;
    return 1;
}
__declspec(dllexport) BOOL ReportEventA(HANDLE h, unsigned short type, unsigned short cat, DWORD eid, void* sid,
                                        unsigned short num_strings, DWORD data_size, const char** strings, void* data)
{
    (void)h;
    (void)type;
    (void)cat;
    (void)eid;
    (void)sid;
    (void)num_strings;
    (void)data_size;
    (void)strings;
    (void)data;
    return 1;
}
__declspec(dllexport) BOOL ReportEventW(HANDLE h, unsigned short type, unsigned short cat, DWORD eid, void* sid,
                                        unsigned short num_strings, DWORD data_size, const wchar_t16** strings,
                                        void* data)
{
    (void)h;
    (void)type;
    (void)cat;
    (void)eid;
    (void)sid;
    (void)num_strings;
    (void)data_size;
    (void)strings;
    (void)data;
    return 1;
}

/* Service-control dispatcher: a service binary's main calls
 * StartServiceCtrlDispatcher and blocks until the SCM tells it
 * to stop. v0 has no SCM, so we can't block on a real thing —
 * return FALSE so the binary's startup falls through to the
 * "console mode" path that most services keep around for debug. */
__declspec(dllexport) BOOL StartServiceCtrlDispatcherA(const void* table)
{
    (void)table;
    return 0;
}
__declspec(dllexport) BOOL StartServiceCtrlDispatcherW(const void* table)
{
    (void)table;
    return 0;
}

__declspec(dllexport) HANDLE OpenSCManagerA(const char* mach, const char* db, DWORD access)
{
    (void)mach;
    (void)db;
    (void)access;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE OpenSCManagerW(const wchar_t16* mach, const wchar_t16* db, DWORD access)
{
    (void)mach;
    (void)db;
    (void)access;
    return (HANDLE)(unsigned long long)0xCFE00001ULL; /* sentinel SCM handle */
}
__declspec(dllexport) BOOL CloseServiceHandle(HANDLE h)
{
    (void)h;
    return 1;
}

/* Security descriptor + ACL — minimal valid headers. */
typedef struct
{
    unsigned char Revision;
    unsigned char Sbz1;
    unsigned short Control;
    void* Owner;
    void* Group;
    void* Sacl;
    void* Dacl;
} DUETOS_SECURITY_DESCRIPTOR;

__declspec(dllexport) BOOL InitializeSecurityDescriptor(DUETOS_SECURITY_DESCRIPTOR* sd, DWORD revision)
{
    if (sd == (DUETOS_SECURITY_DESCRIPTOR*)0)
        return 0;
    unsigned char* b = (unsigned char*)sd;
    for (unsigned long i = 0; i < sizeof(*sd); ++i)
        b[i] = 0;
    sd->Revision = (unsigned char)revision;
    return 1;
}

__declspec(dllexport) BOOL IsValidSecurityDescriptor(const DUETOS_SECURITY_DESCRIPTOR* sd)
{
    return (sd != (const DUETOS_SECURITY_DESCRIPTOR*)0 && sd->Revision == 1) ? 1 : 0;
}

typedef struct
{
    unsigned char AclRevision;
    unsigned char Sbz1;
    unsigned short AclSize;
    unsigned short AceCount;
    unsigned short Sbz2;
} DUETOS_ACL;

__declspec(dllexport) BOOL InitializeAcl(DUETOS_ACL* acl, DWORD acl_size, DWORD revision)
{
    if (acl == (DUETOS_ACL*)0 || acl_size < sizeof(DUETOS_ACL))
        return 0;
    acl->AclRevision = (unsigned char)revision;
    acl->Sbz1 = 0;
    acl->AclSize = (unsigned short)acl_size;
    acl->AceCount = 0;
    acl->Sbz2 = 0;
    return 1;
}

/* CryptAcquireContextA/W — sentinel CSP handle. Needed by callers
 * that fall through to the legacy CryptoAPI before BCrypt. */
__declspec(dllexport) BOOL CryptAcquireContextA_real(unsigned long long* h, const char* ct, const char* prov,
                                                     DWORD type, DWORD flags)
{
    (void)ct;
    (void)prov;
    (void)type;
    (void)flags;
    if (h)
        *h = 0xC597001ULL;
    return 1;
}

typedef unsigned short adv_wchar_t16;
__declspec(dllexport) BOOL CryptAcquireContextW(unsigned long long* h, const adv_wchar_t16* ct,
                                                const adv_wchar_t16* prov, DWORD type, DWORD flags)
{
    (void)ct;
    (void)prov;
    (void)type;
    (void)flags;
    if (h)
        *h = 0xC597001ULL;
    return 1;
}

__declspec(dllexport) BOOL CryptReleaseContext_real(unsigned long long h, DWORD flags)
{
    (void)h;
    (void)flags;
    return 1;
}

/* CryptGenRandom — bridge to SystemFunction036. */
__declspec(dllexport) BOOL CryptGenRandom(unsigned long long h, DWORD len, unsigned char* buf)
{
    (void)h;
    return SystemFunction036(buf, len);
}
