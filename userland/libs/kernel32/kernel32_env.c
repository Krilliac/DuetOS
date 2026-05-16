#include "kernel32_internal.h"

/* ------------------------------------------------------------------
 * Environment variables — per-process userland table.
 *
 * The kernel-hosted env block (GetEnvironmentStringsW via stubs page)
 * gives the fixed boot-time environment. Get/Set/Expand on top of it
 * are kept entirely in user space here so a Set is visible to the
 * matching Get inside the same process. STUB-grade: no inheritance
 * across CreateProcess (we don't have CreateProcess yet anyway).
 * ------------------------------------------------------------------ */

#define DUETOS_ENV_MAX 16
#define DUETOS_ENV_NAME 32
#define DUETOS_ENV_VAL 96

typedef struct
{
    wchar_t16 name[DUETOS_ENV_NAME];
    wchar_t16 val[DUETOS_ENV_VAL];
    int in_use;
} DuetosEnvSlot;

static DuetosEnvSlot g_env_table[DUETOS_ENV_MAX];
static int g_env_seeded = 0;

/* Wide-string copy with explicit length, used by env_seed. Cannot
 * call wstr_copy here — it's defined further down in the file
 * (after GetEnvironmentVariableW); forward-declaring would mean
 * shuffling dozens of unrelated functions. The duplicated three-
 * line walk is cheaper than that churn. */
static void env_seed_one(int slot, const WCHAR_t* name, const wchar_t16* val)
{
    int i = 0;
    while (i < DUETOS_ENV_NAME - 1 && name[i] != 0)
    {
        g_env_table[slot].name[i] = name[i];
        ++i;
    }
    g_env_table[slot].name[i] = 0;
    int j = 0;
    while (j < DUETOS_ENV_VAL - 1 && val[j] != 0)
    {
        g_env_table[slot].val[j] = val[j];
        ++j;
    }
    g_env_table[slot].val[j] = 0;
    g_env_table[slot].in_use = 1;
}

/* Lazy-seed a small set of environment variables on the first
 * Get/Set call in this process. Without this every fresh Win32
 * PE sees a completely empty environment — `getenv("PATH")`,
 * `GetEnvironmentVariableW(L"USERNAME", ...)`, and so on all
 * return 0, even though the kernel-side fixed env block carries
 * sane values. The seed is per-DLL-instance so each PE gets its
 * own writable copy (matches Win32 semantics: SetEnvironmentVariable
 * is process-local). The list mirrors what mini_browser, the smoke
 * tests, and most CLI tools expect to read at startup. */
static void env_seed_defaults(void)
{
    if (g_env_seeded)
        return;
    g_env_seeded = 1;
    /* Each line: slot index, NAME, VALUE. Order doesn't matter —
     * lookup walks all slots until in_use && name match. */
    static const wchar_t16 kPathName[] = {'P', 'A', 'T', 'H', 0};
    static const wchar_t16 kPathVal[] = {'X', ':', '\\', 'S', 'y', 's', 't',  'e',
                                         'm', '3', '2',  ';', 'X', ':', '\\', 0};
    static const wchar_t16 kOsName[] = {'O', 'S', 0};
    static const wchar_t16 kOsVal[] = {'D', 'u', 'e', 't', 'O', 'S', 0};
    static const wchar_t16 kUserName[] = {'U', 'S', 'E', 'R', 'N', 'A', 'M', 'E', 0};
    static const wchar_t16 kUserVal[] = {'u', 's', 'e', 'r', 0};
    static const wchar_t16 kUserDomName[] = {'U', 'S', 'E', 'R', 'D', 'O', 'M', 'A', 'I', 'N', 0};
    static const wchar_t16 kUserDomVal[] = {'D', 'U', 'E', 'T', 'O', 'S', 0};
    static const wchar_t16 kCompName[] = {'C', 'O', 'M', 'P', 'U', 'T', 'E', 'R', 'N', 'A', 'M', 'E', 0};
    static const wchar_t16 kCompVal[] = {'D', 'U', 'E', 'T', 'O', 'S', 0};
    static const wchar_t16 kSysName[] = {'S', 'y', 's', 't', 'e', 'm', 'R', 'o', 'o', 't', 0};
    static const wchar_t16 kSysVal[] = {'X', ':', '\\', 0};
    static const wchar_t16 kWinName[] = {'w', 'i', 'n', 'd', 'i', 'r', 0};
    static const wchar_t16 kTempName[] = {'T', 'E', 'M', 'P', 0};
    static const wchar_t16 kTempVal[] = {'X', ':', '\\', 0};
    static const wchar_t16 kTmpName[] = {'T', 'M', 'P', 0};
    static const wchar_t16 kHomeName[] = {'U', 'S', 'E', 'R', 'P', 'R', 'O', 'F', 'I', 'L', 'E', 0};
    static const wchar_t16 kHomeVal[] = {'X', ':', '\\', 'U', 's', 'e', 'r', 's', '\\', 'u', 's', 'e', 'r', 0};
    static const wchar_t16 kProcArchName[] = {'P', 'R', 'O', 'C', 'E', 'S', 'S', 'O', 'R', '_', 'A', 'R',
                                              'C', 'H', 'I', 'T', 'E', 'C', 'T', 'U', 'R', 'E', 0};
    static const wchar_t16 kProcArchVal[] = {'A', 'M', 'D', '6', '4', 0};
    env_seed_one(0, kPathName, kPathVal);
    env_seed_one(1, kOsName, kOsVal);
    env_seed_one(2, kUserName, kUserVal);
    env_seed_one(3, kUserDomName, kUserDomVal);
    env_seed_one(4, kCompName, kCompVal);
    env_seed_one(5, kSysName, kSysVal);
    env_seed_one(6, kWinName, kSysVal); /* windir == SystemRoot */
    env_seed_one(7, kTempName, kTempVal);
    env_seed_one(8, kTmpName, kTempVal);
    env_seed_one(9, kHomeName, kHomeVal);
    env_seed_one(10, kProcArchName, kProcArchVal);
}

static int wstr_eq_ci(const wchar_t16* a, const wchar_t16* b)
{
    int i = 0;
    for (;;)
    {
        wchar_t16 ca = a[i];
        wchar_t16 cb = b[i];
        if (ca >= 'A' && ca <= 'Z')
            ca = (wchar_t16)(ca + ('a' - 'A'));
        if (cb >= 'A' && cb <= 'Z')
            cb = (wchar_t16)(cb + ('a' - 'A'));
        if (ca != cb)
            return 0;
        if (ca == 0)
            return 1;
        ++i;
    }
}

static int wstr_len(const wchar_t16* s)
{
    int n = 0;
    while (s[n] != 0)
        ++n;
    return n;
}

static void wstr_copy(wchar_t16* dst, const wchar_t16* src, int max)
{
    int i;
    for (i = 0; i < max - 1 && src[i] != 0; ++i)
        dst[i] = src[i];
    dst[i] = 0;
}

__declspec(dllexport) DWORD GetEnvironmentVariableW(const WCHAR_t* name, wchar_t16* buf, DWORD size)
{
    if (name == (const WCHAR_t*)0)
        return 0;
    env_seed_defaults();
    for (int i = 0; i < DUETOS_ENV_MAX; ++i)
    {
        if (!g_env_table[i].in_use)
            continue;
        if (!wstr_eq_ci(g_env_table[i].name, name))
            continue;
        int n = wstr_len(g_env_table[i].val);
        if (buf == (wchar_t16*)0 || size == 0)
            return (DWORD)(n + 1);
        if ((DWORD)n + 1 > size)
        {
            buf[0] = 0;
            return (DWORD)(n + 1);
        }
        wstr_copy(buf, g_env_table[i].val, (int)size);
        return (DWORD)n;
    }
    return 0;
}

__declspec(dllexport) BOOL SetEnvironmentVariableW(const WCHAR_t* name, const wchar_t16* val)
{
    if (name == (const WCHAR_t*)0)
        return 0;
    env_seed_defaults();
    /* val == NULL means "delete" the variable. */
    /* First, find an existing entry to update or delete. */
    for (int i = 0; i < DUETOS_ENV_MAX; ++i)
    {
        if (!g_env_table[i].in_use)
            continue;
        if (!wstr_eq_ci(g_env_table[i].name, name))
            continue;
        if (val == (const WCHAR_t*)0)
        {
            g_env_table[i].in_use = 0;
            return 1;
        }
        wstr_copy(g_env_table[i].val, val, DUETOS_ENV_VAL);
        return 1;
    }
    if (val == (const WCHAR_t*)0)
        return 1; /* Delete of non-existent == success per docs. */
    /* Allocate a free slot. */
    for (int i = 0; i < DUETOS_ENV_MAX; ++i)
    {
        if (g_env_table[i].in_use)
            continue;
        wstr_copy(g_env_table[i].name, name, DUETOS_ENV_NAME);
        wstr_copy(g_env_table[i].val, val, DUETOS_ENV_VAL);
        g_env_table[i].in_use = 1;
        return 1;
    }
    return 0;
}

/* GetCommandLineA / GetCommandLineW — return a stable pointer to
 * the calling process's command-line string.
 *
 * The kernel populates a per-process "proc-env" page (mapped at
 * fixed VA 0x65000000 for every PE that has imports — see
 * kernel/subsystems/win32/proc_env.{h,cpp}). The page carries the
 * program name as both UTF-16LE and ASCII command lines at
 * kProcEnvVa + kProcEnvCmdline{W,A}Off (0x65000300 / 0x65000380).
 *
 * We return those addresses directly. The CRT then sees a real,
 * non-empty command line starting with the program name —
 * matching what the kernel thunk-fallback already returns for
 * any PE that didn't link kernel32.dll's real export.
 *
 * Multi-arg cmdlines arrive when SpawnPeFile gains an argv path;
 * the proc-env layout already reserves enough room. */
#define DUETOS_PROC_ENV_CMDLINE_W_VA 0x0000000065000300ULL
#define DUETOS_PROC_ENV_CMDLINE_A_VA 0x0000000065000380ULL

__declspec(dllexport) const char* GetCommandLineA(void)
{
    return (const char*)(UINT_PTR)DUETOS_PROC_ENV_CMDLINE_A_VA;
}

__declspec(dllexport) const wchar_t16* GetCommandLineW(void)
{
    return (const wchar_t16*)(UINT_PTR)DUETOS_PROC_ENV_CMDLINE_W_VA;
}

__declspec(dllexport) DWORD GetEnvironmentVariableA(const char* name, char* buf, DWORD size)
{
    if (name == (const char*)0)
        return 0;
    /* Translate name to wchar_t16, look up, then translate back. */
    wchar_t16 wname[DUETOS_ENV_NAME];
    int i;
    for (i = 0; i < DUETOS_ENV_NAME - 1 && name[i] != 0; ++i)
        wname[i] = (wchar_t16)(unsigned char)name[i];
    wname[i] = 0;
    wchar_t16 wval[DUETOS_ENV_VAL];
    DWORD n = GetEnvironmentVariableW(wname, wval, DUETOS_ENV_VAL);
    if (n == 0)
        return 0;
    /* n is wchar count without NUL when buf-fit, with NUL otherwise. */
    if (buf == (char*)0 || size == 0)
        return n;
    DWORD j;
    for (j = 0; j < size - 1 && wval[j] != 0; ++j)
        buf[j] = (char)(unsigned char)wval[j];
    buf[j] = 0;
    return j;
}

__declspec(dllexport) BOOL SetEnvironmentVariableA(const char* name, const char* val)
{
    if (name == (const char*)0)
        return 0;
    wchar_t16 wname[DUETOS_ENV_NAME];
    wchar_t16 wval[DUETOS_ENV_VAL];
    int i;
    for (i = 0; i < DUETOS_ENV_NAME - 1 && name[i] != 0; ++i)
        wname[i] = (wchar_t16)(unsigned char)name[i];
    wname[i] = 0;
    if (val == (const char*)0)
        return SetEnvironmentVariableW(wname, (const WCHAR_t*)0);
    for (i = 0; i < DUETOS_ENV_VAL - 1 && val[i] != 0; ++i)
        wval[i] = (wchar_t16)(unsigned char)val[i];
    wval[i] = 0;
    return SetEnvironmentVariableW(wname, wval);
}

__declspec(dllexport) DWORD ExpandEnvironmentStringsW(const wchar_t16* src, wchar_t16* dst, DWORD size)
{
    /* Scan src and substitute %NAME% references with the matching
     * environment-variable value (case-insensitive lookup via
     * GetEnvironmentVariableW). Unmatched %NAME% (no closing '%'
     * within the env-name buffer cap, or name not in the table)
     * is emitted verbatim, preserving the documented Win32
     * behaviour.
     *
     * Single-pass: we always advance `out` so the return value is
     * the full required size (including NUL) even when the
     * caller's buffer is too small. Writes to dst are gated on
     * `dst != NULL && out + 1 < size` so we never overrun the
     * supplied buffer and always leave one slot for the terminator. */
    if (src == (const WCHAR_t*)0)
        return 0;

    DWORD out = 0; /* chars produced so far (excluding NUL) */
    DWORD i = 0;
    for (;;)
    {
        wchar_t16 c = src[i];
        if (c == 0)
            break;
        if (c == (wchar_t16)'%')
        {
            /* Look ahead for the closing '%'. Cap the search at
             * DUETOS_ENV_NAME-1 so a stray '%' followed by a long
             * run of non-'%' characters doesn't blow our scratch
             * buffer or take a quadratic walk. */
            DWORD name_max = (DWORD)(DUETOS_ENV_NAME - 1);
            DWORD k = 0;
            while (k < name_max && src[i + 1 + k] != 0 && src[i + 1 + k] != (wchar_t16)'%')
                ++k;
            if (k > 0 && src[i + 1 + k] == (wchar_t16)'%')
            {
                wchar_t16 name_buf[DUETOS_ENV_NAME];
                for (DWORD m = 0; m < k; ++m)
                    name_buf[m] = src[i + 1 + m];
                name_buf[k] = 0;

                wchar_t16 val_buf[DUETOS_ENV_VAL];
                DWORD got = GetEnvironmentVariableW(name_buf, val_buf, (DWORD)DUETOS_ENV_VAL);
                if (got > 0 && got <= (DWORD)DUETOS_ENV_VAL)
                {
                    /* `got` includes the NUL — value length is got-1. */
                    DWORD vlen = got - 1;
                    for (DWORD m = 0; m < vlen; ++m)
                    {
                        if (dst != (wchar_t16*)0 && out + 1 < size)
                            dst[out] = val_buf[m];
                        ++out;
                    }
                    i = i + 1 + k + 1; /* skip past closing '%' */
                    continue;
                }
                /* Unknown variable — emit %NAME% verbatim. */
                if (dst != (wchar_t16*)0 && out + 1 < size)
                    dst[out] = (wchar_t16)'%';
                ++out;
                for (DWORD m = 0; m < k; ++m)
                {
                    if (dst != (wchar_t16*)0 && out + 1 < size)
                        dst[out] = src[i + 1 + m];
                    ++out;
                }
                if (dst != (wchar_t16*)0 && out + 1 < size)
                    dst[out] = (wchar_t16)'%';
                ++out;
                i = i + 1 + k + 1;
                continue;
            }
            /* No closing '%' within range — fall through and emit
             * the bare '%' as a literal character. */
        }
        if (dst != (wchar_t16*)0 && out + 1 < size)
            dst[out] = c;
        ++out;
        ++i;
    }
    if (dst != (wchar_t16*)0 && size > 0)
    {
        DWORD term = (out < size) ? out : (size - 1);
        dst[term] = 0;
    }
    return out + 1; /* total chars required including NUL */
}
