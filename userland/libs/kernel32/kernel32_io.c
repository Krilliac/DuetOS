#include "kernel32_internal.h"


/* GetFileAttributesA/W live further down — they use SYS_FILE_QUERY_ATTRIBUTES
 * directly. Skipping our placeholder definitions here avoids duplicates. */

/* CreateFileMappingW — for v0 we treat unnamed file mappings
 * backed by the system pagefile (INVALID_HANDLE_VALUE handle)
 * as a heap allocation. The returned "mapping handle" is the
 * heap pointer with the low bit set as a sentinel; MapViewOfFile
 * just returns the same pointer (size 0 → use stored size).
 *
 * Named mappings still STUB. ipc_smoke uses the unnamed path.
 */
typedef struct
{
    DWORD size;
    DWORD protect;
    void* base;
    /* Optional name (UTF-16, low-byte stripped to ASCII for
     * comparison). Empty → unnamed mapping; OpenFileMappingW
     * walks the table for a matching non-empty name. */
    char name[64];
} DUETOS_FILEMAPPING;

#define DUETOS_FILEMAPPING_MAX 8
static DUETOS_FILEMAPPING g_filemappings[DUETOS_FILEMAPPING_MAX];
static int g_filemapping_count = 0;

static int dfm_name_eq(const char* a, const char* b)
{
    int i = 0;
    while (a[i] && b[i])
    {
        if (a[i] != b[i])
            return 0;
        ++i;
    }
    return a[i] == 0 && b[i] == 0;
}

__declspec(dllexport) HANDLE CreateFileMappingW(HANDLE hFile, void* sec, DWORD protect, DWORD sizeHigh, DWORD sizeLow,
                                                const WCHAR_t* name)
{
    (void)hFile;
    (void)sec;
    (void)name;
    if (g_filemapping_count >= DUETOS_FILEMAPPING_MAX)
        return (HANDLE)0;
    unsigned long long total = ((unsigned long long)sizeHigh << 32) | sizeLow;
    if (total == 0)
        total = 0x1000; /* default 4K if caller passed 0 */
    /* Cap at the per-process heap budget. The Win32 heap in v0 is
     * 16 pages = 64 KiB total, so any single allocation has to
     * leave room for the heap header and the slab's own footer.
     * Cap at 32 KiB so a follow-up alloc within the same process
     * still has room — that's enough for ipc_smoke (which just
     * probes the round-trip) and most caller workflows that do
     * one mapping at a time. Real cross-process shared memory
     * needs a SYS_VM_* path; deferred. */
    const unsigned long long kMappingMaxBytes = 0x8000ULL;
    if (total > kMappingMaxBytes)
        total = kMappingMaxBytes;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)total) : "memory");
    if (rv == 0)
        return (HANDLE)0;
    int slot = g_filemapping_count++;
    g_filemappings[slot].size = (DWORD)total;
    g_filemappings[slot].protect = protect;
    g_filemappings[slot].base = (void*)rv;
    /* Capture the name (low-byte UTF-16 strip) so OpenFileMappingW
     * can find the same mapping by name later. The slot is
     * process-local; cross-process named-shm semantics are deferred
     * (would need a kernel-side named-section table). */
    int ni = 0;
    if (name != (const WCHAR_t*)0)
    {
        while (ni < 63 && name[ni] != 0)
        {
            g_filemappings[slot].name[ni] = (char)(name[ni] & 0xFF);
            ++ni;
        }
    }
    g_filemappings[slot].name[ni] = 0;
    /* Sentinel handle: 0x6000 + slot. */
    return (HANDLE)(unsigned long long)(0x6000 + slot);
}

__declspec(dllexport) HANDLE OpenFileMappingW(DWORD desired, BOOL inherit, const WCHAR_t* name)
{
    (void)desired;
    (void)inherit;
    if (name == (const WCHAR_t*)0)
        return (HANDLE)0;
    /* UTF-16 → ASCII low-byte strip into a local scratch, then
     * scan the per-process mapping table for a matching name.
     * Cross-process lookup requires a kernel-mediated named-
     * section registry; this v0 path covers the common in-
     * process pattern (CreateFileMappingW → OpenFileMappingW). */
    char abuf[64];
    int i = 0;
    while (i < 63 && name[i] != 0)
    {
        abuf[i] = (char)(name[i] & 0xFF);
        ++i;
    }
    abuf[i] = 0;
    if (abuf[0] == 0)
        return (HANDLE)0;
    for (int s = 0; s < g_filemapping_count; ++s)
    {
        if (dfm_name_eq(g_filemappings[s].name, abuf))
            return (HANDLE)(unsigned long long)(0x6000 + s);
    }
    return (HANDLE)0;
}

__declspec(dllexport) void* MapViewOfFile(HANDLE h, DWORD desired, DWORD offHigh, DWORD offLow,
                                          unsigned long long bytes)
{
    (void)desired;
    (void)offHigh;
    (void)offLow;
    (void)bytes;
    unsigned long long handle_v = (unsigned long long)h;
    if (handle_v < 0x6000 || handle_v >= 0x6000 + DUETOS_FILEMAPPING_MAX)
        return (void*)0;
    int slot = (int)(handle_v - 0x6000);
    return g_filemappings[slot].base;
}

__declspec(dllexport) BOOL UnmapViewOfFile(const void* base)
{
    (void)base;
    /* Page is freed when CloseHandle of the mapping is called. */
    return 1;
}

/* CreateJobObjectW — opaque sentinel handle. AssignProcessToJobObject
 * accepts and returns success. IsProcessInJob reports FALSE before
 * any assignment in this v0 model. */
__declspec(dllexport) HANDLE CreateJobObjectW(void* sec, const WCHAR_t* name)
{
    (void)sec;
    (void)name;
    return (HANDLE)0x7001ULL;
}

__declspec(dllexport) BOOL AssignProcessToJobObject(HANDLE job, HANDLE proc)
{
    (void)job;
    (void)proc;
    return 1;
}

__declspec(dllexport) BOOL IsProcessInJob(HANDLE proc, HANDLE job, BOOL* in_job)
{
    (void)proc;
    (void)job;
    if (in_job != (BOOL*)0)
        *in_job = 0;
    return 1;
}

/* CreateIoCompletionPort — for v0 we keep an in-memory ring of
 * up to 32 pending completions per port. Single-threaded scope
 * matches the rest of the v0 kernel32 surface; matches the
 * smoke-test usage pattern of "post N, get N within the same
 * thread".
 *
 * T7-03: file→IOCP binding table. CreateIoCompletionPort with
 * a non-INVALID hFile + non-NULL hExisting registers the
 * binding so subsequent overlapped ReadFile / WriteFile calls
 * post a completion packet to the bound port. Only handles
 * inside the kernel-file-handle range (kWin32HandleBase ..
 * +kWin32HandleCap) are valid binding sources; others ignore
 * the call and return the existing port.
 */
#define DUETOS_IOCP_RING 32
typedef struct
{
    DWORD bytes;
    unsigned long long key;
    void* ov;
} DuetosIocpEntry;
typedef struct
{
    DuetosIocpEntry ring[DUETOS_IOCP_RING];
    int head, tail;
    int in_use;
} DuetosIocp;

#define DUETOS_IOCP_MAX 4
static DuetosIocp g_iocp[DUETOS_IOCP_MAX];

#define DUETOS_IOCP_BINDING_SLOTS 16
typedef struct
{
    int in_use;
    HANDLE file_handle;
    HANDLE iocp_handle;
    unsigned long long completion_key;
} DuetosIocpBinding;
static DuetosIocpBinding g_iocp_bindings[DUETOS_IOCP_BINDING_SLOTS];

static int win32_iocp_slot_of_handle(HANDLE iocp)
{
    unsigned long long h = (unsigned long long)(UINT_PTR)iocp;
    if (h < 0x8000 || h >= 0x8000 + DUETOS_IOCP_MAX)
        return -1;
    int slot = (int)(h - 0x8000);
    if (!g_iocp[slot].in_use)
        return -1;
    return slot;
}

/* Push a completion packet onto a port. Drops on full ring
 * (matches PostQueuedCompletionStatus's behaviour). Returns 1
 * on enqueue, 0 on full/closed. */
static int win32_iocp_post_internal(int slot, DWORD bytes, unsigned long long key, void* ov)
{
    if (slot < 0 || slot >= DUETOS_IOCP_MAX || !g_iocp[slot].in_use)
        return 0;
    int next = (g_iocp[slot].tail + 1) % DUETOS_IOCP_RING;
    if (next == g_iocp[slot].head)
        return 0;
    g_iocp[slot].ring[g_iocp[slot].tail].bytes = bytes;
    g_iocp[slot].ring[g_iocp[slot].tail].key = key;
    g_iocp[slot].ring[g_iocp[slot].tail].ov = ov;
    g_iocp[slot].tail = next;
    return 1;
}

/* Look up a binding for a given file handle. Returns the
 * matching slot index in g_iocp_bindings, or -1 on miss. */
static int win32_iocp_lookup_binding(HANDLE file_handle)
{
    for (int i = 0; i < DUETOS_IOCP_BINDING_SLOTS; ++i)
    {
        if (g_iocp_bindings[i].in_use && g_iocp_bindings[i].file_handle == file_handle)
            return i;
    }
    return -1;
}

__declspec(dllexport) HANDLE CreateIoCompletionPort(HANDLE fileHandle, HANDLE existing, unsigned long long key,
                                                    DWORD numThreads)
{
    (void)numThreads;
    HANDLE iocp = existing;
    if (iocp == (HANDLE)0)
    {
        for (int i = 0; i < DUETOS_IOCP_MAX; ++i)
            if (!g_iocp[i].in_use)
            {
                g_iocp[i].head = 0;
                g_iocp[i].tail = 0;
                g_iocp[i].in_use = 1;
                iocp = (HANDLE)(unsigned long long)(0x8000 + i);
                break;
            }
        if (iocp == (HANDLE)0)
            return (HANDLE)0;
    }
    /* Win32 sentinel: INVALID_HANDLE_VALUE = (HANDLE)-1 means
     * "create the port, no file binding". Only valid file
     * handles establish a binding. */
    const unsigned long long fh_raw = (unsigned long long)(UINT_PTR)fileHandle;
    if (fileHandle != (HANDLE)0 && fileHandle != (HANDLE)(long long)-1 && fh_raw >= 0x100ULL && fh_raw < 0x110ULL)
    {
        for (int i = 0; i < DUETOS_IOCP_BINDING_SLOTS; ++i)
        {
            if (!g_iocp_bindings[i].in_use)
            {
                g_iocp_bindings[i].in_use = 1;
                g_iocp_bindings[i].file_handle = fileHandle;
                g_iocp_bindings[i].iocp_handle = iocp;
                g_iocp_bindings[i].completion_key = key;
                break;
            }
        }
    }
    return iocp;
}

__declspec(dllexport) BOOL PostQueuedCompletionStatus(HANDLE iocp, DWORD bytes, unsigned long long key, void* ov)
{
    int slot = win32_iocp_slot_of_handle(iocp);
    if (slot < 0)
        return 0;
    return win32_iocp_post_internal(slot, bytes, key, ov) ? 1 : 0;
}

__declspec(dllexport) BOOL GetQueuedCompletionStatus(HANDLE iocp, DWORD* bytes, unsigned long long* key, void** ov,
                                                     DWORD timeout)
{
    (void)timeout;
    int slot = win32_iocp_slot_of_handle(iocp);
    if (slot < 0)
        return 0;
    if (g_iocp[slot].head == g_iocp[slot].tail)
        return 0; /* empty — could also block, but v0 is non-blocking. */
    if (bytes != (DWORD*)0)
        *bytes = g_iocp[slot].ring[g_iocp[slot].head].bytes;
    if (key != (unsigned long long*)0)
        *key = g_iocp[slot].ring[g_iocp[slot].head].key;
    if (ov != (void**)0)
        *ov = g_iocp[slot].ring[g_iocp[slot].head].ov;
    g_iocp[slot].head = (g_iocp[slot].head + 1) % DUETOS_IOCP_RING;
    return 1;
}

/* OVERLAPPED layout (Microsoft SDK):
 *   +0  ULONG_PTR Internal       — completion status (NTSTATUS)
 *   +8  ULONG_PTR InternalHigh   — bytes transferred
 *   +16 DWORD     Offset         — file offset low
 *   +20 DWORD     OffsetHigh     — file offset high
 *   +24 HANDLE    hEvent         — optional event signaled on done
 * Used by ReadFile / WriteFile when lpOverlapped != NULL.
 */
#define OVERLAPPED_OFF_INTERNAL 0
#define OVERLAPPED_OFF_INTERNAL_HIGH 8
#define OVERLAPPED_OFF_OFFSET_LO 16
#define OVERLAPPED_OFF_OFFSET_HI 20
#define OVERLAPPED_OFF_HEVENT 24

static unsigned long long win32_overlapped_offset(const void* ov)
{
    if (ov == (const void*)0)
        return 0xFFFFFFFFFFFFFFFFULL;
    const unsigned char* p = (const unsigned char*)ov;
    DWORD lo, hi;
    __builtin_memcpy(&lo, p + OVERLAPPED_OFF_OFFSET_LO, sizeof(lo));
    __builtin_memcpy(&hi, p + OVERLAPPED_OFF_OFFSET_HI, sizeof(hi));
    return ((unsigned long long)hi << 32) | lo;
}

static void win32_overlapped_complete(void* ov, unsigned long long status, unsigned long long bytes)
{
    if (ov == (void*)0)
        return;
    unsigned char* p = (unsigned char*)ov;
    __builtin_memcpy(p + OVERLAPPED_OFF_INTERNAL, &status, sizeof(status));
    __builtin_memcpy(p + OVERLAPPED_OFF_INTERNAL_HIGH, &bytes, sizeof(bytes));
}

/* CreateTimerQueue / DeleteTimerQueue — sentinel handle. */
__declspec(dllexport) HANDLE CreateTimerQueue(void)
{
    return (HANDLE)0x8801ULL;
}

__declspec(dllexport) BOOL DeleteTimerQueue(HANDLE q)
{
    (void)q;
    return 1;
}

/* CreateWaitableTimerW / SetWaitableTimer / CancelWaitableTimer
 * land below CreateThread (which the service-thread spawn depends
 * on). See the comment block on the implementation for the v0
 * polling-thread design. */

/* WTSGetActiveConsoleSessionId stub — return 1. */
__declspec(dllexport) DWORD WTSGetActiveConsoleSessionId(void)
{
    return 1;
}

__declspec(dllexport) BOOL ProcessIdToSessionId(DWORD pid, DWORD* session)
{
    (void)pid;
    if (session != (DWORD*)0)
        *session = 1;
    return 1;
}

/* GetSystemPowerStatus — return canned "AC plugged, full battery". */
typedef struct
{
    unsigned char ACLineStatus;
    unsigned char BatteryFlag;
    unsigned char BatteryLifePercent;
    unsigned char Reserved1;
    DWORD BatteryLifeTime;
    DWORD BatteryFullLifeTime;
} DUETOS_SYSTEM_POWER_STATUS;

__declspec(dllexport) BOOL GetSystemPowerStatus(DUETOS_SYSTEM_POWER_STATUS* sps)
{
    if (sps == (DUETOS_SYSTEM_POWER_STATUS*)0)
        return 0;
    sps->ACLineStatus = 1;          /* AC online */
    sps->BatteryFlag = 0x80;        /* no system battery */
    sps->BatteryLifePercent = 0xFF; /* unknown */
    sps->Reserved1 = 0;
    sps->BatteryLifeTime = 0xFFFFFFFFu;
    sps->BatteryFullLifeTime = 0xFFFFFFFFu;
    return 1;
}

__declspec(dllexport) DWORD SetThreadExecutionState(DWORD esFlags)
{
    /* Return previous state (just echo input). */
    return esFlags;
}

__declspec(dllexport) BOOL IsSystemResumeAutomatic(void)
{
    return 0;
}

/* GeoID family — return USA = 244. */
__declspec(dllexport) int GetUserGeoID(int geoclass)
{
    (void)geoclass;
    return 244;
}

__declspec(dllexport) int GetSystemGeoID(int geoclass)
{
    (void)geoclass;
    return 244;
}

__declspec(dllexport) int GetGeoInfoW(int geoid, int gtype, wchar_t16* buf, int cchData, unsigned short langid)
{
    (void)geoid;
    (void)langid;
    static const wchar_t16 sIso2[] = {'U', 'S', 0};
    static const wchar_t16 sIso3[] = {'U', 'S', 'A', 0};
    static const wchar_t16 sName[] = {'U', 'n', 'i', 't', 'e', 'd', ' ', 'S', 't', 'a', 't', 'e', 's', 0};
    const wchar_t16* msg;
    /* gtype: GEO_ISO2=4, GEO_ISO3=5, GEO_FRIENDLYNAME=8 */
    if (gtype == 4)
        msg = sIso2;
    else if (gtype == 5)
        msg = sIso3;
    else
        msg = sName;
    int needed = 0;
    while (msg[needed] != 0)
        ++needed;
    ++needed;
    if (cchData == 0)
        return needed;
    if (buf == (wchar_t16*)0 || cchData < needed)
        return 0;
    int j = 0;
    while (msg[j] != 0)
    {
        buf[j] = msg[j];
        ++j;
    }
    buf[j] = 0;
    return needed;
}

/* GetCalendarInfoEx — return canned strings for common selectors. */
__declspec(dllexport) int GetCalendarInfoEx(const wchar_t16* locale, unsigned int cal, const wchar_t16* reserved,
                                            unsigned int caltype, wchar_t16* buf, int cchData, unsigned int* val)
{
    (void)locale;
    (void)cal;
    (void)reserved;
    (void)val;
    static const wchar_t16 sName[] = {'G', 'r', 'e', 'g', 'o', 'r', 'i', 'a', 'n', 0};
    /* CAL_SCALNAME = 2, others mostly canned. */
    if (caltype != 2 && caltype != 0x1000) /* CAL_SCALNAME or NOUSEROVERRIDE | CAL_SCALNAME */
        return 0;
    int needed = 10;
    if (cchData == 0)
        return needed;
    if (buf == (wchar_t16*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < 9; ++i)
        buf[i] = sName[i];
    buf[9] = 0;
    return needed;
}

__declspec(dllexport) int GetCalendarInfoA(unsigned int locale, unsigned int cal, unsigned int caltype, char* buf,
                                           int cchData, unsigned int* val)
{
    (void)locale;
    (void)cal;
    (void)val;
    if (caltype != 2)
        return 0;
    static const char sName[] = "Gregorian";
    int needed = 10;
    if (cchData == 0)
        return needed;
    if (buf == (char*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < 9; ++i)
        buf[i] = sName[i];
    buf[9] = 0;
    return needed;
}

/* GetDpiForSystem — assume 96 dpi (default 100% scale). */
__declspec(dllexport) unsigned int GetDpiForSystem(void)
{
    return 96;
}

/* Date/time/number format APIs — canned MM/DD/YYYY, HH:MM:SS, pass-through. */
static int duetos_u32_to_dec(unsigned int v, char* out)
{
    if (v == 0)
    {
        out[0] = '0';
        return 1;
    }
    char tmp[16];
    int n = 0;
    while (v != 0)
    {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    }
    for (int i = 0; i < n; ++i)
        out[i] = tmp[n - 1 - i];
    return n;
}

typedef struct
{
    unsigned short y, m, dow, d, h, min, s, ms;
} DUETOS_SYSTEMTIME;

/* en-US locale name tables (DuetOS is en-US-only) shared by the
 * date/time picture formatter. */
static const char* const k_day_full[7] = {"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"};
static const char* const k_day_abbr[7] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char* const k_mon_full[12] = {"January", "February", "March",     "April",   "May",      "June",
                                           "July",    "August",   "September", "October", "November", "December"};
static const char* const k_mon_abbr[12] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

static int dt_emit_str(char* s, int pos, int cap, const char* str)
{
    while (*str && pos < cap - 1)
        s[pos++] = *str++;
    return pos;
}

static int dt_emit_num(char* s, int pos, int cap, unsigned v, int min_width)
{
    char t[16];
    int n = duetos_u32_to_dec(v, t);
    for (int i = n; i < min_width && pos < cap - 1; ++i)
        s[pos++] = '0';
    for (int i = 0; i < n && pos < cap - 1; ++i)
        s[pos++] = t[i];
    return pos;
}

/* Format a SYSTEMTIME through a Win32 date/time picture string into
 * `scratch` (NUL-terminated), returning the length. Honors the
 * documented run-length tokens — d/dd/ddd/dddd, M/MM/MMM/MMMM,
 * y/yy/yyyy, H/HH (24h), h/hh (12h), m/mm, s/ss, t/tt (AM/PM) — plus
 * single-quoted literals ('' = a literal quote). Any other character
 * is copied verbatim. One unified walker serves both Get*Format APIs;
 * each just supplies its default picture. */
static int duetos_fmt_datetime(const DUETOS_SYSTEMTIME* st, const char* fmt, char* scratch, int scap)
{
    int pos = 0;
    const char* p = fmt;
    while (*p && pos < scap - 1)
    {
        char c = *p;
        if (c == '\'')
        {
            ++p;
            while (*p && pos < scap - 1)
            {
                if (*p == '\'')
                {
                    if (p[1] == '\'') /* '' -> literal quote */
                    {
                        scratch[pos++] = '\'';
                        p += 2;
                        continue;
                    }
                    ++p;
                    break;
                }
                scratch[pos++] = *p++;
            }
            continue;
        }
        int run = 0;
        while (p[run] == c)
            ++run;
        unsigned dow = st->dow % 7u;
        unsigned mon = (st->m >= 1 && st->m <= 12) ? (unsigned)(st->m - 1) : 0u;
        if (c == 'd')
        {
            if (run >= 4)
                pos = dt_emit_str(scratch, pos, scap, k_day_full[dow]);
            else if (run == 3)
                pos = dt_emit_str(scratch, pos, scap, k_day_abbr[dow]);
            else
                pos = dt_emit_num(scratch, pos, scap, st->d, run == 2 ? 2 : 1);
        }
        else if (c == 'M')
        {
            if (run >= 4)
                pos = dt_emit_str(scratch, pos, scap, k_mon_full[mon]);
            else if (run == 3)
                pos = dt_emit_str(scratch, pos, scap, k_mon_abbr[mon]);
            else
                pos = dt_emit_num(scratch, pos, scap, st->m, run == 2 ? 2 : 1);
        }
        else if (c == 'y')
        {
            if (run >= 3)
                pos = dt_emit_num(scratch, pos, scap, st->y, 4);
            else
                pos = dt_emit_num(scratch, pos, scap, st->y % 100u, 2);
        }
        else if (c == 'H')
            pos = dt_emit_num(scratch, pos, scap, st->h, run >= 2 ? 2 : 1);
        else if (c == 'h')
        {
            unsigned h12 = st->h % 12u;
            if (h12 == 0)
                h12 = 12;
            pos = dt_emit_num(scratch, pos, scap, h12, run >= 2 ? 2 : 1);
        }
        else if (c == 'm')
            pos = dt_emit_num(scratch, pos, scap, st->min, run >= 2 ? 2 : 1);
        else if (c == 's')
            pos = dt_emit_num(scratch, pos, scap, st->s, run >= 2 ? 2 : 1);
        else if (c == 't')
        {
            const char* ap = (st->h < 12) ? "AM" : "PM";
            if (run >= 2)
                pos = dt_emit_str(scratch, pos, scap, ap);
            else if (pos < scap - 1)
                scratch[pos++] = ap[0];
        }
        else
        {
            for (int i = 0; i < run && pos < scap - 1; ++i)
                scratch[pos++] = c;
        }
        p += run;
    }
    scratch[pos] = 0;
    return pos;
}

/* Shared tail: copy `scratch` into the caller buffer honoring the
 * cchData==0 (query size) / too-small (return 0) contract. */
static int dt_finish(const char* scratch, int len, char* buf, int cchData)
{
    int needed = len + 1;
    if (cchData == 0)
        return needed;
    if (buf == (char*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < len; ++i)
        buf[i] = scratch[i];
    buf[len] = 0;
    return needed;
}

__declspec(dllexport) int GetDateFormatA(unsigned long lcid, DWORD flags, const DUETOS_SYSTEMTIME* st, const char* fmt,
                                         char* buf, int cchData)
{
    (void)lcid;
    (void)flags;
    if (st == (const DUETOS_SYSTEMTIME*)0)
        return 0;
    char scratch[128];
    int len = duetos_fmt_datetime(st, (fmt && fmt[0]) ? fmt : "M/d/yyyy", scratch, (int)sizeof(scratch));
    return dt_finish(scratch, len, buf, cchData);
}

__declspec(dllexport) int GetDateFormatW(unsigned long lcid, DWORD flags, const DUETOS_SYSTEMTIME* st,
                                         const WCHAR_t* fmt, WCHAR_t* buf, int cchData)
{
    (void)lcid;
    (void)flags;
    if (st == (const DUETOS_SYSTEMTIME*)0)
        return 0;
    /* Narrow the wide picture (en-US tokens are all ASCII), format,
     * then widen the result back out. */
    char nfmt[128];
    int fi = 0;
    if (fmt)
        for (; fmt[fi] && fi < (int)sizeof(nfmt) - 1; ++fi)
            nfmt[fi] = (char)(fmt[fi] & 0xFF);
    nfmt[fi] = 0;
    char scratch[128];
    int len = duetos_fmt_datetime(st, (fi > 0) ? nfmt : "M/d/yyyy", scratch, (int)sizeof(scratch));
    int needed = len + 1;
    if (cchData == 0)
        return needed;
    if (buf == (WCHAR_t*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < len; ++i)
        buf[i] = (WCHAR_t)(unsigned char)scratch[i];
    buf[len] = 0;
    return needed;
}

__declspec(dllexport) int GetTimeFormatA(unsigned long lcid, DWORD flags, const DUETOS_SYSTEMTIME* st, const char* fmt,
                                         char* buf, int cchData)
{
    (void)lcid;
    (void)flags;
    if (st == (const DUETOS_SYSTEMTIME*)0)
        return 0;
    char scratch[128];
    int len = duetos_fmt_datetime(st, (fmt && fmt[0]) ? fmt : "HH:mm:ss", scratch, (int)sizeof(scratch));
    return dt_finish(scratch, len, buf, cchData);
}

__declspec(dllexport) int GetTimeFormatW(unsigned long lcid, DWORD flags, const DUETOS_SYSTEMTIME* st,
                                         const WCHAR_t* fmt, WCHAR_t* buf, int cchData)
{
    (void)lcid;
    (void)flags;
    if (st == (const DUETOS_SYSTEMTIME*)0)
        return 0;
    char nfmt[128];
    int fi = 0;
    if (fmt)
        for (; fmt[fi] && fi < (int)sizeof(nfmt) - 1; ++fi)
            nfmt[fi] = (char)(fmt[fi] & 0xFF);
    nfmt[fi] = 0;
    char scratch[128];
    int len = duetos_fmt_datetime(st, (fi > 0) ? nfmt : "HH:mm:ss", scratch, (int)sizeof(scratch));
    int needed = len + 1;
    if (cchData == 0)
        return needed;
    if (buf == (WCHAR_t*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < len; ++i)
        buf[i] = (WCHAR_t)(unsigned char)scratch[i];
    buf[len] = 0;
    return needed;
}

/* NUMBERFMT formatting core (DUETOS_NUMBERFMT_A + num_format_core_a)
 * lives in the freestanding header so the same code is exercised by a
 * fast hosted unit test (tests/host/test_kernel32_nls.cpp) as well as
 * the DLL build. See kernel32_nls_format.h for the rounding + grouping
 * contract. */
#include "kernel32_nls_format.h"

/* Default locale NUMBERFMT for en-US (used when fmt == NULL). */
static const DUETOS_NUMBERFMT_A k_default_numfmt_a = {
    2,   /* NumDigits: 2 decimal places */
    1,   /* LeadingZero */
    3,   /* Grouping: thousands */
    ".", /* lpDecimalSep */
    ",", /* lpThousandSep */
    1,   /* NegativeOrder: -1.1 */
};

__declspec(dllexport) int GetNumberFormatA(unsigned long lcid, DWORD flags, const char* num, void* fmt, char* buf,
                                           int cchData)
{
    (void)lcid;
    (void)flags;
    if (num == (const char*)0)
        return 0;

    const DUETOS_NUMBERFMT_A* nf = (fmt != (void*)0) ? (const DUETOS_NUMBERFMT_A*)fmt : &k_default_numfmt_a;

    char scratch[256];
    int len = num_format_core_a(num, nf, scratch, (int)sizeof(scratch));
    int needed = len + 1;
    if (cchData == 0)
        return needed;
    if (buf == (char*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < len; ++i)
        buf[i] = scratch[i];
    buf[len] = 0;
    return needed;
}

/* GetNumberFormatW — wide variant.  Narrow the wide separator strings,
 * delegate to the A core, then widen the result back to UTF-16.
 * GAP: separators with non-ASCII code points are truncated to '?'. —
 *      revisit when Unicode locale tables land. */
__declspec(dllexport) int GetNumberFormatW(unsigned long lcid, DWORD flags, const WCHAR_t* num, void* fmt, WCHAR_t* buf,
                                           int cchData)
{
    (void)lcid;
    (void)flags;
    if (num == (const WCHAR_t*)0)
        return 0;

    /* Narrow num to ASCII scratch. */
    char num_a[128];
    int ni = 0;
    for (; num[ni] != 0 && ni < 127; ++ni)
        num_a[ni] = (char)(num[ni] & 0xFF);
    num_a[ni] = 0;

    DUETOS_NUMBERFMT_A nf_a;
    char dec_buf[8];
    char tho_buf[8];

    const DUETOS_NUMBERFMT_A* nf;
    if (fmt != (void*)0)
    {
        /* The wide NUMBERFMT mirrors the A one but with LPWSTR
         * separator fields.  Layout: NumDigits(4) + LeadingZero(4) +
         * Grouping(4) + lpDecimalSep(ptr) + lpThousandSep(ptr) +
         * NegativeOrder(4).  We reinterpret as wide and narrow. */
        typedef struct
        {
            unsigned int NumDigits;
            unsigned int LeadingZero;
            unsigned int Grouping;
            const WCHAR_t* lpDecimalSep;
            const WCHAR_t* lpThousandSep;
            unsigned int NegativeOrder;
        } NUMBERFMT_W;
        const NUMBERFMT_W* wf = (const NUMBERFMT_W*)fmt;
        nf_a.NumDigits = wf->NumDigits;
        nf_a.LeadingZero = wf->LeadingZero;
        nf_a.Grouping = wf->Grouping;
        nf_a.NegativeOrder = wf->NegativeOrder;
        /* Narrow separator strings. */
        int di = 0;
        if (wf->lpDecimalSep)
            for (; wf->lpDecimalSep[di] != 0 && di < 7; ++di)
                dec_buf[di] = (char)(wf->lpDecimalSep[di] & 0xFF);
        dec_buf[di] = 0;
        nf_a.lpDecimalSep = dec_buf;
        int ti = 0;
        if (wf->lpThousandSep)
            for (; wf->lpThousandSep[ti] != 0 && ti < 7; ++ti)
                tho_buf[ti] = (char)(wf->lpThousandSep[ti] & 0xFF);
        tho_buf[ti] = 0;
        nf_a.lpThousandSep = tho_buf;
        nf = &nf_a;
    }
    else
    {
        nf = &k_default_numfmt_a;
    }

    char scratch[256];
    int len = num_format_core_a(num_a, nf, scratch, (int)sizeof(scratch));
    int needed = len + 1;
    if (cchData == 0)
        return needed;
    if (buf == (WCHAR_t*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < len; ++i)
        buf[i] = (WCHAR_t)(unsigned char)scratch[i];
    buf[len] = 0;
    return needed;
}

__declspec(dllexport) BOOL EnumSystemLocalesA(BOOL(__stdcall* cb)(char*), DWORD flags)
{
    (void)flags;
    if (cb == (BOOL(__stdcall*)(char*))0)
        return 0;
    char id[] = "00000409";
    cb(id);
    return 1;
}

__declspec(dllexport) BOOL GetDiskFreeSpaceExW(const wchar_t16* dir, void* avail, void* total, void* free_)
{
    (void)dir;
    unsigned long long free_b = 1ULL * 1024 * 1024 * 1024;
    unsigned long long total_b = 8ULL * 1024 * 1024 * 1024;
    if (avail != (void*)0)
        *(unsigned long long*)avail = free_b;
    if (total != (void*)0)
        *(unsigned long long*)total = total_b;
    if (free_ != (void*)0)
        *(unsigned long long*)free_ = free_b;
    return 1;
}

__declspec(dllexport) BOOL GetThreadIOPendingFlag(HANDLE thread, BOOL* pending)
{
    (void)thread;
    if (pending != (BOOL*)0)
        *pending = 0;
    return 1;
}

/* GetUserDefaultUILanguage / GetSystemDefaultUILanguage — en-US. */
__declspec(dllexport) unsigned short GetUserDefaultUILanguage(void)
{
    return 0x0409;
}
__declspec(dllexport) unsigned short GetSystemDefaultUILanguage(void)
{
    return 0x0409;
}

/* Console title — in-memory state. */
static char g_console_title[256] = "DuetOS Console";
__declspec(dllexport) BOOL SetConsoleTitleA(const char* title)
{
    if (title == (const char*)0)
        return 0;
    int i = 0;
    while (i < 255 && title[i] != 0)
    {
        g_console_title[i] = title[i];
        ++i;
    }
    g_console_title[i] = 0;
    return 1;
}
__declspec(dllexport) BOOL SetConsoleTitleW(const wchar_t16* title)
{
    if (title == (const WCHAR_t*)0)
        return 0;
    int i = 0;
    while (i < 255 && title[i] != 0)
    {
        g_console_title[i] = (char)(title[i] & 0xFF);
        ++i;
    }
    g_console_title[i] = 0;
    return 1;
}
__declspec(dllexport) DWORD GetConsoleTitleA(char* title, DWORD size)
{
    if (title == (char*)0 || size == 0)
        return 0;
    int i = 0;
    while ((DWORD)i < size - 1 && g_console_title[i] != 0)
    {
        title[i] = g_console_title[i];
        ++i;
    }
    title[i] = 0;
    return (DWORD)i;
}
__declspec(dllexport) DWORD GetConsoleTitleW(wchar_t16* title, DWORD size)
{
    if (title == (wchar_t16*)0 || size == 0)
        return 0;
    int i = 0;
    while ((DWORD)i < size - 1 && g_console_title[i] != 0)
    {
        title[i] = (wchar_t16)(unsigned char)g_console_title[i];
        ++i;
    }
    title[i] = 0;
    return (DWORD)i;
}

/* FoldStringW — pass-through (LCMapStringW lives further down). */
__declspec(dllexport) int FoldStringW(unsigned long flags, const wchar_t16* src, int srclen, wchar_t16* dst, int dstlen)
{
    (void)flags;
    if (src == (const WCHAR_t*)0)
        return 0;
    int n = 0;
    if (srclen < 0)
    {
        while (src[n] != 0)
            ++n;
        ++n;
    }
    else
        n = srclen;
    if (dstlen == 0)
        return n;
    if (dst == (wchar_t16*)0 || dstlen < n)
        return 0;
    for (int i = 0; i < n; ++i)
        dst[i] = src[i];
    return n;
}

/* GetCurrencyFormatA — en-US: "$1,234.50"; negative "($1,234.50)".
 * Routes the magnitude through the shared NUMBERFMT core (grouping +
 * 2 decimals + half-up rounding), then applies the currency symbol and
 * the en-US default negative order (parentheses — LOCALE_INEGCURR 0).
 * GAP: the CURRENCYFMT struct argument is not honoured; the en-US
 *      locale default is always applied. — revisit with locale tables. */
__declspec(dllexport) int GetCurrencyFormatA(unsigned long lcid, DWORD flags, const char* num, void* fmt, char* buf,
                                             int cchData)
{
    (void)lcid;
    (void)flags;
    (void)fmt;
    if (num == (const char*)0)
        return 0;

    char scratch[160];
    int len = currency_format_core_a(num, &k_default_numfmt_a, "$", scratch, (int)sizeof(scratch));
    int needed = len + 1;
    if (cchData == 0)
        return needed;
    if (buf == (char*)0 || cchData < needed)
        return 0;
    for (int i = 0; i < len; ++i)
        buf[i] = scratch[i];
    buf[len] = 0;
    return needed;
}

/* GetExitCodeThread is defined further down; v17 dup removed. */

/* OpenThread on self-TID — return a sentinel handle. */
__declspec(dllexport) HANDLE OpenThread(DWORD access, BOOL inherit, DWORD tid)
{
    (void)access;
    (void)inherit;
    (void)tid;
    /* Return current-thread pseudo-handle so callers can just use it. */
    return (HANDLE)(long long)-2;
}

/* GetPhysicallyInstalledSystemMemory — 8 GB. */
__declspec(dllexport) BOOL GetPhysicallyInstalledSystemMemory(unsigned long long* mem_in_kb)
{
    if (mem_in_kb == (unsigned long long*)0)
        return 0;
    *mem_in_kb = 8ULL * 1024 * 1024; /* 8 GB in KiB */
    return 1;
}

/* HeapValidate / GetProcessHeaps — accept everything. */
__declspec(dllexport) BOOL HeapValidate(HANDLE heap, DWORD flags, const void* p)
{
    (void)heap;
    (void)flags;
    (void)p;
    return 1;
}

__declspec(dllexport) DWORD GetProcessHeaps(DWORD count, HANDLE* heaps)
{
    /* Single sentinel "process heap" handle — matches what
     * GetProcessHeap returns elsewhere in this TU. */
    if (heaps != (HANDLE*)0 && count >= 1)
        heaps[0] = (HANDLE)1;
    return 1;
}

/* DuplicateHandle — for v0 we just alias the source. */
__declspec(dllexport) BOOL DuplicateHandle(HANDLE src_proc, HANDLE src, HANDLE dst_proc, HANDLE* dst, DWORD access,
                                           BOOL inherit, DWORD opts)
{
    (void)src_proc;
    (void)dst_proc;
    (void)access;
    (void)inherit;
    (void)opts;
    if (dst == (HANDLE*)0)
        return 0;
    *dst = src;
    return 1;
}

/* GetHandleInformation / SetHandleInformation. */
__declspec(dllexport) BOOL GetHandleInformation(HANDLE h, DWORD* flags)
{
    (void)h;
    if (flags != (DWORD*)0)
        *flags = 0;
    return 1;
}

__declspec(dllexport) BOOL SetHandleInformation(HANDLE h, DWORD mask, DWORD flags)
{
    (void)h;
    (void)mask;
    (void)flags;
    return 1;
}

/* QueryProcessCycleTime / QueryThreadCycleTime — use rdtsc. */
__declspec(dllexport) BOOL QueryProcessCycleTime(HANDLE p, unsigned long long* cycles)
{
    (void)p;
    if (cycles == (unsigned long long*)0)
        return 0;
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    *cycles = ((unsigned long long)hi << 32) | lo;
    return 1;
}

__declspec(dllexport) BOOL QueryThreadCycleTime(HANDLE t, unsigned long long* cycles)
{
    (void)t;
    if (cycles == (unsigned long long*)0)
        return 0;
    unsigned int lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    *cycles = ((unsigned long long)hi << 32) | lo;
    return 1;
}

/* GetFileTime — return canned epoch (Jan 1 2026). */
__declspec(dllexport) BOOL GetFileTime(HANDLE f, void* create, void* access, void* write)
{
    (void)f;
    /* FILETIME = 100ns intervals since 1601-01-01.
     * 2026-01-01 ≈ 13369248000000000. */
    unsigned long long t = 13369248000000000ULL;
    if (create != (void*)0)
        *(unsigned long long*)create = t;
    if (access != (void*)0)
        *(unsigned long long*)access = t;
    if (write != (void*)0)
        *(unsigned long long*)write = t;
    return 1;
}

/* GetFileInformationByHandle — fill BY_HANDLE_FILE_INFORMATION. */
__declspec(dllexport) BOOL GetFileInformationByHandle(HANDLE f, void* info)
{
    (void)f;
    if (info == (void*)0)
        return 0;
    /* 4 (attrs) + 24 (3 FILETIMEs) + 4 (volSerial) + 4 (sizeHi) +
     * 4 (sizeLo) + 4 (numLinks) + 4+4 (fileIdx). 52 bytes. */
    unsigned char* b = (unsigned char*)info;
    for (int i = 0; i < 52; ++i)
        b[i] = 0;
    *(DWORD*)(b + 0) = 0x80;        /* FILE_ATTRIBUTE_NORMAL */
    *(DWORD*)(b + 28) = 0xCAFEBABE; /* volSerial */
    *(DWORD*)(b + 40) = 1;          /* numLinks */
    return 1;
}

/* SystemTimeToFileTime — convert SYSTEMTIME to 100-ns intervals
 * since 1601-01-01. Days-since-1601 algorithm. */
__declspec(dllexport) BOOL SystemTimeToFileTime(const DUETOS_SYSTEMTIME* st, void* ft)
{
    if (st == (const DUETOS_SYSTEMTIME*)0 || ft == (void*)0)
        return 0;
    /* Days from 1601-01-01 to year start. */
    int y = st->y;
    if (y < 1601 || y > 30828)
        return 0;
    static const int dom_normal[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    static const int dom_leap[12] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    long long days = 0;
    for (int yr = 1601; yr < y; ++yr)
    {
        int leap = ((yr % 4 == 0) && (yr % 100 != 0)) || (yr % 400 == 0);
        days += leap ? 366 : 365;
    }
    int leap_y = ((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0);
    const int* dom = leap_y ? dom_leap : dom_normal;
    int m = st->m;
    if (m < 1 || m > 12)
        return 0;
    for (int i = 0; i < m - 1; ++i)
        days += dom[i];
    days += (st->d - 1);
    long long secs = days * 86400LL + (long long)st->h * 3600 + (long long)st->min * 60 + st->s;
    long long ticks = secs * 10000000LL + (long long)st->ms * 10000;
    *(long long*)ft = ticks;
    return 1;
}

__declspec(dllexport) BOOL FileTimeToSystemTime(const void* ft, DUETOS_SYSTEMTIME* st)
{
    if (ft == (const void*)0 || st == (DUETOS_SYSTEMTIME*)0)
        return 0;
    long long ticks = *(const long long*)ft;
    long long secs = ticks / 10000000LL;
    int ms = (int)((ticks / 10000LL) % 1000);
    long long days = secs / 86400;
    int sod = (int)(secs % 86400);
    st->h = (unsigned short)(sod / 3600);
    st->min = (unsigned short)((sod % 3600) / 60);
    st->s = (unsigned short)(sod % 60);
    st->ms = (unsigned short)ms;
    int y = 1601;
    static const int dom_normal[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    static const int dom_leap[12] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    while (1)
    {
        int leap = ((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0);
        long long yd = leap ? 366 : 365;
        if (days < yd)
            break;
        days -= yd;
        ++y;
    }
    int leap_y = ((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0);
    const int* dom = leap_y ? dom_leap : dom_normal;
    int m = 0;
    while (m < 11 && days >= dom[m])
    {
        days -= dom[m];
        ++m;
    }
    st->y = (unsigned short)y;
    st->m = (unsigned short)(m + 1);
    st->d = (unsigned short)(days + 1);
    st->dow = 0;
    return 1;
}

/* CompareFileTime. */
__declspec(dllexport) long CompareFileTime(const void* a, const void* b)
{
    if (a == (const void*)0 || b == (const void*)0)
        return 0;
    long long va = *(const long long*)a;
    long long vb = *(const long long*)b;
    if (va < vb)
        return -1;
    if (va > vb)
        return 1;
    return 0;
}

/* OpenProcess on self (or any pid; v0 returns a sentinel handle). */
__declspec(dllexport) HANDLE OpenProcess(DWORD access, BOOL inherit, DWORD pid)
{
    (void)access;
    (void)inherit;
    (void)pid;
    return (HANDLE)(long long)-1; /* current-process pseudo-handle */
}

/* CreatePipe — anonymous cross-process pipe (T11-02).
 *
 * Routes through SYS_WIN32_CREATE_PIPE (186): the kernel
 * allocates a pipe pool slot (the same pool the Linux pipe(2)
 * syscall uses) and writes two Win32-shaped file handles back
 * to the caller. ReadFile / WriteFile / CloseHandle on those
 * handles dispatch by FsBackingKind through the file-route
 * layer to PipeRead / PipeWrite / PipeReleaseRead / PipeReleaseWrite.
 *
 * The legacy in-process ring (DUETOS_PIPE_RD / DUETOS_PIPE_WR
 * sentinels) is kept as a fallback for callers that hit the
 * kernel-side OOM path — the kernel's pipe pool is fixed at
 * 16 slots, and a workload that allocates 17 pipes still gets
 * a (process-local, non-cross-process) ring rather than a
 * NULL handle. */
typedef struct
{
    unsigned char buf[4096];
    unsigned int head, tail;
    int in_use;
} DUETOS_PIPE_RING;
static DUETOS_PIPE_RING g_pipe;

#define DUETOS_PIPE_RD ((HANDLE)(unsigned long long)0xA0010001ULL)
#define DUETOS_PIPE_WR ((HANDLE)(unsigned long long)0xA0010002ULL)

__declspec(dllexport) BOOL CreatePipe(HANDLE* rd, HANDLE* wr, void* sa, DWORD sz)
{
    (void)sa;
    (void)sz;
    if (rd == (HANDLE*)0 || wr == (HANDLE*)0)
        return 0;
    /* SYS_WIN32_CREATE_PIPE = 186. Returns 0 on success with
     * both handles written to the user pointers; non-zero on
     * pool / table full. */
    unsigned long long read_h = 0;
    unsigned long long write_h = 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)186), "D"((long long)&read_h), "S"((long long)&write_h)
                     : "memory");
    if (rv == 0 && read_h != 0 && write_h != 0)
    {
        *rd = (HANDLE)(UINT_PTR)read_h;
        *wr = (HANDLE)(UINT_PTR)write_h;
        return 1;
    }
    /* Kernel-side allocation failed — fall back to the in-process
     * ring. Loses cross-process semantics but keeps existing
     * single-process callers working. */
    g_pipe.head = 0;
    g_pipe.tail = 0;
    g_pipe.in_use = 1;
    *rd = DUETOS_PIPE_RD;
    *wr = DUETOS_PIPE_WR;
    return 1;
}

/* Win32 named-pipe surface — CreateNamedPipeA/W + helpers.
 *
 * Backed by SYS_NAMED_PIPE_CREATE (202) on the server side and the
 * "\\.\pipe\NAME" prefix branch of CreateFileW on the client side
 * (which dispatches SYS_NAMED_PIPE_OPEN (203)). The kernel
 * ipc::named_pipes registry maps the name to a kernel pipe-pool
 * slot; ReadFile / WriteFile / CloseHandle on the returned handles
 * dispatch through the same FsBackingKind::Pipe code path that
 * anonymous CreatePipe handles already use.
 *
 * v0 honours PIPE_ACCESS_INBOUND (0x01) and PIPE_ACCESS_OUTBOUND
 * (0x02) only. DUPLEX (0x03) requires two pool slots and is
 * rejected at the syscall layer; callers see INVALID_HANDLE_VALUE.
 * ConnectNamedPipe is a no-op that returns TRUE (clients may
 * already have connected by the time the server calls it; v0 has
 * no overlapped-wait surface). WaitNamedPipe is a one-shot
 * "is the name registered?" probe. */

#define DUETOS_PIPE_ACCESS_INBOUND 0x00000001UL
#define DUETOS_PIPE_ACCESS_OUTBOUND 0x00000002UL
#define DUETOS_PIPE_ACCESS_DUPLEX 0x00000003UL

#define DUETOS_PIPE_NAME_PREFIX_LEN 9 /* "\\.\pipe\" or "//./pipe/" */

static int duetos_named_pipe_strip_prefix_a(const char* in, char* out, int out_cap)
{
    if (in == (const char*)0 || out == (char*)0 || out_cap <= 1)
        return 0;
    int i = 0;
    int j = 0;
    /* Accept either "\\.\pipe\" or the slash-normalised form
     * "//./pipe/". Anything else fails — the kernel registry holds
     * bare names only. */
    if (!((in[0] == '\\' && in[1] == '\\' && in[2] == '.' && in[3] == '\\' && in[4] == 'p' && in[5] == 'i' &&
           in[6] == 'p' && in[7] == 'e' && in[8] == '\\') ||
          (in[0] == '/' && in[1] == '/' && in[2] == '.' && in[3] == '/' && in[4] == 'p' && in[5] == 'i' &&
           in[6] == 'p' && in[7] == 'e' && in[8] == '/')))
        return 0;
    i = DUETOS_PIPE_NAME_PREFIX_LEN;
    while (j + 1 < out_cap && in[i] != '\0')
        out[j++] = in[i++];
    out[j] = '\0';
    return j;
}

__declspec(dllexport) HANDLE CreateNamedPipeA(const char* lpName, DWORD dwOpenMode, DWORD dwPipeMode,
                                              DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize,
                                              DWORD nDefaultTimeOut, void* lpSecurityAttributes)
{
    (void)dwPipeMode;
    (void)nMaxInstances;
    (void)nOutBufferSize;
    (void)nInBufferSize;
    (void)nDefaultTimeOut;
    (void)lpSecurityAttributes;
    char bare[96];
    const int name_len = duetos_named_pipe_strip_prefix_a(lpName, bare, sizeof(bare));
    if (name_len <= 0)
        return (HANDLE)(long long)-1; /* INVALID_HANDLE_VALUE */
    const unsigned long mode = (dwOpenMode & DUETOS_PIPE_ACCESS_DUPLEX);
    /* DUPLEX is rejected at the kernel boundary too; fail fast here
     * so callers can fall back without paying the syscall cost. */
    if (mode != DUETOS_PIPE_ACCESS_INBOUND && mode != DUETOS_PIPE_ACCESS_OUTBOUND)
        return (HANDLE)(long long)-1;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)202), /* SYS_NAMED_PIPE_CREATE */
                       "D"((long long)bare), "S"((long long)name_len), "d"((long long)mode)
                     : "memory");
    return (HANDLE)rv;
}

__declspec(dllexport) HANDLE CreateNamedPipeW(const wchar_t16* lpName, DWORD dwOpenMode, DWORD dwPipeMode,
                                              DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize,
                                              DWORD nDefaultTimeOut, void* lpSecurityAttributes)
{
    if (lpName == (const wchar_t16*)0)
        return (HANDLE)(long long)-1;
    char ascii[128];
    int j = 0;
    while (j < (int)(sizeof(ascii) - 1) && lpName[j] != 0)
    {
        ascii[j] = (char)(lpName[j] & 0xFF);
        ++j;
    }
    ascii[j] = '\0';
    return CreateNamedPipeA(ascii, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize, nInBufferSize,
                            nDefaultTimeOut, lpSecurityAttributes);
}

/* ConnectNamedPipe — Win32 contract: block until a client connects
 * (or return immediately with ERROR_PIPE_CONNECTED if one already
 * has). v0's kernel registry doesn't expose an "is connected?"
 * probe, and clients can connect at any time after CreateNamedPipe
 * returns, so we treat ConnectNamedPipe as a non-blocking always-
 * succeed. Server code that relies on the synchronisation gets a
 * GAP — documented in ipc/named_pipes.h. */
__declspec(dllexport) BOOL ConnectNamedPipe(HANDLE h, void* lpOverlapped)
{
    (void)h;
    (void)lpOverlapped;
    return 1;
}

/* DisconnectNamedPipe — server-side disconnect. The Win32 contract
 * lets the server keep the handle and re-issue ConnectNamedPipe;
 * v0 just no-ops and returns TRUE. The caller's eventual CloseHandle
 * tears down the pipe pool slot and registry entry. */
__declspec(dllexport) BOOL DisconnectNamedPipe(HANDLE h)
{
    (void)h;
    return 1;
}

/* WaitNamedPipe — caller wants to know if a server is listening on
 * NAME before calling CreateFile. v0 tries an OPEN, and if it
 * succeeds, immediately closes the new handle and returns TRUE.
 * Caller should still CreateFile to obtain the real client handle.
 * dwTimeout is ignored — the registry is non-blocking. */
__declspec(dllexport) BOOL WaitNamedPipeA(const char* lpName, DWORD dwTimeout)
{
    (void)dwTimeout;
    char bare[96];
    const int name_len = duetos_named_pipe_strip_prefix_a(lpName, bare, sizeof(bare));
    if (name_len <= 0)
        return 0;
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)203), /* SYS_NAMED_PIPE_OPEN */
                       "D"((long long)bare), "S"((long long)name_len)
                     : "memory");
    if (rv < 0x100 || rv >= 0x110)
        return 0;
    /* Close the test-open handle so the caller's real CreateFileW
     * can take its place — single-instance pipes have only one
     * client slot. */
    __asm__ volatile("int $0x80"
                     :
                     : "a"((long long)22), /* SYS_FILE_CLOSE */
                       "D"(rv)
                     : "memory");
    return 1;
}

__declspec(dllexport) BOOL WaitNamedPipeW(const wchar_t16* lpName, DWORD dwTimeout)
{
    if (lpName == (const wchar_t16*)0)
        return 0;
    char ascii[128];
    int j = 0;
    while (j < (int)(sizeof(ascii) - 1) && lpName[j] != 0)
    {
        ascii[j] = (char)(lpName[j] & 0xFF);
        ++j;
    }
    ascii[j] = '\0';
    return WaitNamedPipeA(ascii, dwTimeout);
}

/* VirtualQuery — return MEMORY_BASIC_INFORMATION for the supplied
 * pointer. v0 reports MEM_COMMIT|PAGE_READWRITE for any non-NULL
 * input — sufficient for stdio probes that just want the call to
 * succeed. */
typedef struct
{
    void* BaseAddress;
    void* AllocationBase;
    DWORD AllocationProtect;
    unsigned short PartitionId;
    SIZE_T RegionSize;
    DWORD State;
    DWORD Protect;
    DWORD Type;
} DUETOS_MBI;

__declspec(dllexport) SIZE_T VirtualQuery(const void* addr, DUETOS_MBI* info, SIZE_T n)
{
    if (info == (DUETOS_MBI*)0 || n < sizeof(*info))
        return 0;
    info->BaseAddress = (void*)((unsigned long long)addr & ~0xFFFULL);
    info->AllocationBase = info->BaseAddress;
    info->AllocationProtect = 0x04; /* PAGE_READWRITE */
    info->PartitionId = 0;
    info->RegionSize = 0x1000;
    info->State = 0x1000; /* MEM_COMMIT */
    info->Protect = 0x04;
    info->Type = 0x20000; /* MEM_PRIVATE */
    return sizeof(*info);
}

/* SetErrorMode / GetErrorMode — in-memory state. */
static UINT g_kernel32_error_mode = 0;
__declspec(dllexport) UINT SetErrorMode(UINT mode)
{
    UINT prev = g_kernel32_error_mode;
    g_kernel32_error_mode = mode;
    return prev;
}
__declspec(dllexport) UINT GetErrorMode(void)
{
    return g_kernel32_error_mode;
}

/* GetComputerNameExW — return "duetos" for any name-type. */
__declspec(dllexport) BOOL GetComputerNameExW(int name_type, wchar_t16* buf, DWORD* sz)
{
    (void)name_type;
    if (sz == (DWORD*)0)
        return 0;
    static const wchar_t16 hn[] = {'d', 'u', 'e', 't', 'o', 's', 0};
    DWORD needed = 7;
    if (buf == (wchar_t16*)0 || *sz < needed)
    {
        *sz = needed;
        return 0;
    }
    for (int i = 0; i < 7; ++i)
        buf[i] = hn[i];
    *sz = 6;
    return 1;
}

/* GetLogicalDriveStringsA — return "X:\\\0\0" to match the
 * X-drive sentinel that GetLogicalDrives, GetTempPath,
 * GetWindowsDirectory, GetSystemDirectory and the env-var
 * defaults all use. */
__declspec(dllexport) DWORD GetLogicalDriveStringsA(DWORD bufsz, char* buf)
{
    if (bufsz < 5 || buf == (char*)0)
        return 5;
    buf[0] = 'X';
    buf[1] = ':';
    buf[2] = '\\';
    buf[3] = 0;
    buf[4] = 0;
    return 4;
}

/* GetProcessHandleCount — sentinel. */
__declspec(dllexport) BOOL GetProcessHandleCount(HANDLE p, DWORD* count)
{
    (void)p;
    if (count != (DWORD*)0)
        *count = 8;
    return 1;
}

__declspec(dllexport) DWORD GetPrivateProfileStringA(const char* section, const char* key, const char* def_val,
                                                     char* buf, DWORD size, const char* file)
{
    (void)section;
    (void)key;
    (void)file;
    if (buf == (char*)0 || size == 0)
        return 0;
    if (def_val == (const char*)0)
    {
        buf[0] = 0;
        return 0;
    }
    DWORD i = 0;
    while (i < size - 1 && def_val[i] != 0)
    {
        buf[i] = def_val[i];
        ++i;
    }
    buf[i] = 0;
    return i;
}

__declspec(dllexport) UINT GetPrivateProfileIntA(const char* section, const char* key, int def_val, const char* file)
{
    (void)section;
    (void)key;
    (void)file;
    return (UINT)def_val;
}

__declspec(dllexport) DWORD GetProfileStringA(const char* section, const char* key, const char* def_val, char* buf,
                                              DWORD size)
{
    return GetPrivateProfileStringA(section, key, def_val, buf, size, "");
}

__declspec(dllexport) DWORD GetFullPathNameW(const wchar_t16* lpFileName, DWORD nBufferLength, wchar_t16* lpBuffer,
                                             wchar_t16** lpFilePart)
{
    (void)lpFilePart;
    if (lpFileName == (const WCHAR_t*)0 || lpBuffer == (wchar_t16*)0)
        return 0;
    int srclen = 0;
    while (lpFileName[srclen] != 0)
        ++srclen;
    int add_drive = (srclen > 0 && (lpFileName[0] == '\\' || lpFileName[0] == '/')) ? 2 : 0;
    DWORD needed = (DWORD)(srclen + 1 + add_drive);
    if (needed > nBufferLength)
        return needed;
    int j = 0;
    if (add_drive)
    {
        lpBuffer[j++] = 'C';
        lpBuffer[j++] = ':';
    }
    for (int i = 0; i < srclen; ++i)
        lpBuffer[j++] = lpFileName[i];
    lpBuffer[j] = 0;
    return (DWORD)j;
}

/* GetCPInfo — fill a CPINFO so callers checking MaxCharSize > 0
 * pass. We only support CP_ACP / CP_OEMCP / CP_UTF8 / CP_THREAD_ACP
 * out-of-the-box; anything else still gets a generic single-byte
 * code page. The DefaultChar is "?" for fidelity with ANSI Windows. */
typedef struct
{
    unsigned int MaxCharSize;
    unsigned char DefaultChar[2];
    unsigned char LeadByte[12];
} DUETOS_CPINFO;

__declspec(dllexport) BOOL GetCPInfo(unsigned int CodePage, DUETOS_CPINFO* lpCPInfo)
{
    if (lpCPInfo == (DUETOS_CPINFO*)0)
        return 0;
    for (int i = 0; i < 12; ++i)
        lpCPInfo->LeadByte[i] = 0;
    lpCPInfo->DefaultChar[0] = '?';
    lpCPInfo->DefaultChar[1] = 0;
    if (CodePage == 65001) /* CP_UTF8 */
        lpCPInfo->MaxCharSize = 4;
    else
        lpCPInfo->MaxCharSize = 1; /* single-byte ANSI / OEM */
    return 1;
}

__declspec(dllexport) int LCMapStringW(unsigned long Locale, DWORD dwMapFlags, const wchar_t16* lpSrcStr, int cchSrc,
                                       wchar_t16* lpDestStr, int cchDest)
{
    (void)Locale;
    if (lpSrcStr == (const WCHAR_t*)0)
        return 0;
    /* Compute source length. */
    int src_len = cchSrc;
    if (src_len < 0)
    {
        src_len = 0;
        while (lpSrcStr[src_len] != 0)
            ++src_len;
        ++src_len; /* include NUL */
    }
    /* Sizing call — return required dest length. */
    if (cchDest == 0 || lpDestStr == (wchar_t16*)0)
        return src_len;
    if (cchDest < src_len)
        return 0;
    /* Apply the requested transformation, byte-by-byte. */
    const unsigned long LCMAP_LOWERCASE = 0x00000100;
    const unsigned long LCMAP_UPPERCASE = 0x00000200;
    for (int i = 0; i < src_len; ++i)
    {
        wchar_t16 c = lpSrcStr[i];
        if ((dwMapFlags & LCMAP_LOWERCASE) && c >= 'A' && c <= 'Z')
            c = (wchar_t16)(c + ('a' - 'A'));
        else if ((dwMapFlags & LCMAP_UPPERCASE) && c >= 'a' && c <= 'z')
            c = (wchar_t16)(c - ('a' - 'A'));
        lpDestStr[i] = c;
    }
    return src_len;
}

/* CompareStringW / CompareStringA — ordinal compare with optional
 * case-fold (NORM_IGNORECASE = 0x0001). The kernel32 thunk fallback
 * (kOffReturnTwo) always returns 2 (CSTR_EQUAL), which mis-sorts any
 * non-equal strings. The real Win32 contract is to return one of:
 *   CSTR_LESS_THAN    = 1   (lhs <  rhs)
 *   CSTR_EQUAL        = 2   (lhs == rhs)
 *   CSTR_GREATER_THAN = 3   (lhs >  rhs)
 *   0                       (error / invalid arg)
 * v0 implements ordinal compare (no locale collation tables) which
 * matches the documented behaviour when LOCALE_INVARIANT or
 * LOCALE_NEUTRAL is passed. NORM_IGNORECASE folds A-Z → a-z. */
__declspec(dllexport) int CompareStringW(unsigned long Locale, DWORD dwCmpFlags, const wchar_t16* lpString1,
                                         int cchCount1, const wchar_t16* lpString2, int cchCount2)
{
    (void)Locale;
    const unsigned long NORM_IGNORECASE = 0x00000001;
    if (lpString1 == (const WCHAR_t*)0 || lpString2 == (const WCHAR_t*)0)
        return 0;
    int n1 = cchCount1;
    if (n1 < 0)
    {
        n1 = 0;
        while (lpString1[n1] != 0)
            ++n1;
    }
    int n2 = cchCount2;
    if (n2 < 0)
    {
        n2 = 0;
        while (lpString2[n2] != 0)
            ++n2;
    }
    int n = n1 < n2 ? n1 : n2;
    int fold = (dwCmpFlags & NORM_IGNORECASE) != 0;
    for (int i = 0; i < n; ++i)
    {
        wchar_t16 a = lpString1[i];
        wchar_t16 b = lpString2[i];
        if (fold)
        {
            if (a >= 'A' && a <= 'Z')
                a = (wchar_t16)(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z')
                b = (wchar_t16)(b + ('a' - 'A'));
        }
        if (a < b)
            return 1;
        if (a > b)
            return 3;
    }
    if (n1 < n2)
        return 1;
    if (n1 > n2)
        return 3;
    return 2;
}

__declspec(dllexport) int CompareStringA(unsigned long Locale, DWORD dwCmpFlags, const char* lpString1, int cchCount1,
                                         const char* lpString2, int cchCount2)
{
    (void)Locale;
    const unsigned long NORM_IGNORECASE = 0x00000001;
    if (lpString1 == (const char*)0 || lpString2 == (const char*)0)
        return 0;
    int n1 = cchCount1;
    if (n1 < 0)
    {
        n1 = 0;
        while (lpString1[n1] != 0)
            ++n1;
    }
    int n2 = cchCount2;
    if (n2 < 0)
    {
        n2 = 0;
        while (lpString2[n2] != 0)
            ++n2;
    }
    int n = n1 < n2 ? n1 : n2;
    int fold = (dwCmpFlags & NORM_IGNORECASE) != 0;
    for (int i = 0; i < n; ++i)
    {
        unsigned char a = (unsigned char)lpString1[i];
        unsigned char b = (unsigned char)lpString2[i];
        if (fold)
        {
            if (a >= 'A' && a <= 'Z')
                a = (unsigned char)(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z')
                b = (unsigned char)(b + ('a' - 'A'));
        }
        if (a < b)
            return 1;
        if (a > b)
            return 3;
    }
    if (n1 < n2)
        return 1;
    if (n1 > n2)
        return 3;
    return 2;
}

__declspec(dllexport) int CompareStringEx(const wchar_t16* lpLocaleName, DWORD dwCmpFlags, const wchar_t16* lpString1,
                                          int cchCount1, const wchar_t16* lpString2, int cchCount2,
                                          void* lpVersionInformation, void* lpReserved, void* lParam)
{
    (void)lpLocaleName;
    (void)lpVersionInformation;
    (void)lpReserved;
    (void)lParam;
    return CompareStringW(0, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);
}

/* GetStringTypeW / GetStringTypeA — classify each input char into
 * CT_CTYPE1 bitfields. v0 covers ASCII; anything 0x80+ gets zero
 * (the conservative default — caller treats as "unknown class"). */
__declspec(dllexport) BOOL GetStringTypeW(DWORD dwInfoType, const wchar_t16* lpSrcStr, int cchSrc,
                                          unsigned short* lpCharType)
{
    /* C1_UPPER  = 0x0001, C1_LOWER  = 0x0002, C1_DIGIT = 0x0004,
     * C1_SPACE  = 0x0008, C1_PUNCT  = 0x0010, C1_CNTRL = 0x0020,
     * C1_BLANK  = 0x0040, C1_XDIGIT = 0x0080, C1_ALPHA = 0x0100. */
    if (lpSrcStr == (const WCHAR_t*)0 || lpCharType == (unsigned short*)0)
        return 0;
    int n = cchSrc;
    if (n < 0)
    {
        n = 0;
        while (lpSrcStr[n] != 0)
            ++n;
    }
    /* dwInfoType: CT_CTYPE1 = 1, CT_CTYPE2 = 2, CT_CTYPE3 = 4. We
     * support CT_CTYPE1 properly; CT_CTYPE2/3 fill zeros (which
     * matches "no class info available"). */
    if (dwInfoType != 1)
    {
        for (int i = 0; i < n; ++i)
            lpCharType[i] = 0;
        return 1;
    }
    for (int i = 0; i < n; ++i)
    {
        unsigned short c = (unsigned short)lpSrcStr[i];
        unsigned short t = 0;
        if (c >= 'A' && c <= 'Z')
            t |= 0x0001 | 0x0100; /* UPPER | ALPHA */
        if (c >= 'a' && c <= 'z')
            t |= 0x0002 | 0x0100; /* LOWER | ALPHA */
        if (c >= '0' && c <= '9')
            t |= 0x0004 | 0x0080; /* DIGIT | XDIGIT */
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            t |= 0x0080; /* XDIGIT */
        if (c == ' ')
            t |= 0x0008 | 0x0040; /* SPACE | BLANK */
        if (c == '\t')
            t |= 0x0008 | 0x0040;
        if (c == '\n' || c == '\r' || c == '\v' || c == '\f')
            t |= 0x0008;
        if (c < 0x20 || c == 0x7F)
            t |= 0x0020; /* CNTRL */
        if ((c >= 0x21 && c <= 0x2F) || (c >= 0x3A && c <= 0x40) || (c >= 0x5B && c <= 0x60) ||
            (c >= 0x7B && c <= 0x7E))
            t |= 0x0010; /* PUNCT */
        lpCharType[i] = t;
    }
    return 1;
}

__declspec(dllexport) BOOL GetStringTypeA(unsigned long Locale, DWORD dwInfoType, const char* lpSrcStr, int cchSrc,
                                          unsigned short* lpCharType)
{
    (void)Locale;
    /* Translate single-byte input to wide on the stack — same v0
     * ASCII-range classification applies. Cap at 256 chars per call;
     * larger inputs chunk through the loop. */
    if (lpSrcStr == (const char*)0 || lpCharType == (unsigned short*)0)
        return 0;
    int n = cchSrc;
    if (n < 0)
    {
        n = 0;
        while (lpSrcStr[n] != 0)
            ++n;
    }
    wchar_t16 wbuf[256];
    int off = 0;
    while (off < n)
    {
        int chunk = n - off;
        if (chunk > 256)
            chunk = 256;
        for (int i = 0; i < chunk; ++i)
            wbuf[i] = (wchar_t16)(unsigned char)lpSrcStr[off + i];
        if (!GetStringTypeW(dwInfoType, wbuf, chunk, lpCharType + off))
            return 0;
        off += chunk;
    }
    return 1;
}

__declspec(dllexport) BOOL GetStringTypeExW(unsigned long Locale, DWORD dwInfoType, const wchar_t16* lpSrcStr,
                                            int cchSrc, unsigned short* lpCharType)
{
    (void)Locale;
    return GetStringTypeW(dwInfoType, lpSrcStr, cchSrc, lpCharType);
}

/* FormatMessageW — canned messages for FORMAT_MESSAGE_FROM_SYSTEM
 * with a few common error codes. Fully real localisation /
 * inserts deferred until we have a real ntdll error table. */
__declspec(dllexport) DWORD FormatMessageW(DWORD dwFlags, const void* lpSource, DWORD dwMessageId, DWORD dwLanguageId,
                                           wchar_t16* lpBuffer, DWORD nSize, void* Arguments)
{
    (void)dwFlags;
    (void)lpSource;
    (void)dwLanguageId;
    (void)Arguments;
    if (lpBuffer == (wchar_t16*)0 || nSize == 0)
        return 0;
    static const wchar_t16 kOk[] = {'T', 'h', 'e', ' ', 'o', 'p', 'e', 'r', 'a', 't', 'i', 'o', 'n',
                                    ' ', 'c', 'o', 'm', 'p', 'l', 'e', 't', 'e', 'd', ' ', 's', 'u',
                                    'c', 'c', 'e', 's', 's', 'f', 'u', 'l', 'l', 'y', '.', 0};
    static const wchar_t16 kGen[] = {'G', 'e', 'n', 'e', 'r', 'i', 'c', ' ', 'f', 'a', 'i', 'l', 'u', 'r', 'e', '.', 0};
    static const wchar_t16 kNotFound[] = {'T', 'h', 'e', ' ', 's', 'y', 's', 't', 'e', 'm', ' ',
                                          'c', 'a', 'n', 'n', 'o', 't', ' ', 'f', 'i', 'n', 'd',
                                          ' ', 't', 'h', 'e', ' ', 'p', 'a', 't', 'h', '.', 0};
    const wchar_t16* msg;
    if (dwMessageId == 0)
        msg = kOk;
    else if (dwMessageId == 3)
        msg = kNotFound; /* ERROR_PATH_NOT_FOUND */
    else
        msg = kGen;
    DWORD i = 0;
    while (msg[i] != 0 && i < nSize - 1)
    {
        lpBuffer[i] = msg[i];
        ++i;
    }
    lpBuffer[i] = 0;
    return i;
}

__declspec(dllexport) DWORD ExpandEnvironmentStringsA(const char* src, char* dst, DWORD size)
{
    /* Route through the wide implementation so the %VAR% expansion
     * lives in one place. Convert src ASCII → UTF-16, expand,
     * convert the result back to ASCII. The narrow buffer caps the
     * intermediate at DUETOS_ENV_VAL * DUETOS_ENV_MAX which is
     * comfortably larger than any path or command-line value the
     * v0 env table can hold. */
    if (src == (const char*)0)
        return 0;

    enum
    {
        kScratch = DUETOS_ENV_VAL * 8
    };
    wchar_t16 wsrc[kScratch];
    wchar_t16 wdst[kScratch];

    int slen = 0;
    while (slen < kScratch - 1 && src[slen] != 0)
    {
        wsrc[slen] = (wchar_t16)(unsigned char)src[slen];
        ++slen;
    }
    wsrc[slen] = 0;

    DWORD wresult = ExpandEnvironmentStringsW(wsrc, wdst, (DWORD)kScratch);
    /* wresult includes the NUL. The expanded text is in wdst[0..wresult-1]. */
    if (dst == (char*)0 || size == 0)
        return wresult;

    DWORD copy_len = wresult; /* includes NUL */
    if (copy_len > size)
        copy_len = size; /* truncate but always leave NUL */
    if (copy_len == 0)
        return wresult;

    DWORD j;
    for (j = 0; j + 1 < copy_len; ++j)
        dst[j] = (char)(wdst[j] & 0xFF);
    dst[j] = 0;
    return wresult;
}

__declspec(dllexport) wchar_t16* lstrcatW(wchar_t16* dst, const wchar_t16* src)
{
    if (dst == (wchar_t16*)0 || src == (const WCHAR_t*)0)
        return dst;
    wchar_t16* d = dst;
    while (*d != 0)
        ++d;
    while ((*d++ = *src++) != 0)
    { /* copy including NUL */
    }
    return dst;
}

/* ------------------------------------------------------------------
 * File / console I/O
 *
 * Backed by the file syscall family:
 *   SYS_WRITE      = 2  — fd-based write (fd=1 → stdout)
 *   SYS_FILE_OPEN  = 20 — open (rdi=ASCII path, rsi=len)
 *   SYS_FILE_READ  = 21 — read (rdi=handle, rsi=buf, rdx=count)
 *   SYS_FILE_CLOSE = 22 — close (rdi=handle, no-op for unknown)
 *   SYS_FILE_SEEK  = 23 — seek (rdi=handle, rsi=offset, rdx=whence)
 *   SYS_FILE_FSTAT = 24 — fstat-style size (rdi=handle, rsi=outptr)
 *
 * The Win32 contract: handle goes in rcx, then rdx, r8, r9 for
 * args 2-4, with arg 5+ on the stack. Our SYS_* take args in
 * rdi, rsi, rdx, r10, r8, r9 — so the trampolines mostly just
 * shuffle the calling convention.
 *
 * WriteFile dispatches by handle range:
 *   - Pipe sentinel handles (DUETOS_PIPE_WR/_RD) → in-process
 *     anonymous-pipe ring.
 *   - Kernel file handles (0x100..0x10F, planted by CreateFileW
 *     via SYS_FILE_OPEN / SYS_FILE_CREATE) → SYS_FILE_WRITE
 *     (syscall 43); cap-gated on kCapFsWrite. Routes through the
 *     per-handle cursor + fat32 in-place-or-grow write.
 *   - Std-output / std-error handles (the negative-int values
 *     GetStdHandle hands back: STD_OUTPUT_HANDLE = (HANDLE)-11,
 *     STD_ERROR_HANDLE = (HANDLE)-12) → SYS_WRITE(fd=1).
 *   - Anything else → fail (return FALSE, *lpWritten = 0). The
 *     legacy "dump everything to stdout" fallback used to mask
 *     bugs where a Win32 caller passed a stale handle.
 *
 * WriteConsole* always route to stdout regardless of handle —
 * they're console-bound by Win32 contract.
 * ------------------------------------------------------------------ */

typedef void* LPDWORD_t; /* DWORD* via opaque pointer to avoid C-warning chains */

__declspec(dllexport) BOOL WriteFile(HANDLE hFile, const void* buf, DWORD n, DWORD* lpWritten, void* lpOverlapped)
{
    /* Anonymous pipe: push bytes into the in-process ring instead
     * of routing to stdout. Drop oldest on overflow to keep the
     * producer non-blocking; matches the v0 stdin-ring policy on
     * the kernel side. */
    if (hFile == DUETOS_PIPE_WR && g_pipe.in_use)
    {
        const unsigned char* src = (const unsigned char*)buf;
        DWORD wrote = 0;
        while (wrote < n)
        {
            if (g_pipe.head - g_pipe.tail >= sizeof(g_pipe.buf))
                ++g_pipe.tail;
            g_pipe.buf[g_pipe.head & 0xFFF] = src[wrote++];
            ++g_pipe.head;
        }
        if (lpWritten != (DWORD*)0)
            *lpWritten = wrote;
        return 1;
    }

    const unsigned long long h_raw = (unsigned long long)(UINT_PTR)hFile;

    /* Kernel file handle (Win32-shaped pseudo-handle): 0x100..0x10F.
     * Route through SYS_FILE_WRITE so the per-handle cursor +
     * canary wall + cap gate fire. T7-03: when lpOverlapped is
     * supplied, honour OVERLAPPED.Offset (seek before write) and
     * write OVERLAPPED.Internal / InternalHigh on completion. If
     * the file is bound to an IOCP via CreateIoCompletionPort,
     * post a completion packet so GetQueuedCompletionStatus
     * surfaces the result. */
    if (h_raw >= 0x100ULL && h_raw < 0x110ULL)
    {
        if (lpOverlapped != (void*)0)
        {
            const unsigned long long ov_off = win32_overlapped_offset(lpOverlapped);
            if (ov_off != 0xFFFFFFFFFFFFFFFFULL)
            {
                long long seek_rv;
                __asm__ volatile("int $0x80"
                                 : "=a"(seek_rv)
                                 : "a"((long long)23),                                              /* SYS_FILE_SEEK */
                                   "D"((long long)h_raw), "S"((long long)ov_off), "d"((long long)0) /* SEEK_SET */
                                 : "memory");
                (void)seek_rv;
            }
        }
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)43), /* SYS_FILE_WRITE */
                           "D"((long long)h_raw), "S"((long long)buf), "d"((long long)n)
                         : "memory");
        const int ok = (rv >= 0 && (unsigned long long)rv != ~0ULL);
        const DWORD bytes = ok ? (DWORD)rv : 0;
        if (lpWritten != (DWORD*)0)
            *lpWritten = bytes;
        if (lpOverlapped != (void*)0)
        {
            win32_overlapped_complete(lpOverlapped, ok ? 0ULL : 0xC0000001ULL, (unsigned long long)bytes);
            const int bidx = win32_iocp_lookup_binding(hFile);
            if (bidx >= 0)
            {
                const int slot = win32_iocp_slot_of_handle(g_iocp_bindings[bidx].iocp_handle);
                win32_iocp_post_internal(slot, bytes, g_iocp_bindings[bidx].completion_key, lpOverlapped);
            }
        }
        return ok ? 1 : 0;
    }

    /* Std handles. GetStdHandle zero-extends DWORD into HANDLE,
     * so STD_OUTPUT_HANDLE = (DWORD)-11 = 0xFFFFFFF5 surfaces as
     * 0x00000000FFFFFFF5 here. STD_INPUT (-10) is invalid for a
     * write but we silently route it the same way the flat-stub
     * impl did. */
    if (h_raw == 0xFFFFFFF5ULL || h_raw == 0xFFFFFFF4ULL || h_raw == 0xFFFFFFF6ULL)
    {
        long long rv;
        __asm__ volatile("int $0x80"
                         : "=a"(rv)
                         : "a"((long long)2),   /* SYS_WRITE */
                           "D"((long long)1),   /* fd=1 (stdout) */
                           "S"((long long)buf), /* buf */
                           "d"((long long)n)    /* count */
                         : "memory");
        if (lpWritten != (DWORD*)0)
            *lpWritten = rv >= 0 ? (DWORD)rv : 0;
        return rv >= 0 ? 1 : 0;
    }

    /* Unknown handle — fail rather than silently routing to
     * stdout. Caller almost certainly passed a stale or never-
     * opened handle. */
    if (lpWritten != (DWORD*)0)
        *lpWritten = 0;
    return 0;
}

__declspec(dllexport) BOOL WriteConsoleA(HANDLE hConsole, const void* buf, DWORD n, DWORD* lpWritten, void* lpReserved)
{
    /* Same shape as WriteFile — alias the impl. */
    return WriteFile(hConsole, buf, n, lpWritten, lpReserved);
}

/* WriteConsoleW — n is wide-char count. Emit each wchar's low
 * byte to stdout (UTF-16 → ASCII strip; fine for ASCII and
 * Latin-1 codepoints, garbles the rest. Same approximation as
 * the flat stub at kOffWriteConsoleW). */
__declspec(dllexport) BOOL WriteConsoleW(HANDLE hConsole, const wchar_t16* buf, DWORD n, DWORD* lpWritten,
                                         void* lpReserved)
{
    (void)hConsole;
    (void)lpReserved;
    if (buf == (const WCHAR_t*)0 || n == 0)
    {
        if (lpWritten != (DWORD*)0)
            *lpWritten = 0;
        return 1;
    }
    /* Strip into a stack-local ASCII buffer up to 256 bytes
     * per call. CRT writes typically come a line at a time so
     * this is rarely a real cap. */
    char ascii[256];
    DWORD cap = n > 256 ? 256 : n;
    for (DWORD i = 0; i < cap; ++i)
        ascii[i] = (char)(buf[i] & 0xFF);
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)2), /* SYS_WRITE */
                       "D"((long long)1), /* fd=1 */
                       "S"((long long)ascii), "d"((long long)cap)
                     : "memory");
    if (lpWritten != (DWORD*)0)
        *lpWritten = rv >= 0 ? (DWORD)rv : 0;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL CloseHandle(HANDLE h)
{
    long long discard;
    __asm__ volatile("int $0x80"
                     : "=a"(discard)
                     : "a"((long long)22), /* SYS_FILE_CLOSE */
                       "D"((long long)h)
                     : "memory");
    return 1; /* Match flat-stub: always TRUE — kernel side
               * handles unknown handles as a no-op. */
}

/* CreateFileW — wide path in rcx (lpFileName), other args
 * ignored. UTF-16 → ASCII strip on a stack-local buffer, then
 * SYS_FILE_OPEN(rdi=path, rsi=len). Returns the kernel handle
 * (Win32-shaped 0x100..0x10F) or -1 on failure. */
__declspec(dllexport) HANDLE CreateFileW(const wchar_t16* lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                         void* lpSecurityAttributes, DWORD dwCreationDisposition,
                                         DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    (void)dwDesiredAccess;
    (void)dwShareMode;
    (void)lpSecurityAttributes;
    (void)dwCreationDisposition;
    (void)dwFlagsAndAttributes;
    (void)hTemplateFile;
    if (lpFileName == (const WCHAR_t*)0)
        return (HANDLE)(long long)-1; /* INVALID_HANDLE_VALUE */
    /* UTF-16 → ASCII; normalise '\\' → '/' so Windows-style paths
     * match the kernel ramfs's POSIX-style lookup. Optional drive
     * prefix "C:" / "c:" is stripped — DuetOS has one logical
     * volume; drive letters are vestigial from the Win32 ABI. */
    char ascii[256];
    int i = 0;
    int j = 0;
    /* Skip drive letter prefix if present. */
    if (lpFileName[0] != 0 && lpFileName[1] == ':' &&
        ((lpFileName[0] >= 'A' && lpFileName[0] <= 'Z') || (lpFileName[0] >= 'a' && lpFileName[0] <= 'z')))
        i = 2;
    while (j < 255 && lpFileName[i] != 0)
    {
        char c = (char)(lpFileName[i] & 0xFF);
        ascii[j++] = (c == '\\') ? '/' : c;
        ++i;
    }
    ascii[j] = '\0';
    i = j;
    /* Named-pipe prefix recognition. After backslash normalisation,
     * "\\.\pipe\NAME" becomes "//./pipe/NAME". Route through
     * SYS_NAMED_PIPE_OPEN (203) with the bare name instead of
     * dispatching SYS_FILE_OPEN (which would miss in ramfs / FAT32). */
    if (j > 9 && ascii[0] == '/' && ascii[1] == '/' && ascii[2] == '.' && ascii[3] == '/' && ascii[4] == 'p' &&
        ascii[5] == 'i' && ascii[6] == 'p' && ascii[7] == 'e' && ascii[8] == '/')
    {
        const char* name = ascii + 9;
        const int name_len = j - 9;
        long long rv_pipe;
        __asm__ volatile("int $0x80"
                         : "=a"(rv_pipe)
                         : "a"((long long)203), /* SYS_NAMED_PIPE_OPEN */
                           "D"((long long)name), "S"((long long)name_len)
                         : "memory");
        return (HANDLE)rv_pipe;
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)20), /* SYS_FILE_OPEN */
                       "D"((long long)ascii), "S"((long long)i)
                     : "memory");
    return (HANDLE)rv;
}

__declspec(dllexport) BOOL ReadFile(HANDLE h, void* buf, DWORD count, DWORD* lpRead, void* lpOverlapped)
{
    /* Anonymous pipe: drain bytes from the in-process ring set up
     * by CreatePipe rather than dispatching SYS_FILE_READ (which
     * doesn't know the pipe sentinel handle and would return -1).
     * Single-process / single-reader / single-writer model is
     * fine for v0 — pipe_smoke and the typical "captured stdout"
     * use-case both fit. */
    if (h == DUETOS_PIPE_RD && g_pipe.in_use)
    {
        unsigned char* dst = (unsigned char*)buf;
        DWORD got = 0;
        while (got < count && g_pipe.head != g_pipe.tail)
        {
            dst[got++] = g_pipe.buf[g_pipe.tail & 0xFFF];
            ++g_pipe.tail;
        }
        if (lpRead != (DWORD*)0)
            *lpRead = got;
        return 1;
    }

    const unsigned long long h_raw = (unsigned long long)(UINT_PTR)h;

    /* Std handles: STDIN reports immediate EOF (no kbd-read syscall
     * yet); STDOUT / STDERR are write-only — Win32 convention is to
     * return TRUE with *lpRead = 0 ("end of file") rather than
     * fall through to a failing SYS_FILE_READ. */
    if (h_raw == 0xFFFFFFF6ULL || h_raw == 0xFFFFFFF5ULL || h_raw == 0xFFFFFFF4ULL)
    {
        if (lpRead != (DWORD*)0)
            *lpRead = 0;
        return 1;
    }

    /* Kernel file handle range — same numeric band as WriteFile.
     * Anything else falls through to SYS_FILE_READ which will
     * reject it with -1; we mirror that as FALSE. T7-03: honour
     * lpOverlapped for kernel file handles — seek to
     * OVERLAPPED.Offset, read, stamp Internal/InternalHigh, and
     * post a completion packet if the file is IOCP-bound. */
    if (h_raw >= 0x100ULL && h_raw < 0x110ULL && lpOverlapped != (void*)0)
    {
        const unsigned long long ov_off = win32_overlapped_offset(lpOverlapped);
        if (ov_off != 0xFFFFFFFFFFFFFFFFULL)
        {
            long long seek_rv;
            __asm__ volatile("int $0x80"
                             : "=a"(seek_rv)
                             : "a"((long long)23),                                              /* SYS_FILE_SEEK */
                               "D"((long long)h_raw), "S"((long long)ov_off), "d"((long long)0) /* SEEK_SET */
                             : "memory");
            (void)seek_rv;
        }
    }
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)21), /* SYS_FILE_READ */
                       "D"((long long)h_raw), "S"((long long)buf), "d"((long long)count)
                     : "memory");
    const int ok = (rv >= 0);
    const DWORD bytes = ok ? (DWORD)rv : 0;
    if (lpRead != (DWORD*)0)
        *lpRead = bytes;
    if (lpOverlapped != (void*)0)
    {
        win32_overlapped_complete(lpOverlapped, ok ? 0ULL : 0xC0000011ULL /* STATUS_END_OF_FILE */,
                                  (unsigned long long)bytes);
        const int bidx = win32_iocp_lookup_binding(h);
        if (bidx >= 0)
        {
            const int slot = win32_iocp_slot_of_handle(g_iocp_bindings[bidx].iocp_handle);
            win32_iocp_post_internal(slot, bytes, g_iocp_bindings[bidx].completion_key, lpOverlapped);
        }
    }
    return ok ? 1 : 0;
}

__declspec(dllexport) BOOL SetFilePointerEx(HANDLE h, long long liDistance, long long* lpNewPosition,
                                            DWORD dwMoveMethod)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)23), /* SYS_FILE_SEEK */
                       "D"((long long)h), "S"((long long)liDistance), "d"((long long)dwMoveMethod)
                     : "memory");
    if (lpNewPosition != (long long*)0)
        *lpNewPosition = rv;
    return rv >= 0 ? 1 : 0;
}

__declspec(dllexport) BOOL GetFileSizeEx(HANDLE h, long long* lpFileSize)
{
    long long rv;
    __asm__ volatile("int $0x80"
                     : "=a"(rv)
                     : "a"((long long)24), /* SYS_FILE_FSTAT */
                       "D"((long long)h), "S"((long long)lpFileSize)
                     : "memory");
    /* SYS_FILE_FSTAT returns 0 on success and writes to the
     * out pointer; non-zero is failure. */
    return rv == 0 ? 1 : 0;
}

/* GetFileSize — DWORD version. Same semantics as GetFileSizeEx
 * but returns the size in rax (low 32 bits) and writes the
 * high 32 bits via lpFileSizeHigh if non-null. */
__declspec(dllexport) DWORD GetFileSize(HANDLE h, DWORD* lpFileSizeHigh)
{
    long long size = 0;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)24), "D"((long long)h), "S"((long long)&size) : "memory");
    if (rv != 0)
        return 0xFFFFFFFFu; /* INVALID_FILE_SIZE */
    if (lpFileSizeHigh != (DWORD*)0)
        *lpFileSizeHigh = (DWORD)(size >> 32);
    return (DWORD)(size & 0xFFFFFFFFu);
}
