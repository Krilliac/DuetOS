/*
 * userland/libs/advapi32_32/advapi32_32_reg.c
 *
 * The Reg* family of the i386 (PE32) advapi32.dll companion, driven
 * by the kernel-owned Win32 registry over SYS_REGISTRY (130).
 *
 * Before this slice the four registry exports this DLL shipped were
 * constant-returners: RegOpenKeyExA always reported
 * ERROR_FILE_NOT_FOUND, RegQueryValueExA always reported a zero-byte
 * value of type REG_NONE, and RegEnumKeyExA always reported
 * ERROR_NO_MORE_ITEMS. A PE32 that stores its settings in the
 * registry saw an empty, unwritable hive.
 *
 * Design note — why the syscall and not a DLL-local tree:
 * `userland/libs/advapi32/advapi32.c` (the PE32+ sibling) carries its
 * own static registry that the kernel's tree is kept in sync with by
 * hand; registry.h's header comment calls that duplication
 * intentional-but-temporary. CLAUDE.md's "one source of truth per
 * resource" rule points the other way, and the kernel tree is the
 * strictly better one anyway: it is mutable (the sidecar value pool),
 * it persists to REGISTRY.HIV, and its mutation path is cap-gated on
 * kCapFsWrite. So the 32-bit port does not grow a third copy of the
 * tree — it calls the kernel.
 *
 * Two consequences of that choice, both marked at the call sites:
 *
 *  1. The kernel stores REG_SZ payloads as NARROW ASCII (see the
 *     kRegKeys table in kernel/subsystems/win32/registry.cpp:
 *     "DuetOS\0" is 7 bytes, not 14). The W entry points therefore
 *     transcode on BOTH edges — wide in on set, wide out on query —
 *     so an A caller and a W caller each see their own encoding and
 *     the stored form stays uniform.
 *
 *  2. A process may hold at most Process::kWin32RegistryCap == 8 open
 *     keys. RegCloseKey returns slots, so a caller that closes what it
 *     opens is unaffected; one that leaks handles runs out.
 */

#include "../common/duet32_syscall.h"

typedef unsigned int DWORD;
typedef int BOOL;
typedef void* HANDLE;
typedef HANDLE HKEY;
typedef long LONG;
typedef unsigned long LSTATUS;
typedef unsigned char BYTE;
typedef unsigned short wchar_t16;

#define SYS_REGISTRY 130

/* Sub-op selectors — mirror
 * duetos::subsystems::win32::registry::kOp* (registry.h). Stable ABI:
 * once a shipped DLL uses one of these the value is locked. */
#define REG_OP_OPEN 1
#define REG_OP_CLOSE 2
#define REG_OP_QUERY_VALUE 3
#define REG_OP_SET_VALUE 4
#define REG_OP_DELETE_VALUE 5
#define REG_OP_FLUSH 6
#define REG_OP_ENUM_VALUE 7
#define REG_OP_QUERY_KEY 8
#define REG_OP_ENUM_KEY 9

/* NTSTATUS values SYS_REGISTRY reports (registry.cpp). */
#define NT_SUCCESS_ 0x00000000u
#define NT_OBJECT_NAME_NOT_FOUND 0xC0000034u
#define NT_INVALID_HANDLE 0xC0000008u
#define NT_INVALID_PARAMETER 0xC000000Du
#define NT_BUFFER_TOO_SMALL 0xC0000023u
#define NT_INSUFFICIENT_RESOURCES 0xC000009Au
#define NT_ACCESS_DENIED 0xC0000022u
#define NT_NO_MORE_ENTRIES 0x8000001Au

/* Win32 error codes. */
#define ERROR_SUCCESS 0UL
#define ERROR_FILE_NOT_FOUND 2UL
#define ERROR_ACCESS_DENIED 5UL
#define ERROR_INVALID_HANDLE 6UL
#define ERROR_OUTOFMEMORY 14UL
#define ERROR_INVALID_PARAMETER 87UL
#define ERROR_MORE_DATA 234UL
#define ERROR_NO_MORE_ITEMS 259UL

#define REG_NONE 0UL
#define REG_SZ 1UL
#define REG_EXPAND_SZ 2UL
#define REG_BINARY 3UL
#define REG_DWORD 4UL
#define REG_MULTI_SZ 7UL

/* RegCreateKeyEx disposition out-values. */
#define REG_CREATED_NEW_KEY 1UL
#define REG_OPENED_EXISTING_KEY 2UL

/* Bounded by the kernel's own limits: kSidecarNameMax (64) for value
 * names, and the 256-byte path scratch CopyUserAsciiPath uses. */
#define REG_NAME_MAX 64
#define REG_PATH_MAX 256

/* ------------------------------------------------------------------
 * Local helpers
 * ------------------------------------------------------------------ */

static LSTATUS reg_status_to_win32(int raw)
{
    switch ((unsigned)raw)
    {
    case NT_SUCCESS_:
        return ERROR_SUCCESS;
    case NT_OBJECT_NAME_NOT_FOUND:
        return ERROR_FILE_NOT_FOUND;
    case NT_INVALID_HANDLE:
        return ERROR_INVALID_HANDLE;
    case NT_BUFFER_TOO_SMALL:
        return ERROR_MORE_DATA;
    case NT_INSUFFICIENT_RESOURCES:
        return ERROR_OUTOFMEMORY;
    case NT_ACCESS_DENIED:
        return ERROR_ACCESS_DENIED;
    case NT_NO_MORE_ENTRIES:
        return ERROR_NO_MORE_ITEMS;
    default:
        return ERROR_INVALID_PARAMETER;
    }
}

/* Flatten UTF-16 into a bounded ASCII buffer; non-ASCII code units
 * become '?'. Always NUL-terminates. */
static void reg_w_to_a(const wchar_t16* src, char* dst, unsigned cap)
{
    unsigned i = 0;
    if (cap == 0)
        return;
    if (src)
    {
        for (; i + 1 < cap && src[i] != 0; ++i)
        {
            const wchar_t16 c = src[i];
            dst[i] = (c > 0 && c < 0x7F) ? (char)c : '?';
        }
    }
    dst[i] = '\0';
}

/* Widen `n` ASCII bytes into `dst`, which holds `cap` wchar_t16
 * slots. Returns the number of code units written (excluding any
 * terminator the source carried). */
static unsigned reg_a_to_w(const char* src, unsigned n, wchar_t16* dst, unsigned cap)
{
    unsigned i = 0;
    for (; i < n && i < cap; ++i)
        dst[i] = (wchar_t16)(unsigned char)src[i];
    return i;
}

/* True for the REG_* types whose payload is text and therefore has a
 * different byte length in the A and W worlds. */
static int reg_type_is_text(DWORD type)
{
    return type == REG_SZ || type == REG_EXPAND_SZ || type == REG_MULTI_SZ;
}

/* Widest payload the kernel's mutable tier accepts (kSidecarDataMax);
 * also comfortably above every static value it ships. Doubles as the
 * narrow staging buffer size for the W entry points. */
#define REG_DATA_MAX 256

/* i386 CODEGEN TRAP — do not "simplify" the staging buffers below
 * back into `unsigned long long`.
 *
 * SYS_REGISTRY writes several of its out-slots as u64s, so the
 * obvious spelling for a staging local is `unsigned long long`. On
 * i386 that local wants 8-byte alignment, the incoming __stdcall
 * frame only guarantees 4, and clang responds by realigning the stack
 * — which pins EBP as a frame pointer. duet_syscall6 needs EBP: it is
 * the only register left for arg6 once EAX/EBX/ECX/EDX/ESI/EDI are
 * bound. The result is a hard "inline assembly requires more
 * registers than available" at every six-argument call site in the
 * translation unit.
 *
 * Every u64 the kernel writes is therefore staged as a pair of
 * 4-byte-aligned u32s: [0] is the low half, [1] the high half. The
 * kernel copies these slots with CopyToUser (a byte copy), so it has
 * no alignment expectation of its own. */
#define REG_LO 0
#define REG_HI 1

/* ------------------------------------------------------------------
 * Open / close / flush
 * ------------------------------------------------------------------ */

static LSTATUS reg_open(HKEY parent, const char* subkey, HKEY* out)
{
    if (!out)
        return ERROR_INVALID_PARAMETER;
    *out = (HKEY)0;
    unsigned slot[2] = {0, 0};
    const char* path = subkey ? subkey : "";
    const int rv = duet_syscall4(SYS_REGISTRY, REG_OP_OPEN, (unsigned)(unsigned long)parent,
                                 (unsigned)(unsigned long)path, (unsigned)(unsigned long)slot);
    const LSTATUS st = reg_status_to_win32(rv);
    if (st == ERROR_SUCCESS)
    {
        /* Registry handles live in [0x600, 0x608) —
         * Process::kWin32RegistryBase — so the 64-bit slot the kernel
         * writes always fits an i386 HKEY without loss. */
        *out = (HKEY)(unsigned long)slot[REG_LO];
    }
    return st;
}

__declspec(dllexport) LONG __stdcall RegOpenKeyExA(HKEY key, const char* subkey, DWORD opts, DWORD access, HKEY* out)
{
    /* GAP: `access` (KEY_READ / KEY_WRITE / KEY_WOW64_*) is not
     * enforced at open time — the kernel gates mutation on kCapFsWrite
     * inside the SetValue / DeleteValue ops instead, so a nominally
     * read-only handle that tries to write is refused by the cap gate
     * rather than by the open. Revisit if a per-handle access mask
     * lands kernel-side. */
    (void)opts;
    (void)access;
    return (LONG)reg_open(key, subkey, out);
}

__declspec(dllexport) LONG __stdcall RegOpenKeyExW(HKEY key, const wchar_t16* subkey, DWORD opts, DWORD access,
                                                   HKEY* out)
{
    char path[REG_PATH_MAX];
    reg_w_to_a(subkey, path, sizeof(path));
    return RegOpenKeyExA(key, path, opts, access, out);
}

__declspec(dllexport) LONG __stdcall RegOpenKeyA(HKEY key, const char* subkey, HKEY* out)
{
    return RegOpenKeyExA(key, subkey, 0, 0, out);
}

__declspec(dllexport) LONG __stdcall RegOpenKeyW(HKEY key, const wchar_t16* subkey, HKEY* out)
{
    return RegOpenKeyExW(key, subkey, 0, 0, out);
}

__declspec(dllexport) LONG __stdcall RegCloseKey(HKEY key)
{
    /* Closing a predefined root is a Win32 no-op success — those are
     * sentinels, not slots, and the kernel reports
     * STATUS_INVALID_HANDLE for them. */
    const unsigned raw = (unsigned)(unsigned long)key;
    if (raw >= 0x80000000u)
        return (LONG)ERROR_SUCCESS;
    return (LONG)reg_status_to_win32(duet_syscall2(SYS_REGISTRY, REG_OP_CLOSE, raw));
}

__declspec(dllexport) LONG __stdcall RegFlushKey(HKEY key)
{
    (void)key;
    /* The kernel persists each successful mutation to REGISTRY.HIV
     * from inside the SetValue / DeleteValue op, so an explicit flush
     * has nothing left to write. */
    return (LONG)reg_status_to_win32(duet_syscall1(SYS_REGISTRY, REG_OP_FLUSH));
}

/* ------------------------------------------------------------------
 * Value query
 * ------------------------------------------------------------------ */

/* Raw query against the kernel tree. `cap` is the byte capacity of
 * `buf` (which may be null for a size-only probe). On any status that
 * carries metadata the kernel writes a packed u64 whose low half is
 * the REG_* type and whose high half is the byte count the value
 * actually needs; both are surfaced through the out params. */
static LSTATUS reg_query_raw(HKEY key, const char* name, DWORD* type_out, BYTE* buf, DWORD cap, DWORD* need_out)
{
    unsigned packed[2] = {0, 0};
    const int rv = duet_syscall6(SYS_REGISTRY, REG_OP_QUERY_VALUE, (unsigned)(unsigned long)key,
                                 (unsigned)(unsigned long)(name ? name : ""), (unsigned)(unsigned long)buf, cap,
                                 (unsigned)(unsigned long)packed);
    const LSTATUS st = reg_status_to_win32(rv);
    if (st == ERROR_SUCCESS || st == ERROR_MORE_DATA)
    {
        if (type_out)
            *type_out = (DWORD)packed[REG_LO];
        if (need_out)
            *need_out = (DWORD)packed[REG_HI];
    }
    return st;
}

__declspec(dllexport) LONG __stdcall RegQueryValueExA(HKEY key, const char* name, DWORD* reserved, DWORD* type,
                                                      BYTE* data, DWORD* cb)
{
    (void)reserved;
    const DWORD cap = (cb && data) ? *cb : 0;
    DWORD need = 0;
    DWORD local_type = REG_NONE;
    const LSTATUS st = reg_query_raw(key, name, &local_type, data, cap, &need);
    if (st == ERROR_SUCCESS || st == ERROR_MORE_DATA)
    {
        if (type)
            *type = local_type;
        if (cb)
            *cb = need;
    }
    return (LONG)st;
}

__declspec(dllexport) LONG __stdcall RegQueryValueExW(HKEY key, const wchar_t16* name, DWORD* reserved, DWORD* type,
                                                      BYTE* data, DWORD* cb)
{
    (void)reserved;
    char aname[REG_NAME_MAX];
    reg_w_to_a(name, aname, sizeof(aname));

    /* Stage through a narrow buffer: the kernel's payloads are ASCII
     * (see the file header), so a text value has to be widened before
     * it can satisfy a W caller, and the caller's byte budget is in
     * wide bytes. Non-text types pass straight through. */
    BYTE stage[REG_DATA_MAX];
    DWORD need = 0;
    DWORD local_type = REG_NONE;
    LSTATUS st = reg_query_raw(key, aname, &local_type, stage, (DWORD)sizeof(stage), &need);
    if (st != ERROR_SUCCESS && st != ERROR_MORE_DATA)
        return (LONG)st;
    if (type)
        *type = local_type;

    if (!reg_type_is_text(local_type))
    {
        const DWORD cap = (cb && data) ? *cb : 0;
        if (cb)
            *cb = need;
        if (!data)
            return (LONG)ERROR_SUCCESS;
        if (st == ERROR_MORE_DATA || cap < need)
            return (LONG)ERROR_MORE_DATA;
        for (DWORD i = 0; i < need; ++i)
            data[i] = stage[i];
        return (LONG)ERROR_SUCCESS;
    }

    /* GAP: a text value longer than REG_DATA_MAX narrow bytes cannot
     * be staged, so the wide byte count is reported but no bytes are
     * handed back. The kernel's own mutable tier caps payloads at
     * exactly REG_DATA_MAX, so this is only reachable if a future
     * static value exceeds it. */
    const DWORD wide_bytes = need * 2u;
    const DWORD cap = (cb && data) ? *cb : 0;
    if (cb)
        *cb = wide_bytes;
    if (!data)
        return (LONG)ERROR_SUCCESS;
    if (st == ERROR_MORE_DATA || cap < wide_bytes)
        return (LONG)ERROR_MORE_DATA;
    (void)reg_a_to_w((const char*)stage, need, (wchar_t16*)data, need);
    return (LONG)ERROR_SUCCESS;
}

/* RegGetValueW / A — the "open-less" convenience wrapper. `flags`
 * carries RRF_RT_* type restrictions; the type actually stored is
 * reported through `type` either way.
 *
 * GAP: the RRF_RT_* type filter is not enforced and RRF_NOEXPAND is
 * ignored (the kernel tree stores no REG_EXPAND_SZ values today, so
 * there is nothing to expand). A caller that asked for RRF_RT_DWORD
 * and got a REG_SZ must check `type` itself. */
__declspec(dllexport) LONG __stdcall RegGetValueA(HKEY key, const char* subkey, const char* value, DWORD flags,
                                                  DWORD* type, void* data, DWORD* cb)
{
    (void)flags;
    HKEY scoped = key;
    int opened = 0;
    if (subkey && subkey[0])
    {
        const LSTATUS st = reg_open(key, subkey, &scoped);
        if (st != ERROR_SUCCESS)
            return (LONG)st;
        opened = 1;
    }
    const LONG rv = RegQueryValueExA(scoped, value, 0, type, (BYTE*)data, cb);
    if (opened)
        (void)RegCloseKey(scoped);
    return rv;
}

__declspec(dllexport) LONG __stdcall RegGetValueW(HKEY key, const wchar_t16* subkey, const wchar_t16* value,
                                                  DWORD flags, DWORD* type, void* data, DWORD* cb)
{
    (void)flags;
    HKEY scoped = key;
    int opened = 0;
    if (subkey && subkey[0])
    {
        char path[REG_PATH_MAX];
        reg_w_to_a(subkey, path, sizeof(path));
        const LSTATUS st = reg_open(key, path, &scoped);
        if (st != ERROR_SUCCESS)
            return (LONG)st;
        opened = 1;
    }
    const LONG rv = RegQueryValueExW(scoped, value, 0, type, (BYTE*)data, cb);
    if (opened)
        (void)RegCloseKey(scoped);
    return rv;
}

/* ------------------------------------------------------------------
 * Value mutation
 *
 * Both ops are cap-gated kernel-side on kCapFsWrite (registry.cpp
 * DoSetValue / DoDeleteValue) — a sandboxed PE32 that lacks the cap
 * gets STATUS_ACCESS_DENIED, surfaced here as ERROR_ACCESS_DENIED.
 * Nothing on this path can write registry state the calling process
 * is not already cleared for.
 * ------------------------------------------------------------------ */

__declspec(dllexport) LONG __stdcall RegSetValueExA(HKEY key, const char* name, DWORD reserved, DWORD type,
                                                    const BYTE* data, DWORD cb)
{
    (void)reserved;
    return (LONG)reg_status_to_win32(duet_syscall6(SYS_REGISTRY, REG_OP_SET_VALUE, (unsigned)(unsigned long)key,
                                                   (unsigned)(unsigned long)(name ? name : ""),
                                                   (unsigned)(unsigned long)data, cb, type));
}

__declspec(dllexport) LONG __stdcall RegSetValueExW(HKEY key, const wchar_t16* name, DWORD reserved, DWORD type,
                                                    const BYTE* data, DWORD cb)
{
    char aname[REG_NAME_MAX];
    reg_w_to_a(name, aname, sizeof(aname));
    if (!reg_type_is_text(type) || !data)
        return RegSetValueExA(key, aname, reserved, type, data, cb);

    /* Narrow the payload so the stored form matches what the A entry
     * points and the kernel's own static tree use. `cb` is in wide
     * bytes; the flattened value is half that, code unit for code
     * unit, with the terminator preserved. */
    char narrow[REG_DATA_MAX];
    const DWORD units = cb / 2u;
    DWORD n = 0;
    const wchar_t16* w = (const wchar_t16*)data;
    for (; n < units && n < (DWORD)sizeof(narrow); ++n)
    {
        const wchar_t16 c = w[n];
        narrow[n] = (c > 0 && c < 0x7F) ? (char)c : (c == 0 ? '\0' : '?');
    }
    return RegSetValueExA(key, aname, reserved, type, (const BYTE*)narrow, n);
}

__declspec(dllexport) LONG __stdcall RegDeleteValueA(HKEY key, const char* name)
{
    return (LONG)reg_status_to_win32(duet_syscall3(SYS_REGISTRY, REG_OP_DELETE_VALUE, (unsigned)(unsigned long)key,
                                                   (unsigned)(unsigned long)(name ? name : "")));
}

__declspec(dllexport) LONG __stdcall RegDeleteValueW(HKEY key, const wchar_t16* name)
{
    char aname[REG_NAME_MAX];
    reg_w_to_a(name, aname, sizeof(aname));
    return RegDeleteValueA(key, aname);
}

/* ------------------------------------------------------------------
 * Key creation / deletion
 *
 * The kernel registry has a fixed key tree — registry.h states
 * NtCreateKey / NtDeleteKey are unimplemented and only VALUES on
 * existing keys are mutable. Rather than report a success the caller
 * cannot observe, RegCreateKeyEx degrades to an open: an existing
 * well-known key comes back with REG_OPENED_EXISTING_KEY (and is then
 * fully writable through RegSetValueEx), and anything else fails the
 * way Win32 fails when creation is refused.
 * ------------------------------------------------------------------ */

__declspec(dllexport) LONG __stdcall RegCreateKeyExA(HKEY key, const char* subkey, DWORD reserved, char* cls,
                                                     DWORD opts, DWORD access, void* sa, HKEY* out, DWORD* disp)
{
    (void)reserved;
    (void)cls;
    (void)opts;
    (void)access;
    (void)sa;
    const LSTATUS st = reg_open(key, subkey, out);
    if (st == ERROR_SUCCESS)
    {
        if (disp)
            *disp = REG_OPENED_EXISTING_KEY;
        return (LONG)ERROR_SUCCESS;
    }
    // STUB: no key creation. The kernel registry's key tree is fixed
    // (registry.h: NtCreateKey is unimplemented), so a subkey that is
    // not already in the static tree cannot be created and this
    // reports ERROR_ACCESS_DENIED instead of inventing a handle. An
    // app that stores settings under its own new subkey will fail
    // here; one that writes values under an existing well-known key
    // works end to end.
    if (disp)
        *disp = 0;
    return (LONG)ERROR_ACCESS_DENIED;
}

__declspec(dllexport) LONG __stdcall RegCreateKeyExW(HKEY key, const wchar_t16* subkey, DWORD reserved, wchar_t16* cls,
                                                     DWORD opts, DWORD access, void* sa, HKEY* out, DWORD* disp)
{
    (void)cls;
    char path[REG_PATH_MAX];
    reg_w_to_a(subkey, path, sizeof(path));
    return RegCreateKeyExA(key, path, reserved, 0, opts, access, sa, out, disp);
}

__declspec(dllexport) LONG __stdcall RegCreateKeyA(HKEY key, const char* subkey, HKEY* out)
{
    return RegCreateKeyExA(key, subkey, 0, 0, 0, 0, 0, out, 0);
}

__declspec(dllexport) LONG __stdcall RegCreateKeyW(HKEY key, const wchar_t16* subkey, HKEY* out)
{
    return RegCreateKeyExW(key, subkey, 0, 0, 0, 0, 0, out, 0);
}

__declspec(dllexport) LONG __stdcall RegDeleteKeyA(HKEY key, const char* subkey)
{
    // STUB: no key deletion — same missing kernel op as
    // RegCreateKeyEx. Reporting the failure honestly beats a
    // pretend-success that leaves the key visible to the next
    // RegOpenKeyEx. Values CAN be deleted (RegDeleteValue).
    HKEY probe = (HKEY)0;
    if (reg_open(key, subkey, &probe) != ERROR_SUCCESS)
        return (LONG)ERROR_FILE_NOT_FOUND;
    (void)RegCloseKey(probe);
    return (LONG)ERROR_ACCESS_DENIED;
}

__declspec(dllexport) LONG __stdcall RegDeleteKeyW(HKEY key, const wchar_t16* subkey)
{
    char path[REG_PATH_MAX];
    reg_w_to_a(subkey, path, sizeof(path));
    return RegDeleteKeyA(key, path);
}

/* ------------------------------------------------------------------
 * Enumeration
 *
 * Both enumerate ops share one staging shape: a 32-byte header
 * followed by the ASCII name body. Field placement differs between
 * the two (kOpEnumerateKey puts name_chars at +16; kOpEnumerateValue
 * packs type/size/name_chars into the first 16 bytes), so each
 * wrapper decodes its own header. The staging buffer is u64-aligned
 * because the kernel writes it as four u64s.
 * ------------------------------------------------------------------ */

#define REG_ENUM_HDR 32
#define REG_ENUM_BUF (REG_ENUM_HDR + REG_NAME_MAX)

union reg_enum_stage
{
    unsigned align[REG_ENUM_BUF / 4];
    unsigned char b[REG_ENUM_BUF];
};

static DWORD reg_u32_at(const union reg_enum_stage* s, unsigned off)
{
    return (DWORD)s->b[off] | ((DWORD)s->b[off + 1] << 8) | ((DWORD)s->b[off + 2] << 16) | ((DWORD)s->b[off + 3] << 24);
}

/* Copy `chars` ASCII bytes of the staged name into the caller's
 * narrow or wide buffer. `cap_chars` is the caller's capacity in
 * characters INCLUDING the terminator, per the Win32 contract for
 * lpcchName. Returns ERROR_MORE_DATA when it does not fit. */
static LSTATUS reg_emit_name(const char* src, DWORD chars, char* dst_a, wchar_t16* dst_w, DWORD* cap_chars)
{
    const DWORD cap = cap_chars ? *cap_chars : 0;
    if (cap_chars)
        *cap_chars = chars;
    if (!dst_a && !dst_w)
        return ERROR_SUCCESS;
    if (cap < chars + 1u)
        return ERROR_MORE_DATA;
    if (dst_a)
    {
        for (DWORD i = 0; i < chars; ++i)
            dst_a[i] = src[i];
        dst_a[chars] = '\0';
    }
    else
    {
        (void)reg_a_to_w(src, chars, dst_w, chars);
        dst_w[chars] = 0;
    }
    return ERROR_SUCCESS;
}

static LSTATUS reg_enum_key(HKEY key, DWORD index, char* name_a, wchar_t16* name_w, DWORD* cb)
{
    union reg_enum_stage s;
    for (unsigned i = 0; i < REG_ENUM_BUF / 4; ++i)
        s.align[i] = 0;
    const int rv = duet_syscall5(SYS_REGISTRY, REG_OP_ENUM_KEY, (unsigned)(unsigned long)key, index,
                                 (unsigned)(unsigned long)&s, (unsigned)REG_ENUM_BUF);
    const LSTATUS st = reg_status_to_win32(rv);
    if (st != ERROR_SUCCESS)
        return st;
    DWORD chars = reg_u32_at(&s, 16);
    if (chars > REG_NAME_MAX - 1u)
        chars = REG_NAME_MAX - 1u;
    return reg_emit_name((const char*)&s.b[REG_ENUM_HDR], chars, name_a, name_w, cb);
}

__declspec(dllexport) LONG __stdcall RegEnumKeyExA(HKEY key, DWORD index, char* name, DWORD* cb, DWORD* reserved,
                                                   char* cls, DWORD* cls_cb, void* last_write)
{
    /* GAP: class strings and last-write timestamps are not modelled by
     * the kernel tree, so both out params report "absent". Win32
     * callers that only want the subkey name — which is what an
     * enumeration loop needs — are unaffected. */
    (void)reserved;
    (void)cls;
    if (cls_cb)
        *cls_cb = 0;
    if (last_write)
    {
        ((DWORD*)last_write)[0] = 0;
        ((DWORD*)last_write)[1] = 0;
    }
    return (LONG)reg_enum_key(key, index, name, 0, cb);
}

__declspec(dllexport) LONG __stdcall RegEnumKeyExW(HKEY key, DWORD index, wchar_t16* name, DWORD* cb, DWORD* reserved,
                                                   wchar_t16* cls, DWORD* cls_cb, void* last_write)
{
    (void)reserved;
    (void)cls;
    if (cls_cb)
        *cls_cb = 0;
    if (last_write)
    {
        ((DWORD*)last_write)[0] = 0;
        ((DWORD*)last_write)[1] = 0;
    }
    return (LONG)reg_enum_key(key, index, 0, name, cb);
}

__declspec(dllexport) LONG __stdcall RegEnumKeyA(HKEY key, DWORD index, char* name, DWORD cb)
{
    DWORD n = cb;
    return (LONG)reg_enum_key(key, index, name, 0, &n);
}

__declspec(dllexport) LONG __stdcall RegEnumKeyW(HKEY key, DWORD index, wchar_t16* name, DWORD cb)
{
    DWORD n = cb;
    return (LONG)reg_enum_key(key, index, 0, name, &n);
}

/* RegEnumValue — the kernel's enumerate op reports name / type / size
 * but not the payload, so a caller that asked for data gets it from a
 * follow-up query by the enumerated name. That is exactly one extra
 * syscall per iteration and keeps the value bytes on the same
 * A-vs-W transcode path RegQueryValueEx already owns. */
static LSTATUS reg_enum_value(HKEY key, DWORD index, char* name_a, wchar_t16* name_w, DWORD* name_cb, DWORD* type,
                              BYTE* data, DWORD* data_cb)
{
    union reg_enum_stage s;
    for (unsigned i = 0; i < REG_ENUM_BUF / 4; ++i)
        s.align[i] = 0;
    const int rv = duet_syscall5(SYS_REGISTRY, REG_OP_ENUM_VALUE, (unsigned)(unsigned long)key, index,
                                 (unsigned)(unsigned long)&s, (unsigned)REG_ENUM_BUF);
    const LSTATUS st = reg_status_to_win32(rv);
    if (st != ERROR_SUCCESS)
        return st;
    const DWORD stored_type = reg_u32_at(&s, 4);
    DWORD chars = reg_u32_at(&s, 12);
    if (chars > REG_NAME_MAX - 1u)
        chars = REG_NAME_MAX - 1u;
    char ascii_name[REG_NAME_MAX];
    for (DWORD i = 0; i < chars; ++i)
        ascii_name[i] = (char)s.b[REG_ENUM_HDR + i];
    ascii_name[chars] = '\0';

    if (type)
        *type = stored_type;
    if (data || data_cb)
    {
        /* Route the payload through the caller's own width so text
         * values land in the encoding that caller expects. `wide` is
         * decided by which name buffer the entry point handed down,
         * which is exactly the A-vs-W distinction. */
        if (name_w)
        {
            wchar_t16 wname[REG_NAME_MAX];
            (void)reg_a_to_w(ascii_name, chars, wname, chars);
            wname[chars] = 0;
            (void)RegQueryValueExW(key, wname, 0, type, data, data_cb);
        }
        else
        {
            (void)RegQueryValueExA(key, ascii_name, 0, type, data, data_cb);
        }
    }
    return reg_emit_name(ascii_name, chars, name_a, name_w, name_cb);
}

__declspec(dllexport) LONG __stdcall RegEnumValueA(HKEY key, DWORD index, char* name, DWORD* name_cb, DWORD* reserved,
                                                   DWORD* type, BYTE* data, DWORD* data_cb)
{
    (void)reserved;
    return (LONG)reg_enum_value(key, index, name, 0, name_cb, type, data, data_cb);
}

__declspec(dllexport) LONG __stdcall RegEnumValueW(HKEY key, DWORD index, wchar_t16* name, DWORD* name_cb,
                                                   DWORD* reserved, DWORD* type, BYTE* data, DWORD* data_cb)
{
    (void)reserved;
    return (LONG)reg_enum_value(key, index, 0, name, name_cb, type, data, data_cb);
}

/* RegQueryInfoKey — counts and worst-case lengths for an enumeration
 * loop. The kernel packs five u64 counters; anything Win32 asks for
 * that the tree does not model (security descriptor size, class
 * string, last-write time) reports zero. */
static LSTATUS reg_query_info(HKEY key, DWORD* subkeys, DWORD* max_subkey_len, DWORD* values, DWORD* max_value_name,
                              DWORD* max_value_len)
{
    /* Five u64 counters, staged as ten u32s — see the codegen-trap
     * note above. Only the low half of each is meaningful. */
    unsigned packed[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    const int rv = duet_syscall4(SYS_REGISTRY, REG_OP_QUERY_KEY, (unsigned)(unsigned long)key,
                                 (unsigned)(unsigned long)packed, (unsigned)sizeof(packed));
    const LSTATUS st = reg_status_to_win32(rv);
    if (st != ERROR_SUCCESS)
        return st;
    if (subkeys)
        *subkeys = (DWORD)packed[0];
    if (values)
        *values = (DWORD)packed[2];
    if (max_subkey_len)
        *max_subkey_len = (DWORD)packed[4];
    if (max_value_name)
        *max_value_name = (DWORD)packed[6];
    if (max_value_len)
        *max_value_len = (DWORD)packed[8];
    return ERROR_SUCCESS;
}

/* GAP: `cls`/`cls_cb`, `sd_bytes` and `last_write` report "absent" —
 * the kernel tree has no class strings, no security descriptors and
 * no timestamps. Every counter an enumeration loop actually reads is
 * real. Note max_value_len is in the STORED (narrow) byte count; a W
 * caller sizing a text buffer should double it. */
__declspec(dllexport) LONG __stdcall RegQueryInfoKeyA(HKEY key, char* cls, DWORD* cls_cb, DWORD* reserved,
                                                      DWORD* subkeys, DWORD* max_subkey_len, DWORD* max_cls_len,
                                                      DWORD* values, DWORD* max_value_name, DWORD* max_value_len,
                                                      DWORD* sd_bytes, void* last_write)
{
    (void)reserved;
    if (cls && cls_cb && *cls_cb > 0)
        cls[0] = '\0';
    if (cls_cb)
        *cls_cb = 0;
    if (max_cls_len)
        *max_cls_len = 0;
    if (sd_bytes)
        *sd_bytes = 0;
    if (last_write)
    {
        ((DWORD*)last_write)[0] = 0;
        ((DWORD*)last_write)[1] = 0;
    }
    return (LONG)reg_query_info(key, subkeys, max_subkey_len, values, max_value_name, max_value_len);
}

__declspec(dllexport) LONG __stdcall RegQueryInfoKeyW(HKEY key, wchar_t16* cls, DWORD* cls_cb, DWORD* reserved,
                                                      DWORD* subkeys, DWORD* max_subkey_len, DWORD* max_cls_len,
                                                      DWORD* values, DWORD* max_value_name, DWORD* max_value_len,
                                                      DWORD* sd_bytes, void* last_write)
{
    (void)reserved;
    if (cls && cls_cb && *cls_cb > 0)
        cls[0] = 0;
    if (cls_cb)
        *cls_cb = 0;
    if (max_cls_len)
        *max_cls_len = 0;
    if (sd_bytes)
        *sd_bytes = 0;
    if (last_write)
    {
        ((DWORD*)last_write)[0] = 0;
        ((DWORD*)last_write)[1] = 0;
    }
    return (LONG)reg_query_info(key, subkeys, max_subkey_len, values, max_value_name, max_value_len);
}
