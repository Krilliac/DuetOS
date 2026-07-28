/*
 * userland/libs/advapi32_32/advapi32_32_sec.c
 *
 * The token / privilege / SID / ETW tier of the i386 (PE32)
 * advapi32.dll companion.
 *
 * SECURITY CONTRACT — read before adding anything here.
 *
 * CLAUDE.md's subsystem-isolation rule 2 is the governing constraint:
 * auth and privilege are KERNEL-owned. A Win32 PE must not be able to
 * acquire, through a token-shaped API, any authority a native DuetOS
 * process could not. This file is written so that the reviewable
 * question — "could a malicious PE use this path to do something a
 * native process couldn't?" — answers no at every entry point:
 *
 *   - The ONE call that touches real authority is
 *     AdjustTokenPrivileges, and it does not decide anything: it
 *     hands the caller's TOKEN_PRIVILEGES blob verbatim to
 *     SYS_TOKEN_ADJUST (169), which maps privilege LUIDs to caps and
 *     refuses to ADD any cap the process does not already hold
 *     (kernel/subsystems/win32/token_syscall.cpp). Enabling is
 *     therefore at best a no-op; SE_PRIVILEGE_REMOVED genuinely drops
 *     a cap, which only ever lowers authority. This DLL cannot alter
 *     that outcome — it does not inspect or rewrite the blob.
 *
 *   - Everything that would REPORT authority (GetTokenInformation,
 *     CheckTokenMembership) is a facade, and every facade answers in
 *     the direction that cannot be used to gain anything: not
 *     elevated, not a member, no groups. A caller that gates a
 *     privileged operation on these answers declines to attempt it;
 *     a caller that ignores them still has to pass the kernel's cap
 *     gate on the actual syscall.
 *
 *   - The SID and ACL builders operate purely on caller-supplied
 *     memory. Nothing in DuetOS consumes a SID or an ACL to grant
 *     authority — integrity levels and ACL-shaped probes are
 *     explicitly facades per CLAUDE.md — so constructing one is a
 *     data-structure operation, not a privilege operation.
 *
 * Never let a future edit make a facade here answer "yes". If a real
 * membership or elevation answer is ever needed, it has to come from
 * a kernel cap query, not from a constant in this file.
 */

#include "../common/duet32_syscall.h"

typedef unsigned int DWORD;
typedef int BOOL;
typedef void* HANDLE;
typedef unsigned char BYTE;
typedef unsigned short wchar_t16;

#define SYS_TOKEN_ADJUST 169

#define ERROR_SUCCESS 0UL

/* ------------------------------------------------------------------
 * Privilege names -> LUIDs
 *
 * The LUID lows are the well-known Windows values, and they are the
 * same numbers kernel/subsystems/win32/token_syscall.cpp's
 * LuidLowToCap switches on — a LUID this table does not know maps to
 * kCapNone kernel-side, i.e. it is accepted and has no effect.
 * ------------------------------------------------------------------ */

struct sec_privilege
{
    const char* name;
    unsigned luid_low;
};

static const struct sec_privilege k_privileges[] = {
    {"SeIncreaseBasePriorityPrivilege", 14},
    {"SeBackupPrivilege", 17},
    {"SeRestorePrivilege", 18},
    {"SeDebugPrivilege", 20},
    {"SeShutdownPrivilege", 19},
    {"SeChangeNotifyPrivilege", 23},
    {"SeSecurityPrivilege", 8},
    {"SeTakeOwnershipPrivilege", 9},
    {"SeLoadDriverPrivilege", 10},
    {"SeSystemtimePrivilege", 12},
    {"SeTimeZonePrivilege", 34},
    {"SeUndockPrivilege", 25},
    {"SeImpersonatePrivilege", 29},
    {"SeCreateGlobalPrivilege", 30},
};

static int sec_streq_a(const char* a, const char* b)
{
    if (!a || !b)
        return 0;
    while (*a && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == *b;
}

static void sec_w_to_a(const wchar_t16* src, char* dst, unsigned cap)
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

/* LookupPrivilegeValue — a real name-to-LUID table lookup. The LUID
 * is the only thing AdjustTokenPrivileges needs from it, and feeding
 * the kernel the right LUID is what makes SE_PRIVILEGE_REMOVED drop
 * the right cap. An unknown name fails, which is the Win32 contract
 * (and safer than inventing a LUID that maps onto a real cap). */
__declspec(dllexport) BOOL __stdcall LookupPrivilegeValueA(const char* system, const char* name, void* luid)
{
    (void)system;
    if (!luid)
        return 0;
    for (unsigned i = 0; i < sizeof(k_privileges) / sizeof(k_privileges[0]); ++i)
    {
        if (sec_streq_a(k_privileges[i].name, name))
        {
            ((DWORD*)luid)[0] = k_privileges[i].luid_low;
            ((DWORD*)luid)[1] = 0; /* HighPart — always 0 for well-known privileges */
            return 1;
        }
    }
    return 0;
}

__declspec(dllexport) BOOL __stdcall LookupPrivilegeValueW(const wchar_t16* system, const wchar_t16* name, void* luid)
{
    /* `system` names a remote machine; there is no remote LSA to ask,
     * and the A variant ignores it, so it is not transcoded. */
    (void)system;
    char aname[64];
    sec_w_to_a(name, aname, sizeof(aname));
    return LookupPrivilegeValueA(0, aname, luid);
}

/* ------------------------------------------------------------------
 * Token handles
 * ------------------------------------------------------------------ */

/* The sentinel every token entry point in this DLL accepts. There is
 * no per-token kernel object: a process's authority IS its cap set,
 * which SYS_TOKEN_ADJUST reaches without needing a handle. Matching
 * the PE32+ sibling's 0x1000 keeps the two surfaces from diverging. */
#define SEC_TOKEN_SENTINEL ((HANDLE)0x1000)

// STUB: no token object. OpenProcessToken hands back a fixed sentinel
// rather than opening anything, because DuetOS models authority as
// the process cap set and there is nothing per-token to open. The
// `access` mask is not evaluated — a token handle confers no
// authority here, so there is nothing for an access check to protect.
__declspec(dllexport) BOOL __stdcall OpenProcessToken(HANDLE process, DWORD access, HANDLE* token)
{
    (void)process;
    (void)access;
    if (!token)
        return 0;
    *token = SEC_TOKEN_SENTINEL;
    return 1;
}

// STUB: same sentinel, same reasoning as OpenProcessToken — threads
// do not carry a separate authority in DuetOS.
__declspec(dllexport) BOOL __stdcall OpenThreadToken(HANDLE thread, DWORD access, BOOL self, HANDLE* token)
{
    (void)thread;
    (void)access;
    (void)self;
    if (!token)
        return 0;
    *token = SEC_TOKEN_SENTINEL;
    return 1;
}

/* AdjustTokenPrivileges — the one real authority call on this page.
 *
 * The blob goes to the kernel verbatim. SYS_TOKEN_ADJUST maps each
 * privilege LUID to a cap and will NOT add a cap the process lacks;
 * an enable request for a withheld privilege is refused and reported
 * as STATUS_NOT_ALL_ASSIGNED, while SE_PRIVILEGE_REMOVED genuinely
 * drops the mapped cap. So the only directions this call can move
 * authority are "no change" and "less". */
__declspec(dllexport) BOOL __stdcall AdjustTokenPrivileges(HANDLE token, BOOL disable_all, void* new_state,
                                                           DWORD buf_len, void* prev_state, DWORD* ret_len)
{
    (void)token;
    const unsigned prev_cap = prev_state ? buf_len : 0u;
    const int rv =
        duet_syscall5(SYS_TOKEN_ADJUST, disable_all ? 1u : 0u, disable_all ? 0u : (unsigned)(unsigned long)new_state,
                      disable_all ? 0u : buf_len, (unsigned)(unsigned long)prev_state, prev_cap);
    if (ret_len)
        *ret_len = (rv == 0 || rv == 1) ? prev_cap : 0u;
    /* Win32 returns TRUE for STATUS_NOT_ALL_ASSIGNED too — the caller
     * is expected to check GetLastError() for ERROR_NOT_ALL_ASSIGNED.
     * Only a malformed blob (rv < 0) is a hard failure. */
    return (rv == 0 || rv == 1) ? 1 : 0;
}

/* ------------------------------------------------------------------
 * Token information — facades that never answer "yes"
 * ------------------------------------------------------------------ */

#define TokenElevationType_ 18
#define TokenElevation_ 20
#define TokenIntegrityLevel_ 25
#define TokenSessionId_ 12

__declspec(dllexport) BOOL __stdcall GetTokenInformation(HANDLE token, DWORD info_class, void* info, DWORD info_len,
                                                         DWORD* used)
{
    (void)token;

    /* The scalar classes get a real, deliberately-minimal answer.
     * "Not elevated" / "default elevation" is the direction that
     * cannot be parlayed into authority: a caller that gates a
     * privileged action on elevation declines to attempt it, and one
     * that attempts it anyway still meets the kernel cap gate. */
    if (info_class == TokenElevation_ || info_class == TokenElevationType_ || info_class == TokenSessionId_)
    {
        if (used)
            *used = 4;
        if (!info || info_len < 4)
            return 0;
        *(DWORD*)info = (info_class == TokenElevationType_) ? 1u /* TokenElevationTypeDefault */ : 0u;
        return 1;
    }

    // STUB: integrity levels are an explicit facade in DuetOS
    // (CLAUDE.md subsystem-isolation rule 2). Reporting a level would
    // be inventing an authority tier the kernel does not implement, so
    // the query fails instead.
    if (info_class == TokenIntegrityLevel_)
    {
        if (used)
            *used = 0;
        return 0;
    }

    // STUB: every remaining class (TokenUser, TokenGroups,
    // TokenPrivileges, ...) needs a token object DuetOS does not have.
    // The buffer is zeroed and the call succeeds so a caller that only
    // probes "did this work" proceeds; the zeroed SID it reads back is
    // one CheckTokenMembership reports no membership for, which keeps
    // the two answers consistent. Mirrors the PE32+ sibling.
    if (info)
    {
        BYTE* b = (BYTE*)info;
        for (DWORD i = 0; i < info_len; ++i)
            b[i] = 0;
    }
    if (used)
        *used = info_len > 16u ? 16u : info_len;
    return 1;
}

// STUB: no group membership model. Always reports "not a member",
// which is the only answer that cannot be used to gain authority —
// the common caller shape is `IsUserAnAdmin`-style, and answering yes
// would let a PE talk itself into a privileged code path that the
// kernel would then have to refuse anyway.
__declspec(dllexport) BOOL __stdcall CheckTokenMembership(HANDLE token, void* sid, BOOL* is_member)
{
    (void)token;
    (void)sid;
    if (!is_member)
        return 0;
    *is_member = 0;
    return 1;
}

/* ------------------------------------------------------------------
 * SIDs
 *
 * Pure structure work on caller memory. Win32 SID layout:
 *   byte 0    revision (1)
 *   byte 1    SubAuthorityCount (<= 15)
 *   bytes 2-7 IdentifierAuthority (6 big-endian bytes)
 *   bytes 8+  SubAuthority[count], 4 bytes each, little-endian
 *
 * Nothing in DuetOS consults a SID to grant authority, so building
 * one is data manipulation, not a privilege operation.
 * ------------------------------------------------------------------ */

#define SEC_SID_POOL 8
#define SEC_SID_MAX 68 /* 8 + 4 * 15 */

/* GAP: SIDs come from a fixed pool rather than the process heap, so
 * this DLL carries no cross-DLL allocator dependency and cannot leak.
 * A caller that allocates more than SEC_SID_POOL live SIDs without
 * freeing gets FALSE — real Windows would keep going. Revisit if a
 * caller is ever observed needing more. */
static BYTE s_sid_pool[SEC_SID_POOL][SEC_SID_MAX];
static BYTE s_sid_used[SEC_SID_POOL];

__declspec(dllexport) DWORD __stdcall GetSidLengthRequired(BYTE sub_count)
{
    return (DWORD)(8u + 4u * (unsigned)sub_count);
}

__declspec(dllexport) DWORD __stdcall GetLengthSid(void* sid)
{
    if (!sid)
        return 8;
    return (DWORD)(8u + 4u * (unsigned)((const BYTE*)sid)[1]);
}

__declspec(dllexport) BOOL __stdcall IsValidSid(void* sid)
{
    if (!sid)
        return 0;
    const BYTE* b = (const BYTE*)sid;
    return (b[0] == 1 && b[1] <= 15) ? 1 : 0;
}

__declspec(dllexport) BOOL __stdcall EqualSid(void* a, void* b)
{
    if (!a || !b)
        return 0;
    const DWORD len = GetLengthSid(a);
    if (len != GetLengthSid(b))
        return 0;
    const BYTE* pa = (const BYTE*)a;
    const BYTE* pb = (const BYTE*)b;
    for (DWORD i = 0; i < len; ++i)
    {
        if (pa[i] != pb[i])
            return 0;
    }
    return 1;
}

__declspec(dllexport) void* __stdcall GetSidIdentifierAuthority(void* sid)
{
    return sid ? (void*)((BYTE*)sid + 2) : (void*)0;
}

__declspec(dllexport) BYTE* __stdcall GetSidSubAuthorityCount(void* sid)
{
    return sid ? ((BYTE*)sid + 1) : (BYTE*)0;
}

__declspec(dllexport) DWORD* __stdcall GetSidSubAuthority(void* sid, DWORD index)
{
    if (!sid)
        return (DWORD*)0;
    return (DWORD*)((BYTE*)sid + 8 + 4u * index);
}

__declspec(dllexport) BOOL __stdcall InitializeSid(void* sid, void* auth, BYTE sub_count)
{
    if (!sid || sub_count > 15)
        return 0;
    BYTE* b = (BYTE*)sid;
    b[0] = 1;
    b[1] = sub_count;
    for (int i = 0; i < 6; ++i)
        b[2 + i] = auth ? ((const BYTE*)auth)[i] : 0;
    return 1;
}

__declspec(dllexport) BOOL __stdcall AllocateAndInitializeSid(void* auth, BYTE sub_count, DWORD sa0, DWORD sa1,
                                                              DWORD sa2, DWORD sa3, DWORD sa4, DWORD sa5, DWORD sa6,
                                                              DWORD sa7, void** sid)
{
    if (!sid)
        return 0;
    *sid = (void*)0;
    if (sub_count > 15)
        return 0;
    unsigned slot = 0;
    for (; slot < SEC_SID_POOL; ++slot)
    {
        if (!s_sid_used[slot])
            break;
    }
    if (slot == SEC_SID_POOL)
        return 0;
    s_sid_used[slot] = 1;
    BYTE* b = s_sid_pool[slot];
    (void)InitializeSid(b, auth, sub_count);
    const DWORD subs[8] = {sa0, sa1, sa2, sa3, sa4, sa5, sa6, sa7};
    for (unsigned i = 0; i < (unsigned)sub_count && i < 8; ++i)
    {
        BYTE* dst = b + 8 + 4u * i;
        dst[0] = (BYTE)(subs[i] & 0xFFu);
        dst[1] = (BYTE)((subs[i] >> 8) & 0xFFu);
        dst[2] = (BYTE)((subs[i] >> 16) & 0xFFu);
        dst[3] = (BYTE)((subs[i] >> 24) & 0xFFu);
    }
    /* Sub-authorities past the eight named parameters have no source
     * value; zero them so the SID is fully initialised. */
    for (unsigned i = 8; i < (unsigned)sub_count; ++i)
    {
        BYTE* dst = b + 8 + 4u * i;
        dst[0] = dst[1] = dst[2] = dst[3] = 0;
    }
    *sid = (void*)b;
    return 1;
}

/* FreeSid returns the pool slot. Win32's contract is "returns NULL on
 * success"; a pointer that did not come from the pool is ignored. */
__declspec(dllexport) void* __stdcall FreeSid(void* sid)
{
    for (unsigned i = 0; i < SEC_SID_POOL; ++i)
    {
        if ((void*)s_sid_pool[i] == sid)
        {
            s_sid_used[i] = 0;
            break;
        }
    }
    return (void*)0;
}

/* ------------------------------------------------------------------
 * ACLs
 *
 * InitializeAcl writes the 8-byte ACL header Win32 defines. ACLs are
 * an explicit facade in DuetOS — nothing consults one — so building
 * the header correctly is the whole contract this can honour.
 * ------------------------------------------------------------------ */

__declspec(dllexport) BOOL __stdcall InitializeAcl(void* acl, DWORD acl_size, DWORD revision)
{
    /* ACL header: BYTE AclRevision, BYTE Sbz1, WORD AclSize,
     * WORD AceCount, WORD Sbz2. */
    if (!acl || acl_size < 8)
        return 0;
    BYTE* b = (BYTE*)acl;
    b[0] = (BYTE)revision;
    b[1] = 0;
    b[2] = (BYTE)(acl_size & 0xFFu);
    b[3] = (BYTE)((acl_size >> 8) & 0xFFu);
    b[4] = 0;
    b[5] = 0;
    b[6] = 0;
    b[7] = 0;
    return 1;
}

/* ------------------------------------------------------------------
 * ETW
 *
 * There is no trace consumer in DuetOS. Windows itself makes every
 * one of these a cheap no-op when no session is listening, so
 * silently succeeding is the behaviour a caller is written against —
 * but it is still an omission, not an implementation.
 * ------------------------------------------------------------------ */

// STUB: no ETW provider registry. The returned handle is a sentinel
// EventUnregister accepts and nothing else reads.
__declspec(dllexport) DWORD __stdcall EventRegister(const void* provider_id, void* callback, void* context,
                                                    unsigned long long* handle)
{
    (void)provider_id;
    (void)callback;
    (void)context;
    if (handle)
        *handle = 0xE7E7E7E7ULL;
    return ERROR_SUCCESS;
}

__declspec(dllexport) DWORD __stdcall EventUnregister(unsigned long long handle)
{
    (void)handle;
    return ERROR_SUCCESS;
}

// STUB: events are dropped — there is no trace sink to write them to.
__declspec(dllexport) DWORD __stdcall EventWrite(unsigned long long handle, const void* descriptor, DWORD count,
                                                 void* data)
{
    (void)handle;
    (void)descriptor;
    (void)count;
    (void)data;
    return ERROR_SUCCESS;
}

__declspec(dllexport) DWORD __stdcall EventWriteTransfer(unsigned long long handle, const void* descriptor,
                                                         const void* activity, const void* related, DWORD count,
                                                         void* data)
{
    (void)handle;
    (void)descriptor;
    (void)activity;
    (void)related;
    (void)count;
    (void)data;
    return ERROR_SUCCESS;
}

// STUB: no session to enable, so no provider is ever enabled. Callers
// use this to skip building expensive event payloads; FALSE is both
// the honest and the cheap answer.
__declspec(dllexport) BOOL __stdcall EventEnabled(unsigned long long handle, const void* descriptor)
{
    (void)handle;
    (void)descriptor;
    return 0;
}
