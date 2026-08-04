/*
 * advapi32_32.c — i386 advapi32.dll: CryptoAPI + event-log tier.
 *
 * The Reg* family moved to advapi32_32_reg.c when it stopped being a
 * set of constant-returners and started driving the kernel-owned
 * registry over SYS_REGISTRY; the security / token / SID tier lives
 * in advapi32_32_sec.c. What is left here is still v0 stub tier and
 * carries its markers inline.
 */
#include "../common/duet32_syscall.h"

/* SYS_RANDOM_BYTES (kernel/syscall/syscall.h) — kernel CSPRNG, RDSEED/RDRAND
 * seeded. Returns the number of bytes written; a short count means the copy
 * faulted part-way and the buffer must NOT be treated as random. */
#define SYS_RANDOM_BYTES 212

typedef unsigned int DWORD;
typedef int BOOL;
typedef void* HANDLE;
typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTHASH;
typedef HANDLE HCRYPTKEY;
typedef unsigned char BYTE;


/*
 * Fill `buf` from the kernel CSPRNG. Returns 1 only on a full-length fill.
 *
 * These are security APIs. Returning success with predictable bytes is
 * strictly worse than failing: callers use them for session tokens, nonces,
 * key material and authentication challenges, and a caller that receives
 * FALSE takes its error path, whereas a caller handed LCG output ships a
 * broken secret. Both entry points below previously ran
 *   ctr = ctr * 1103515245u + 12345u
 * which is the textbook glibc LCG — trivially predictable from one output.
 *
 * The old comment here claimed a real RNG "needs the 32-bit syscall
 * trampoline"; that trampoline now exists in ../common/duet32_syscall.h and
 * every other _32 DLL already issues syscalls through it.
 */
static BOOL duet32_csprng_fill(void* buf, unsigned len)
{
    if (buf == 0)
        return 0;
    if (len == 0)
        return 1;
    int wrote = duet_syscall2(SYS_RANDOM_BYTES, (unsigned)(unsigned long)buf, len);
    return (wrote >= 0 && (unsigned)wrote == len) ? 1 : 0;
}

/* CryptoAPI stubs. v0 returns FALSE so caller's NULL-on-fail path runs. */
__declspec(dllexport) BOOL __stdcall CryptAcquireContextA(HCRYPTPROV* h, const char* n, const char* p, DWORD type,
                                                          DWORD flags)
{
    (void)n;
    (void)p;
    (void)type;
    (void)flags;
    if (h)
        *h = 0;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptAcquireContextW(HCRYPTPROV* h, const void* n, const void* p, DWORD type,
                                                          DWORD flags)
{
    (void)n;
    (void)p;
    (void)type;
    (void)flags;
    if (h)
        *h = 0;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptCreateHash(HCRYPTPROV p, DWORD algid, HCRYPTKEY k, DWORD flags,
                                                     HCRYPTHASH* out)
{
    (void)p;
    (void)algid;
    (void)k;
    (void)flags;
    if (out)
        *out = 0;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptDecrypt(HCRYPTKEY k, HCRYPTHASH h, BOOL final, DWORD flags, BYTE* data,
                                                  DWORD* len)
{
    (void)k;
    (void)h;
    (void) final;
    (void)flags;
    (void)data;
    (void)len;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptDestroyHash(HCRYPTHASH h)
{
    (void)h;
    return 1;
}
__declspec(dllexport) BOOL __stdcall CryptDestroyKey(HCRYPTKEY k)
{
    (void)k;
    return 1;
}
__declspec(dllexport) BOOL __stdcall CryptEnumProvidersW(DWORD idx, DWORD* rsv, DWORD flags, DWORD* type, void* name,
                                                         DWORD* nlen)
{
    (void)idx;
    (void)rsv;
    (void)flags;
    (void)type;
    (void)name;
    (void)nlen;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptExportKey(HCRYPTKEY k, HCRYPTKEY exp_k, DWORD type, DWORD flags, BYTE* data,
                                                    DWORD* len)
{
    (void)k;
    (void)exp_k;
    (void)type;
    (void)flags;
    (void)data;
    (void)len;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptGenRandom(HCRYPTPROV p, DWORD len, BYTE* buf)
{
    (void)p;
    return duet32_csprng_fill(buf, len);
}
__declspec(dllexport) BOOL __stdcall CryptGetHashParam(HCRYPTHASH h, DWORD p, BYTE* data, DWORD* len, DWORD flags)
{
    (void)h;
    (void)p;
    (void)data;
    (void)flags;
    if (len)
        *len = 0;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptGetProvParam(HCRYPTPROV p, DWORD param, BYTE* data, DWORD* len, DWORD flags)
{
    (void)p;
    (void)param;
    (void)data;
    (void)flags;
    if (len)
        *len = 0;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptGetUserKey(HCRYPTPROV p, DWORD spec, HCRYPTKEY* out)
{
    (void)p;
    (void)spec;
    if (out)
        *out = 0;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptHashData(HCRYPTHASH h, const BYTE* data, DWORD len, DWORD flags)
{
    (void)h;
    (void)data;
    (void)len;
    (void)flags;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptReleaseContext(HCRYPTPROV p, DWORD flags)
{
    (void)p;
    (void)flags;
    return 1;
}
__declspec(dllexport) BOOL __stdcall CryptSetHashParam(HCRYPTHASH h, DWORD param, const BYTE* data, DWORD flags)
{
    (void)h;
    (void)param;
    (void)data;
    (void)flags;
    return 0;
}
__declspec(dllexport) BOOL __stdcall CryptSignHashW(HCRYPTHASH h, DWORD spec, const void* desc, DWORD flags, BYTE* sig,
                                                    DWORD* siglen)
{
    (void)h;
    (void)spec;
    (void)desc;
    (void)flags;
    (void)sig;
    if (siglen)
        *siglen = 0;
    return 0;
}

/* Event log stubs. */
__declspec(dllexport) BOOL __stdcall DeregisterEventSource(HANDLE h)
{
    (void)h;
    return 1;
}
__declspec(dllexport) HANDLE __stdcall RegisterEventSourceW(const void* unc, const void* src)
{
    (void)unc;
    (void)src;
    return (HANDLE)1;
}
__declspec(dllexport) BOOL __stdcall ReportEventW(HANDLE h, unsigned short type, unsigned short cat, DWORD eid,
                                                  void* sid, unsigned short n_str, DWORD bin_sz, const void* str,
                                                  void* bin)
{
    (void)h;
    (void)type;
    (void)cat;
    (void)eid;
    (void)sid;
    (void)n_str;
    (void)bin_sz;
    (void)str;
    (void)bin;
    return 1;
}

/* SystemFunction036 = RtlGenRandom — documented as cryptographically secure,
 * so it must come from the kernel CSPRNG or fail. */
__declspec(dllexport) BOOL __stdcall SystemFunction036(void* buf, unsigned len)
{
    return duet32_csprng_fill(buf, len);
}
