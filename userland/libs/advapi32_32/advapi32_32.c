/*
 * advapi32_32.c — i386 advapi32.dll: CryptoAPI + event-log tier.
 *
 * The Reg* family moved to advapi32_32_reg.c when it stopped being a
 * set of constant-returners and started driving the kernel-owned
 * registry over SYS_REGISTRY; the security / token / SID tier lives
 * in advapi32_32_sec.c. What is left here is still v0 stub tier and
 * carries its markers inline.
 */
typedef unsigned int DWORD;
typedef int BOOL;
typedef void* HANDLE;
typedef HANDLE HCRYPTPROV;
typedef HANDLE HCRYPTHASH;
typedef HANDLE HCRYPTKEY;
typedef unsigned char BYTE;

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
    /* v0 fills with a counter so callers that consume entropy see
     * "something" non-zero. Real RNG via SYS_RAND_BYTES needs the
     * 32-bit syscall trampoline; v0 sequence is good enough for
     * "did the call succeed" probes. */
    (void)p;
    static unsigned counter = 0xC0DEF00D;
    for (DWORD i = 0; i < len; ++i)
    {
        counter = counter * 1103515245u + 12345u;
        buf[i] = (BYTE)(counter >> 16);
    }
    return 1;
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

/* SystemFunction036 = RtlGenRandom — secure RNG. v0 uses same LCG. */
__declspec(dllexport) BOOL __stdcall SystemFunction036(void* buf, unsigned len)
{
    static unsigned ctr = 0xBADCAFE;
    BYTE* p = (BYTE*)buf;
    for (unsigned i = 0; i < len; ++i)
    {
        ctr = ctr * 1103515245u + 12345u;
        p[i] = (BYTE)(ctr >> 16);
    }
    return 1;
}
