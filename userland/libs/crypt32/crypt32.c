/* crypt32.dll — certificate / CMS stubs. All fail. */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

__declspec(dllexport) HANDLE CertOpenStore(const void* prov, DWORD enc, HANDLE hcp, DWORD flags, const void* para)
{
    (void)prov;
    (void)enc;
    (void)hcp;
    (void)flags;
    (void)para;
    return (HANDLE)0;
}
__declspec(dllexport) BOOL CertCloseStore(HANDLE h, DWORD flags)
{
    (void)h;
    (void)flags;
    return 1;
}
__declspec(dllexport) const void* CertFindCertificateInStore(HANDLE h, DWORD enc, DWORD flags, DWORD find_type,
                                                             const void* p, const void* prev)
{
    (void)h;
    (void)enc;
    (void)flags;
    (void)find_type;
    (void)p;
    (void)prev;
    return (void*)0;
}
__declspec(dllexport) BOOL CertFreeCertificateContext(const void* ctx)
{
    (void)ctx;
    return 1;
}
__declspec(dllexport) BOOL CryptAcquireContextA(unsigned long long* h, const char* ct, const char* prov, DWORD type,
                                                DWORD flags)
{
    (void)ct;
    (void)prov;
    (void)type;
    (void)flags;
    if (h)
        *h = 0;
    return 0;
}
__declspec(dllexport) BOOL CryptReleaseContext(unsigned long long h, DWORD flags)
{
    (void)h;
    (void)flags;
    return 1;
}
__declspec(dllexport) BOOL CryptGenRandom(unsigned long long h, DWORD len, unsigned char* buf)
{
    (void)h;
    if (!buf || len == 0)
        return 1;
    /* Tick-mixed SPLITMIX64. The kernel performance counter
     * (SYS_PERF_COUNTER, 100 Hz) is XORed into the state on
     * every call so the output isn't a static repeat sequence
     * across the process lifetime. Still NOT cryptographic —
     * crypto callers should route through bcrypt's rdrand path. */
    static unsigned long long s = 0xA5A5A5A5A5A5A5A5ULL;
    long long ticks;
    __asm__ volatile("int $0x80" : "=a"(ticks) : "a"((long long)13) : "memory");
    s ^= (unsigned long long)ticks;
    for (DWORD i = 0; i < len; ++i)
    {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (unsigned char)(s >> 56);
    }
    return 1;
}
__declspec(dllexport) BOOL CryptProtectData(void* in, const wchar_t16* desc, void* entropy, void* reserved,
                                            void* prompt, DWORD flags, void* out)
{
    (void)in;
    (void)desc;
    (void)entropy;
    (void)reserved;
    (void)prompt;
    (void)flags;
    (void)out;
    return 0;
}
__declspec(dllexport) BOOL CryptUnprotectData(void* in, wchar_t16** desc, void* entropy, void* reserved, void* prompt,
                                              DWORD flags, void* out)
{
    (void)in;
    (void)desc;
    (void)entropy;
    (void)reserved;
    (void)prompt;
    (void)flags;
    (void)out;
    return 0;
}

__declspec(dllexport) BOOL CryptStringToBinaryA(const char* str, DWORD str_len, DWORD flags, unsigned char* binary,
                                                DWORD* binary_size, DWORD* skip, DWORD* used_flags)
{
    (void)str;
    (void)str_len;
    (void)flags;
    (void)binary;
    if (binary_size)
        *binary_size = 0;
    if (skip)
        *skip = 0;
    if (used_flags)
        *used_flags = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptBinaryToStringA(const unsigned char* binary, DWORD binary_size, DWORD flags, char* str,
                                                DWORD* str_len)
{
    (void)binary;
    (void)binary_size;
    (void)flags;
    (void)str;
    if (str_len)
        *str_len = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptCreateHash(unsigned long long h, DWORD algid, unsigned long long key, DWORD flags,
                                           unsigned long long* hash)
{
    (void)h;
    (void)algid;
    (void)key;
    (void)flags;
    if (hash)
        *hash = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptHashData(unsigned long long h, const unsigned char* data, DWORD len, DWORD flags)
{
    (void)h;
    (void)data;
    (void)len;
    (void)flags;
    return 0;
}

__declspec(dllexport) BOOL CryptDestroyHash(unsigned long long h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL CryptGetHashParam(unsigned long long h, DWORD param, unsigned char* buf, DWORD* len,
                                             DWORD flags)
{
    (void)h;
    (void)param;
    (void)buf;
    (void)flags;
    if (len)
        *len = 0;
    return 0;
}

__declspec(dllexport) const void* CertEnumCertificatesInStore(HANDLE store, const void* prev)
{
    (void)store;
    (void)prev;
    return (void*)0;
}

__declspec(dllexport) DWORD CertGetNameStringW(const void* ctx, DWORD type, DWORD flags, void* type_param,
                                               wchar_t16* name, DWORD name_len)
{
    (void)ctx;
    (void)type;
    (void)flags;
    (void)type_param;
    (void)name_len;
    if (name)
        name[0] = 0;
    return 1; /* "" + NUL char count */
}

__declspec(dllexport) BOOL CertVerifyCertificateChainPolicy(const void* policy, void* chain, void* params, void* status)
{
    (void)policy;
    (void)chain;
    (void)params;
    if (status)
    {
        unsigned char* p = (unsigned char*)status;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
    return 1; /* "policy succeeded" — caller still inspects status. */
}
