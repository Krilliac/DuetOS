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
    /* Simple deterministic SPLITMIX64 — NOT cryptographic. */
    static unsigned long long s = 0xA5A5A5A5A5A5A5A5ULL;
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
