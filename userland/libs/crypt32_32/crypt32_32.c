/* crypt32_32.c — i386 crypt32.dll v0 stubs. */
typedef unsigned int DWORD;
typedef int BOOL;
typedef void* HANDLE;
typedef HANDLE HCERTSTORE;
typedef const void* PCCERT_CONTEXT;

__declspec(dllexport) BOOL __stdcall CertCloseStore(HCERTSTORE h, DWORD flags)
{
    (void)h;
    (void)flags;
    return 1;
}

__declspec(dllexport) HCERTSTORE __stdcall CertOpenStore(const char* prov, DWORD enc, HANDLE prov_ctx, DWORD flags,
                                                         const void* prov_param)
{
    (void)prov;
    (void)enc;
    (void)prov_ctx;
    (void)flags;
    (void)prov_param;
    return 0;
}

__declspec(dllexport) HCERTSTORE __stdcall CertOpenSystemStoreA(HANDLE hprov, const char* name)
{
    (void)hprov;
    (void)name;
    return 0;
}

__declspec(dllexport) PCCERT_CONTEXT __stdcall CertDuplicateCertificateContext(PCCERT_CONTEXT ctx)
{
    return ctx;
}

__declspec(dllexport) PCCERT_CONTEXT __stdcall CertEnumCertificatesInStore(HCERTSTORE h, PCCERT_CONTEXT prev)
{
    (void)h;
    (void)prev;
    return 0;
}

__declspec(dllexport) PCCERT_CONTEXT __stdcall CertFindCertificateInStore(HCERTSTORE h, DWORD enc, DWORD find_flags,
                                                                          DWORD find_type, const void* find_par,
                                                                          PCCERT_CONTEXT prev)
{
    (void)h;
    (void)enc;
    (void)find_flags;
    (void)find_type;
    (void)find_par;
    (void)prev;
    return 0;
}

__declspec(dllexport) BOOL __stdcall CertFreeCertificateContext(PCCERT_CONTEXT ctx)
{
    (void)ctx;
    return 1;
}

__declspec(dllexport) BOOL __stdcall CertGetCertificateContextProperty(PCCERT_CONTEXT ctx, DWORD prop, void* data,
                                                                       DWORD* sz)
{
    (void)ctx;
    (void)prop;
    (void)data;
    if (sz)
        *sz = 0;
    return 0;
}

__declspec(dllexport) BOOL __stdcall CertGetEnhancedKeyUsage(PCCERT_CONTEXT ctx, DWORD flags, void* usage, DWORD* sz)
{
    (void)ctx;
    (void)flags;
    (void)usage;
    if (sz)
        *sz = 0;
    return 0;
}

__declspec(dllexport) BOOL __stdcall CertGetIntendedKeyUsage(DWORD enc, const void* ci, unsigned char* usage,
                                                             DWORD usage_sz)
{
    (void)enc;
    (void)ci;
    (void)usage;
    (void)usage_sz;
    return 0;
}
