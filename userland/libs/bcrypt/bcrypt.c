/*
 * userland/libs/bcrypt/bcrypt.c — 8 CNG stubs.
 * All except BCryptGenRandom are no-ops returning STATUS_SUCCESS.
 * BCryptGenRandom fills with a deterministic counter (NOT secure).
 */

typedef int                BOOL;
typedef unsigned long      NTSTATUS;
typedef unsigned long      ULONG;
typedef unsigned long long ULONG_PTR;
typedef void*              HANDLE;
typedef unsigned short     wchar_t16;

#define STATUS_SUCCESS   0UL
#define STATUS_NOT_FOUND 0xC0000225UL

__declspec(dllexport) NTSTATUS BCryptOpenAlgorithmProvider(HANDLE* h, const wchar_t16* algid,
                                                          const wchar_t16* implementation, ULONG flags)
{
    (void) algid;
    (void) implementation;
    (void) flags;
    if (h)
        *h = (HANDLE) 0x2000; /* Sentinel */
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptCloseAlgorithmProvider(HANDLE h, ULONG flags)
{
    (void) h;
    (void) flags;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptCreateHash(HANDLE alg, HANDLE* hash, unsigned char* obj, ULONG obj_len,
                                                unsigned char* secret, ULONG secret_len, ULONG flags)
{
    (void) alg;
    (void) obj;
    (void) obj_len;
    (void) secret;
    (void) secret_len;
    (void) flags;
    if (hash)
        *hash = (HANDLE) 0x3000;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptHashData(HANDLE h, unsigned char* in, ULONG len, ULONG flags)
{
    (void) h;
    (void) in;
    (void) len;
    (void) flags;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptFinishHash(HANDLE h, unsigned char* out, ULONG len, ULONG flags)
{
    (void) h;
    (void) flags;
    /* Zero the output — deterministic, not cryptographic. */
    if (out)
        for (ULONG i = 0; i < len; ++i)
            out[i] = 0;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptDestroyHash(HANDLE h)
{
    (void) h;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptGetProperty(HANDLE h, const wchar_t16* prop, unsigned char* out, ULONG len,
                                                 ULONG* result_len, ULONG flags)
{
    (void) h;
    (void) prop;
    (void) out;
    (void) flags;
    if (result_len)
        *result_len = len;
    return STATUS_NOT_FOUND;
}

/* BCryptGenRandom — deterministic SPLITMIX64 counter. NOT
 * secure; real crypto callers MUST NOT rely on this.
 * Documented in the header comment. */
static unsigned long long g_bcrypt_rand = 0x9E3779B97F4A7C15ULL;

__declspec(dllexport) NTSTATUS BCryptGenRandom(HANDLE alg, unsigned char* buf, ULONG len, ULONG flags)
{
    (void) alg;
    (void) flags;
    for (ULONG i = 0; i < len; ++i)
    {
        g_bcrypt_rand = g_bcrypt_rand * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i]        = (unsigned char) (g_bcrypt_rand >> 56);
    }
    return STATUS_SUCCESS;
}
