/*
 * userland/libs/bcrypt/bcrypt.c — 8 CNG stubs.
 * All except BCryptGenRandom are no-ops returning STATUS_SUCCESS.
 * BCryptGenRandom fills with a deterministic counter (NOT secure).
 */

typedef int BOOL;
typedef unsigned long NTSTATUS;
typedef unsigned long ULONG;
typedef unsigned long long ULONG_PTR;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define STATUS_SUCCESS 0UL
#define STATUS_NOT_FOUND 0xC0000225UL

__declspec(dllexport) NTSTATUS BCryptOpenAlgorithmProvider(HANDLE* h, const wchar_t16* algid,
                                                           const wchar_t16* implementation, ULONG flags)
{
    (void)algid;
    (void)implementation;
    (void)flags;
    if (h)
        *h = (HANDLE)0x2000; /* Sentinel */
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptCloseAlgorithmProvider(HANDLE h, ULONG flags)
{
    (void)h;
    (void)flags;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptCreateHash(HANDLE alg, HANDLE* hash, unsigned char* obj, ULONG obj_len,
                                                unsigned char* secret, ULONG secret_len, ULONG flags)
{
    (void)alg;
    (void)obj;
    (void)obj_len;
    (void)secret;
    (void)secret_len;
    (void)flags;
    if (hash)
        *hash = (HANDLE)0x3000;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptHashData(HANDLE h, unsigned char* in, ULONG len, ULONG flags)
{
    (void)h;
    (void)in;
    (void)len;
    (void)flags;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptFinishHash(HANDLE h, unsigned char* out, ULONG len, ULONG flags)
{
    (void)h;
    (void)flags;
    /* Zero the output — deterministic, not cryptographic. */
    if (out)
        for (ULONG i = 0; i < len; ++i)
            out[i] = 0;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptDestroyHash(HANDLE h)
{
    (void)h;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptGetProperty(HANDLE h, const wchar_t16* prop, unsigned char* out, ULONG len,
                                                 ULONG* result_len, ULONG flags)
{
    (void)h;
    (void)prop;
    (void)out;
    (void)flags;
    if (result_len)
        *result_len = len;
    return STATUS_NOT_FOUND;
}

/* BCryptGenRandom — RDRAND/RDSEED-backed if the host CPU
 * supports it; falls back to a SPLITMIX64 counter mixed with
 * SYS_PERF_COUNTER (kernel ticks) so the output is at least
 * unpredictable across reboots. NOT formally cryptographic —
 * real crypto callers should still avoid this entry point — but
 * the previous implementation was a pure deterministic LCG, so
 * any caller that relied on freshness is strictly better off.
 *
 * Mix:
 *   - Seed: g_bcrypt_rand XOR SYS_PERF_COUNTER (per-call).
 *   - Try RDRAND for each byte (gated on CPUID via a probe).
 *   - On RDRAND failure, fall through to SPLITMIX64 + LCG step.
 */
static unsigned long long g_bcrypt_rand = 0x9E3779B97F4A7C15ULL;

static int has_rdrand(void)
{
    static int probed = 0;
    static int cached = 0;
    if (probed)
        return cached;
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1));
    cached = (ecx & (1u << 30)) != 0;
    probed = 1;
    return cached;
}

static int rdrand_u64(unsigned long long* out)
{
    unsigned char ok = 0;
    unsigned long long val = 0;
    /* Up to 10 retries — Intel guidance for RDRAND under contention. */
    for (int i = 0; i < 10; ++i)
    {
        __asm__ volatile("rdrand %0; setc %1" : "=r"(val), "=qm"(ok));
        if (ok)
        {
            *out = val;
            return 1;
        }
    }
    return 0;
}

__declspec(dllexport) NTSTATUS BCryptGenRandom(HANDLE alg, unsigned char* buf, ULONG len, ULONG flags)
{
    (void)alg;
    (void)flags;
    if (!buf || len == 0)
        return STATUS_SUCCESS;

    /* Per-call seed mix from kernel performance counter. */
    long long ticks;
    __asm__ volatile("int $0x80" : "=a"(ticks) : "a"((long long)13) : "memory");
    g_bcrypt_rand ^= (unsigned long long)ticks;

    const int rdrand_ok = has_rdrand();
    ULONG i = 0;
    while (i < len)
    {
        unsigned long long bits = 0;
        int got = 0;
        if (rdrand_ok)
            got = rdrand_u64(&bits);
        if (!got)
        {
            g_bcrypt_rand = g_bcrypt_rand * 6364136223846793005ULL + 1442695040888963407ULL;
            bits = g_bcrypt_rand;
        }
        const ULONG room = len - i;
        const ULONG take = (room < 8) ? room : 8;
        for (ULONG j = 0; j < take; ++j)
            buf[i + j] = (unsigned char)(bits >> (j * 8));
        i += take;
    }
    return STATUS_SUCCESS;
}
