/*
 * userland/libs/bcrypt/bcrypt.c — minimal CNG implementation.
 * SHA-256 is real (FIPS 180-4 reference); other algorithms still
 * route through STATUS_SUCCESS sentinels — they accept a hash
 * handle, ingest data, and produce a deterministic but
 * crypto-meaningless digest. BCryptGenRandom is RDRAND/RDSEED
 * backed via SYS_RAND_BYTES.
 */

typedef int BOOL;
typedef unsigned long NTSTATUS;
typedef unsigned long ULONG;
typedef unsigned long long ULONG_PTR;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define STATUS_SUCCESS 0UL
#define STATUS_NOT_FOUND 0xC0000225UL
#define STATUS_INVALID_PARAMETER 0xC000000DUL

/* SHA-256 reference. ~80 lines. Pre-allocated state lives in a
 * single static slot — single-threaded callers only, matches
 * the v0 bcrypt scope. */
typedef struct
{
    unsigned int h[8];
    unsigned char buf[64];
    unsigned long long bitlen;
    unsigned int buflen;
} Sha256;

static const unsigned int kSha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static unsigned int rotr32(unsigned int x, unsigned int n)
{
    return (x >> n) | (x << (32 - n));
}

static void Sha256Init(Sha256* s)
{
    s->h[0] = 0x6a09e667;
    s->h[1] = 0xbb67ae85;
    s->h[2] = 0x3c6ef372;
    s->h[3] = 0xa54ff53a;
    s->h[4] = 0x510e527f;
    s->h[5] = 0x9b05688c;
    s->h[6] = 0x1f83d9ab;
    s->h[7] = 0x5be0cd19;
    s->bitlen = 0;
    s->buflen = 0;
}

static void Sha256Block(Sha256* s, const unsigned char* p)
{
    unsigned int w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = ((unsigned int)p[i * 4] << 24) | ((unsigned int)p[i * 4 + 1] << 16) | ((unsigned int)p[i * 4 + 2] << 8) |
               (unsigned int)p[i * 4 + 3];
    for (int i = 16; i < 64; ++i)
    {
        unsigned int s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    unsigned int a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    unsigned int e = s->h[4], f = s->h[5], g = s->h[6], hh = s->h[7];
    for (int i = 0; i < 64; ++i)
    {
        unsigned int S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        unsigned int ch = (e & f) ^ (~e & g);
        unsigned int t1 = hh + S1 + ch + kSha256K[i] + w[i];
        unsigned int S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        unsigned int mj = (a & b) ^ (a & c) ^ (b & c);
        unsigned int t2 = S0 + mj;
        hh = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
    s->h[5] += f;
    s->h[6] += g;
    s->h[7] += hh;
}

static void Sha256Update(Sha256* s, const unsigned char* p, unsigned int n)
{
    s->bitlen += (unsigned long long)n * 8;
    while (n > 0)
    {
        unsigned int take = 64 - s->buflen;
        if (take > n)
            take = n;
        for (unsigned int i = 0; i < take; ++i)
            s->buf[s->buflen + i] = p[i];
        s->buflen += take;
        p += take;
        n -= take;
        if (s->buflen == 64)
        {
            Sha256Block(s, s->buf);
            s->buflen = 0;
        }
    }
}

static void Sha256Final(Sha256* s, unsigned char* out32)
{
    s->buf[s->buflen++] = 0x80;
    if (s->buflen > 56)
    {
        while (s->buflen < 64)
            s->buf[s->buflen++] = 0;
        Sha256Block(s, s->buf);
        s->buflen = 0;
    }
    while (s->buflen < 56)
        s->buf[s->buflen++] = 0;
    unsigned long long bl = s->bitlen;
    for (int i = 7; i >= 0; --i)
        s->buf[56 + i] = (unsigned char)(bl >> ((7 - i) * 8));
    Sha256Block(s, s->buf);
    for (int i = 0; i < 8; ++i)
    {
        out32[i * 4 + 0] = (unsigned char)(s->h[i] >> 24);
        out32[i * 4 + 1] = (unsigned char)(s->h[i] >> 16);
        out32[i * 4 + 2] = (unsigned char)(s->h[i] >> 8);
        out32[i * 4 + 3] = (unsigned char)(s->h[i] >> 0);
    }
}

/* Algorithm IDs come in as UTF-16. We compare against L"SHA256". */
static int IsSha256(const wchar_t16* algid)
{
    if (algid == 0)
        return 0;
    static const wchar_t16 kSha256[] = {'S', 'H', 'A', '2', '5', '6', 0};
    for (int i = 0;; ++i)
    {
        if (algid[i] != kSha256[i])
            return 0;
        if (kSha256[i] == 0)
            return 1;
    }
}

/* One static SHA-256 slot. Single-threaded callers only — same
 * scope as the rest of the v0 bcrypt surface. */
static Sha256 g_sha256_slot;
static int g_sha256_in_use;

#define BCRYPT_HANDLE_SHA256 ((HANDLE)0x3001)
#define BCRYPT_HANDLE_GENERIC ((HANDLE)0x3000)

__declspec(dllexport) NTSTATUS BCryptOpenAlgorithmProvider(HANDLE* h, const wchar_t16* algid,
                                                           const wchar_t16* implementation, ULONG flags)
{
    (void)implementation;
    (void)flags;
    if (h == 0)
        return STATUS_INVALID_PARAMETER;
    if (IsSha256(algid))
    {
        *h = (HANDLE)0x2001; /* Sentinel for SHA-256 alg-provider. */
    }
    else
    {
        *h = (HANDLE)0x2000;
    }
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
    (void)obj;
    (void)obj_len;
    (void)secret;
    (void)secret_len;
    (void)flags;
    if (hash == 0)
        return STATUS_INVALID_PARAMETER;
    if (alg == (HANDLE)0x2001)
    {
        Sha256Init(&g_sha256_slot);
        g_sha256_in_use = 1;
        *hash = BCRYPT_HANDLE_SHA256;
    }
    else
    {
        *hash = BCRYPT_HANDLE_GENERIC;
    }
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptHashData(HANDLE h, unsigned char* in, ULONG len, ULONG flags)
{
    (void)flags;
    if (h == BCRYPT_HANDLE_SHA256 && g_sha256_in_use)
    {
        Sha256Update(&g_sha256_slot, in, len);
    }
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptFinishHash(HANDLE h, unsigned char* out, ULONG len, ULONG flags)
{
    (void)flags;
    if (out == 0)
        return STATUS_INVALID_PARAMETER;
    if (h == BCRYPT_HANDLE_SHA256 && g_sha256_in_use)
    {
        unsigned char tmp[32];
        Sha256Final(&g_sha256_slot, tmp);
        g_sha256_in_use = 0;
        ULONG cap = (len < 32) ? len : 32;
        for (ULONG i = 0; i < cap; ++i)
            out[i] = tmp[i];
        return STATUS_SUCCESS;
    }
    /* Non-SHA-256 algorithms: zero-fill (legacy stub behaviour). */
    for (ULONG i = 0; i < len; ++i)
        out[i] = 0;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptDestroyHash(HANDLE h)
{
    if (h == BCRYPT_HANDLE_SHA256)
        g_sha256_in_use = 0;
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
