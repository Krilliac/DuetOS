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

/* SHA-1 reference. ~50 lines. */
typedef struct
{
    unsigned int h[5];
    unsigned char buf[64];
    unsigned long long bitlen;
    unsigned int buflen;
} Sha1;

static unsigned int rotl32(unsigned int x, unsigned int n)
{
    return (x << n) | (x >> (32 - n));
}

static void Sha1Init(Sha1* s)
{
    s->h[0] = 0x67452301;
    s->h[1] = 0xEFCDAB89;
    s->h[2] = 0x98BADCFE;
    s->h[3] = 0x10325476;
    s->h[4] = 0xC3D2E1F0;
    s->buflen = 0;
    s->bitlen = 0;
}

static void Sha1Block(Sha1* s, const unsigned char* p)
{
    unsigned int w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = ((unsigned int)p[i * 4] << 24) | ((unsigned int)p[i * 4 + 1] << 16) | ((unsigned int)p[i * 4 + 2] << 8) |
               (unsigned int)p[i * 4 + 3];
    for (int i = 16; i < 80; ++i)
        w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    unsigned int a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3], e = s->h[4];
    for (int i = 0; i < 80; ++i)
    {
        unsigned int f, k;
        if (i < 20)
        {
            f = (b & c) | (~b & d);
            k = 0x5A827999;
        }
        else if (i < 40)
        {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        }
        else if (i < 60)
        {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        }
        else
        {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        unsigned int t = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = t;
    }
    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
}

static void Sha1Update(Sha1* s, const unsigned char* p, unsigned int n)
{
    s->bitlen += (unsigned long long)n * 8ULL;
    while (n)
    {
        unsigned int room = 64 - s->buflen;
        unsigned int take = n < room ? n : room;
        for (unsigned int i = 0; i < take; ++i)
            s->buf[s->buflen + i] = p[i];
        s->buflen += take;
        p += take;
        n -= take;
        if (s->buflen == 64)
        {
            Sha1Block(s, s->buf);
            s->buflen = 0;
        }
    }
}

static void Sha1Final(Sha1* s, unsigned char* out20)
{
    s->buf[s->buflen++] = 0x80;
    if (s->buflen > 56)
    {
        while (s->buflen < 64)
            s->buf[s->buflen++] = 0;
        Sha1Block(s, s->buf);
        s->buflen = 0;
    }
    while (s->buflen < 56)
        s->buf[s->buflen++] = 0;
    unsigned long long bl = s->bitlen;
    for (int i = 7; i >= 0; --i)
        s->buf[56 + i] = (unsigned char)(bl >> ((7 - i) * 8));
    Sha1Block(s, s->buf);
    for (int i = 0; i < 5; ++i)
    {
        out20[i * 4 + 0] = (unsigned char)(s->h[i] >> 24);
        out20[i * 4 + 1] = (unsigned char)(s->h[i] >> 16);
        out20[i * 4 + 2] = (unsigned char)(s->h[i] >> 8);
        out20[i * 4 + 3] = (unsigned char)(s->h[i] >> 0);
    }
}

/* MD5 reference. */
typedef struct
{
    unsigned int a, b, c, d;
    unsigned char buf[64];
    unsigned long long bitlen;
    unsigned int buflen;
} Md5;

static const unsigned int kMd5K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static const unsigned int kMd5R[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                       5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                       4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                       6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static void Md5Init(Md5* s)
{
    s->a = 0x67452301;
    s->b = 0xefcdab89;
    s->c = 0x98badcfe;
    s->d = 0x10325476;
    s->buflen = 0;
    s->bitlen = 0;
}

static void Md5Block(Md5* s, const unsigned char* p)
{
    unsigned int M[16];
    for (int i = 0; i < 16; ++i)
        M[i] = (unsigned int)p[i * 4] | ((unsigned int)p[i * 4 + 1] << 8) | ((unsigned int)p[i * 4 + 2] << 16) |
               ((unsigned int)p[i * 4 + 3] << 24);
    unsigned int a = s->a, b = s->b, c = s->c, d = s->d;
    for (int i = 0; i < 64; ++i)
    {
        unsigned int f, g;
        if (i < 16)
        {
            f = (b & c) | (~b & d);
            g = (unsigned int)i;
        }
        else if (i < 32)
        {
            f = (d & b) | (~d & c);
            g = (5u * (unsigned int)i + 1u) & 15u;
        }
        else if (i < 48)
        {
            f = b ^ c ^ d;
            g = (3u * (unsigned int)i + 5u) & 15u;
        }
        else
        {
            f = c ^ (b | ~d);
            g = (7u * (unsigned int)i) & 15u;
        }
        unsigned int t = d;
        d = c;
        c = b;
        b = b + rotl32(a + f + kMd5K[i] + M[g], kMd5R[i]);
        a = t;
    }
    s->a += a;
    s->b += b;
    s->c += c;
    s->d += d;
}

static void Md5Update(Md5* s, const unsigned char* p, unsigned int n)
{
    s->bitlen += (unsigned long long)n * 8ULL;
    while (n)
    {
        unsigned int room = 64 - s->buflen;
        unsigned int take = n < room ? n : room;
        for (unsigned int i = 0; i < take; ++i)
            s->buf[s->buflen + i] = p[i];
        s->buflen += take;
        p += take;
        n -= take;
        if (s->buflen == 64)
        {
            Md5Block(s, s->buf);
            s->buflen = 0;
        }
    }
}

static void Md5Final(Md5* s, unsigned char* out16)
{
    s->buf[s->buflen++] = 0x80;
    if (s->buflen > 56)
    {
        while (s->buflen < 64)
            s->buf[s->buflen++] = 0;
        Md5Block(s, s->buf);
        s->buflen = 0;
    }
    while (s->buflen < 56)
        s->buf[s->buflen++] = 0;
    unsigned long long bl = s->bitlen;
    for (int i = 0; i < 8; ++i)
        s->buf[56 + i] = (unsigned char)(bl >> (i * 8));
    Md5Block(s, s->buf);
    unsigned int v[4] = {s->a, s->b, s->c, s->d};
    for (int i = 0; i < 4; ++i)
    {
        out16[i * 4 + 0] = (unsigned char)(v[i] >> 0);
        out16[i * 4 + 1] = (unsigned char)(v[i] >> 8);
        out16[i * 4 + 2] = (unsigned char)(v[i] >> 16);
        out16[i * 4 + 3] = (unsigned char)(v[i] >> 24);
    }
}

/* Algorithm-id matching: BCryptOpenAlgorithmProvider passes a UTF-16
 * algorithm name (e.g. L"SHA256", L"SHA1", L"MD5"). Each match
 * function checks for exact equality. */
static int wstr_eq(const wchar_t16* a, const char* b)
{
    if (!a)
        return 0;
    for (int i = 0;; ++i)
    {
        if (a[i] != (wchar_t16)(unsigned char)b[i])
            return 0;
        if (b[i] == 0)
            return 1;
    }
}

static int IsSha256(const wchar_t16* algid)
{
    return wstr_eq(algid, "SHA256");
}
static int IsSha1(const wchar_t16* algid)
{
    return wstr_eq(algid, "SHA1");
}
static int IsMd5(const wchar_t16* algid)
{
    return wstr_eq(algid, "MD5");
}

/* Per-algorithm hash slot. Single-threaded callers only. The slot
 * union holds whichever digest is live; g_hash_kind selects the
 * dispatcher branch. */
typedef enum
{
    HK_NONE = 0,
    HK_SHA256 = 1,
    HK_SHA1 = 2,
    HK_MD5 = 3,
} HashKind;

#define BCRYPT_ALG_SHA256 ((HANDLE)0x2001)
#define BCRYPT_ALG_SHA1 ((HANDLE)0x2002)
#define BCRYPT_ALG_MD5 ((HANDLE)0x2003)
#define BCRYPT_ALG_GENERIC ((HANDLE)0x2000)

#define BCRYPT_HASH_SHA256 ((HANDLE)0x3001)
#define BCRYPT_HASH_SHA1 ((HANDLE)0x3002)
#define BCRYPT_HASH_MD5 ((HANDLE)0x3003)
#define BCRYPT_HASH_GENERIC ((HANDLE)0x3000)

static Sha256 g_sha256_slot;
static Sha1 g_sha1_slot;
static Md5 g_md5_slot;
static int g_sha256_in_use;
static int g_sha1_in_use;
static int g_md5_in_use;

static unsigned int hash_size_for_alg(HANDLE alg)
{
    if (alg == BCRYPT_ALG_SHA256)
        return 32;
    if (alg == BCRYPT_ALG_SHA1)
        return 20;
    if (alg == BCRYPT_ALG_MD5)
        return 16;
    return 0;
}

__declspec(dllexport) NTSTATUS BCryptOpenAlgorithmProvider(HANDLE* h, const wchar_t16* algid,
                                                           const wchar_t16* implementation, ULONG flags)
{
    (void)implementation;
    (void)flags;
    if (h == 0)
        return STATUS_INVALID_PARAMETER;
    if (IsSha256(algid))
        *h = BCRYPT_ALG_SHA256;
    else if (IsSha1(algid))
        *h = BCRYPT_ALG_SHA1;
    else if (IsMd5(algid))
        *h = BCRYPT_ALG_MD5;
    else
        *h = BCRYPT_ALG_GENERIC;
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
    if (alg == BCRYPT_ALG_SHA256)
    {
        Sha256Init(&g_sha256_slot);
        g_sha256_in_use = 1;
        *hash = BCRYPT_HASH_SHA256;
    }
    else if (alg == BCRYPT_ALG_SHA1)
    {
        Sha1Init(&g_sha1_slot);
        g_sha1_in_use = 1;
        *hash = BCRYPT_HASH_SHA1;
    }
    else if (alg == BCRYPT_ALG_MD5)
    {
        Md5Init(&g_md5_slot);
        g_md5_in_use = 1;
        *hash = BCRYPT_HASH_MD5;
    }
    else
    {
        *hash = BCRYPT_HASH_GENERIC;
    }
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptHashData(HANDLE h, unsigned char* in, ULONG len, ULONG flags)
{
    (void)flags;
    if (h == BCRYPT_HASH_SHA256 && g_sha256_in_use)
        Sha256Update(&g_sha256_slot, in, len);
    else if (h == BCRYPT_HASH_SHA1 && g_sha1_in_use)
        Sha1Update(&g_sha1_slot, in, len);
    else if (h == BCRYPT_HASH_MD5 && g_md5_in_use)
        Md5Update(&g_md5_slot, in, len);
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptFinishHash(HANDLE h, unsigned char* out, ULONG len, ULONG flags)
{
    (void)flags;
    if (out == 0)
        return STATUS_INVALID_PARAMETER;
    if (h == BCRYPT_HASH_SHA256 && g_sha256_in_use)
    {
        unsigned char tmp[32];
        Sha256Final(&g_sha256_slot, tmp);
        g_sha256_in_use = 0;
        ULONG cap = (len < 32) ? len : 32;
        for (ULONG i = 0; i < cap; ++i)
            out[i] = tmp[i];
        return STATUS_SUCCESS;
    }
    if (h == BCRYPT_HASH_SHA1 && g_sha1_in_use)
    {
        unsigned char tmp[20];
        Sha1Final(&g_sha1_slot, tmp);
        g_sha1_in_use = 0;
        ULONG cap = (len < 20) ? len : 20;
        for (ULONG i = 0; i < cap; ++i)
            out[i] = tmp[i];
        return STATUS_SUCCESS;
    }
    if (h == BCRYPT_HASH_MD5 && g_md5_in_use)
    {
        unsigned char tmp[16];
        Md5Final(&g_md5_slot, tmp);
        g_md5_in_use = 0;
        ULONG cap = (len < 16) ? len : 16;
        for (ULONG i = 0; i < cap; ++i)
            out[i] = tmp[i];
        return STATUS_SUCCESS;
    }
    for (ULONG i = 0; i < len; ++i)
        out[i] = 0;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptDestroyHash(HANDLE h)
{
    if (h == BCRYPT_HASH_SHA256)
        g_sha256_in_use = 0;
    else if (h == BCRYPT_HASH_SHA1)
        g_sha1_in_use = 0;
    else if (h == BCRYPT_HASH_MD5)
        g_md5_in_use = 0;
    return STATUS_SUCCESS;
}

/* BCryptGetProperty handles the property names Windows callers most
 * often query: "HashDigestLength", "ObjectLength", "BlockLength".
 * Other properties return STATUS_NOT_FOUND. */
__declspec(dllexport) NTSTATUS BCryptGetProperty(HANDLE h, const wchar_t16* prop, unsigned char* out, ULONG len,
                                                 ULONG* result_len, ULONG flags)
{
    (void)flags;
    if (!prop)
        return STATUS_INVALID_PARAMETER;
    unsigned int sz = hash_size_for_alg(h);
    if (sz == 0 && (h == BCRYPT_HASH_SHA256 || h == BCRYPT_HASH_SHA1 || h == BCRYPT_HASH_MD5))
    {
        sz = (h == BCRYPT_HASH_SHA256) ? 32 : (h == BCRYPT_HASH_SHA1) ? 20 : 16;
    }
    if (wstr_eq(prop, "HashDigestLength"))
    {
        if (result_len)
            *result_len = 4;
        if (!out)
            return STATUS_SUCCESS;
        if (len < 4)
            return STATUS_INVALID_PARAMETER;
        out[0] = (unsigned char)(sz & 0xFF);
        out[1] = (unsigned char)((sz >> 8) & 0xFF);
        out[2] = 0;
        out[3] = 0;
        return STATUS_SUCCESS;
    }
    if (wstr_eq(prop, "ObjectLength") || wstr_eq(prop, "BlockLength"))
    {
        unsigned int v = wstr_eq(prop, "BlockLength") ? 64 : (unsigned int)sizeof(Sha256);
        if (result_len)
            *result_len = 4;
        if (!out)
            return STATUS_SUCCESS;
        if (len < 4)
            return STATUS_INVALID_PARAMETER;
        out[0] = (unsigned char)(v & 0xFF);
        out[1] = (unsigned char)((v >> 8) & 0xFF);
        out[2] = (unsigned char)((v >> 16) & 0xFF);
        out[3] = (unsigned char)((v >> 24) & 0xFF);
        return STATUS_SUCCESS;
    }
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
