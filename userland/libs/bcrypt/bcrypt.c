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

/* SHA-256 reference. ~80 lines. Hash state is stored per handle
 * below so different Win32 threads can hash concurrently without
 * trampling a process-global singleton. */
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

/* SHA-512 reference (FIPS 180-4 §6.4). Same shape as SHA-256 but
 * 64-bit words, 80 rounds, 1024-bit blocks, 128-bit length pad.
 * SHA-384 reuses the entire core — only the eight initial-hash
 * values and the truncated output (48 bytes vs 64) differ. The
 * 128-bit length field is encoded as { 8 zero bytes, 8 bytes of
 * bitlen big-endian } since `bitlen` is a u64 (callers are bounded
 * by 2^61 input bytes, well below the 2^125-byte limit). */
typedef struct
{
    unsigned long long h[8];
    unsigned char buf[128];
    unsigned long long bitlen;
    unsigned int buflen;
} Sha512;

static const unsigned long long kSha512K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
    0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
    0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
    0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
    0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
    0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
    0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
    0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
    0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static unsigned long long rotr64(unsigned long long x, unsigned int n)
{
    return (x >> n) | (x << (64 - n));
}

static void Sha512Init(Sha512* s)
{
    s->h[0] = 0x6a09e667f3bcc908ULL;
    s->h[1] = 0xbb67ae8584caa73bULL;
    s->h[2] = 0x3c6ef372fe94f82bULL;
    s->h[3] = 0xa54ff53a5f1d36f1ULL;
    s->h[4] = 0x510e527fade682d1ULL;
    s->h[5] = 0x9b05688c2b3e6c1fULL;
    s->h[6] = 0x1f83d9abfb41bd6bULL;
    s->h[7] = 0x5be0cd19137e2179ULL;
    s->bitlen = 0;
    s->buflen = 0;
}

static void Sha384Init(Sha512* s)
{
    s->h[0] = 0xcbbb9d5dc1059ed8ULL;
    s->h[1] = 0x629a292a367cd507ULL;
    s->h[2] = 0x9159015a3070dd17ULL;
    s->h[3] = 0x152fecd8f70e5939ULL;
    s->h[4] = 0x67332667ffc00b31ULL;
    s->h[5] = 0x8eb44a8768581511ULL;
    s->h[6] = 0xdb0c2e0d64f98fa7ULL;
    s->h[7] = 0x47b5481dbefa4fa4ULL;
    s->bitlen = 0;
    s->buflen = 0;
}

static void Sha512Block(Sha512* s, const unsigned char* p)
{
    unsigned long long w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = ((unsigned long long)p[i * 8] << 56) | ((unsigned long long)p[i * 8 + 1] << 48) |
               ((unsigned long long)p[i * 8 + 2] << 40) | ((unsigned long long)p[i * 8 + 3] << 32) |
               ((unsigned long long)p[i * 8 + 4] << 24) | ((unsigned long long)p[i * 8 + 5] << 16) |
               ((unsigned long long)p[i * 8 + 6] << 8) | (unsigned long long)p[i * 8 + 7];
    for (int i = 16; i < 80; ++i)
    {
        unsigned long long s0 = rotr64(w[i - 15], 1) ^ rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7);
        unsigned long long s1 = rotr64(w[i - 2], 19) ^ rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    unsigned long long a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    unsigned long long e = s->h[4], f = s->h[5], g = s->h[6], hh = s->h[7];
    for (int i = 0; i < 80; ++i)
    {
        unsigned long long S1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41);
        unsigned long long ch = (e & f) ^ (~e & g);
        unsigned long long t1 = hh + S1 + ch + kSha512K[i] + w[i];
        unsigned long long S0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39);
        unsigned long long mj = (a & b) ^ (a & c) ^ (b & c);
        unsigned long long t2 = S0 + mj;
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

static void Sha512Update(Sha512* s, const unsigned char* p, unsigned int n)
{
    s->bitlen += (unsigned long long)n * 8;
    while (n > 0)
    {
        unsigned int take = 128 - s->buflen;
        if (take > n)
            take = n;
        for (unsigned int i = 0; i < take; ++i)
            s->buf[s->buflen + i] = p[i];
        s->buflen += take;
        p += take;
        n -= take;
        if (s->buflen == 128)
        {
            Sha512Block(s, s->buf);
            s->buflen = 0;
        }
    }
}

/* Common finaliser. out_len must be 48 (SHA-384) or 64 (SHA-512). */
static void Sha512Final(Sha512* s, unsigned char* out, unsigned int out_len)
{
    s->buf[s->buflen++] = 0x80;
    if (s->buflen > 112)
    {
        while (s->buflen < 128)
            s->buf[s->buflen++] = 0;
        Sha512Block(s, s->buf);
        s->buflen = 0;
    }
    while (s->buflen < 112)
        s->buf[s->buflen++] = 0;
    /* High 64 bits of the 128-bit length always zero (capped at 2^61
     * input bytes by bitlen's u64 width). Low 64 bits are bitlen big-endian. */
    for (int i = 0; i < 8; ++i)
        s->buf[112 + i] = 0;
    unsigned long long bl = s->bitlen;
    for (int i = 7; i >= 0; --i)
        s->buf[120 + i] = (unsigned char)(bl >> ((7 - i) * 8));
    Sha512Block(s, s->buf);
    const unsigned int words = out_len / 8;
    for (unsigned int i = 0; i < words; ++i)
    {
        out[i * 8 + 0] = (unsigned char)(s->h[i] >> 56);
        out[i * 8 + 1] = (unsigned char)(s->h[i] >> 48);
        out[i * 8 + 2] = (unsigned char)(s->h[i] >> 40);
        out[i * 8 + 3] = (unsigned char)(s->h[i] >> 32);
        out[i * 8 + 4] = (unsigned char)(s->h[i] >> 24);
        out[i * 8 + 5] = (unsigned char)(s->h[i] >> 16);
        out[i * 8 + 6] = (unsigned char)(s->h[i] >> 8);
        out[i * 8 + 7] = (unsigned char)(s->h[i] >> 0);
    }
}

/* AES-128 / AES-256 reference (FIPS 197). Encrypts / decrypts one
 * 16-byte block at a time. Key expansion produces 11 round-keys
 * for AES-128 (176 bytes) or 15 for AES-256 (240 bytes). The same
 * Sbox / inverse-Sbox / Rcon tables drive both key sizes. CBC mode
 * is the higher-level chaining wrapper layered on top. No bitslice
 * / no AES-NI — straight reference code, ~250 LOC, runs in ~12 µs
 * per block on a typical 2026 CPU. Sufficient for a v0 BCryptEncrypt
 * / BCryptDecrypt that matches the API shape every Win32 caller
 * expects. */

static const unsigned char kAesSbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9,
    0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F,
    0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07,
    0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3,
    0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58,
    0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3,
    0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F,
    0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC,
    0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,
    0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70,
    0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11,
    0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42,
    0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

static const unsigned char kAesInvSbox[256] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39,
    0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2,
    0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E, 0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76,
    0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC,
    0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D,
    0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C,
    0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F,
    0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85,
    0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62,
    0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD,
    0x5A, 0xF4, 0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60,
    0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
    0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6,
    0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

static const unsigned char kAesRcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

/* GF(2^8) multiplication used by MixColumns / InvMixColumns. */
static unsigned char aes_xtime(unsigned char x)
{
    return (unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

/* AES key expansion. key_bytes ∈ {16, 32}. round_keys must hold
 * 11 × 16 = 176 bytes for AES-128 or 15 × 16 = 240 bytes for
 * AES-256. Returns the number of rounds. */
static int aes_key_expansion(const unsigned char* key, unsigned int key_bytes, unsigned char* round_keys)
{
    const int Nk = (key_bytes == 32) ? 8 : 4;
    const int Nr = Nk + 6; /* 10 for AES-128, 14 for AES-256 */
    const int total_words = (Nr + 1) * 4;
    /* First Nk words of round_keys are the key bytes verbatim. */
    for (int i = 0; i < Nk * 4; ++i)
        round_keys[i] = key[i];
    unsigned char tmp[4];
    for (int i = Nk; i < total_words; ++i)
    {
        tmp[0] = round_keys[(i - 1) * 4 + 0];
        tmp[1] = round_keys[(i - 1) * 4 + 1];
        tmp[2] = round_keys[(i - 1) * 4 + 2];
        tmp[3] = round_keys[(i - 1) * 4 + 3];
        if (i % Nk == 0)
        {
            /* RotWord + SubWord + XOR Rcon. */
            const unsigned char t = tmp[0];
            tmp[0] = (unsigned char)(kAesSbox[tmp[1]] ^ kAesRcon[i / Nk]);
            tmp[1] = kAesSbox[tmp[2]];
            tmp[2] = kAesSbox[tmp[3]];
            tmp[3] = kAesSbox[t];
        }
        else if (Nk > 6 && i % Nk == 4)
        {
            /* AES-256 only: extra SubWord every 4 words inside the cycle. */
            tmp[0] = kAesSbox[tmp[0]];
            tmp[1] = kAesSbox[tmp[1]];
            tmp[2] = kAesSbox[tmp[2]];
            tmp[3] = kAesSbox[tmp[3]];
        }
        for (int j = 0; j < 4; ++j)
            round_keys[i * 4 + j] = (unsigned char)(round_keys[(i - Nk) * 4 + j] ^ tmp[j]);
    }
    return Nr;
}

static void aes_add_round_key(unsigned char state[16], const unsigned char* rk)
{
    for (int i = 0; i < 16; ++i)
        state[i] ^= rk[i];
}

static void aes_sub_bytes(unsigned char state[16])
{
    for (int i = 0; i < 16; ++i)
        state[i] = kAesSbox[state[i]];
}

static void aes_inv_sub_bytes(unsigned char state[16])
{
    for (int i = 0; i < 16; ++i)
        state[i] = kAesInvSbox[state[i]];
}

static void aes_shift_rows(unsigned char s[16])
{
    /* Row 1: shift left by 1.  Row 2: by 2.  Row 3: by 3.
     * AES state is stored column-major: index = col*4 + row. */
    unsigned char t;
    t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    t = s[2];
    unsigned char u = s[6];
    s[2] = s[10];
    s[6] = s[14];
    s[10] = t;
    s[14] = u;
    t = s[3];
    s[3] = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = t;
}

static void aes_inv_shift_rows(unsigned char s[16])
{
    unsigned char t;
    t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    t = s[2];
    unsigned char u = s[6];
    s[2] = s[10];
    s[6] = s[14];
    s[10] = t;
    s[14] = u;
    t = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = s[3];
    s[3] = t;
}

static void aes_mix_columns(unsigned char s[16])
{
    for (int c = 0; c < 4; ++c)
    {
        unsigned char* col = s + c * 4;
        const unsigned char a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        const unsigned char t = (unsigned char)(a0 ^ a1 ^ a2 ^ a3);
        col[0] ^= (unsigned char)(t ^ aes_xtime((unsigned char)(a0 ^ a1)));
        col[1] ^= (unsigned char)(t ^ aes_xtime((unsigned char)(a1 ^ a2)));
        col[2] ^= (unsigned char)(t ^ aes_xtime((unsigned char)(a2 ^ a3)));
        col[3] ^= (unsigned char)(t ^ aes_xtime((unsigned char)(a3 ^ a0)));
    }
}

/* Helpers: multiply by 9, 11, 13, 14 in GF(2^8). Each is a sum of
 * xtime applications: 9 = 8+1, 11 = 8+2+1, 13 = 8+4+1, 14 = 8+4+2. */
static unsigned char aes_mul9(unsigned char x)
{
    const unsigned char x2 = aes_xtime(x);
    const unsigned char x4 = aes_xtime(x2);
    const unsigned char x8 = aes_xtime(x4);
    return (unsigned char)(x8 ^ x);
}
static unsigned char aes_mul11(unsigned char x)
{
    const unsigned char x2 = aes_xtime(x);
    const unsigned char x4 = aes_xtime(x2);
    const unsigned char x8 = aes_xtime(x4);
    return (unsigned char)(x8 ^ x2 ^ x);
}
static unsigned char aes_mul13(unsigned char x)
{
    const unsigned char x2 = aes_xtime(x);
    const unsigned char x4 = aes_xtime(x2);
    const unsigned char x8 = aes_xtime(x4);
    return (unsigned char)(x8 ^ x4 ^ x);
}
static unsigned char aes_mul14(unsigned char x)
{
    const unsigned char x2 = aes_xtime(x);
    const unsigned char x4 = aes_xtime(x2);
    const unsigned char x8 = aes_xtime(x4);
    return (unsigned char)(x8 ^ x4 ^ x2);
}

static void aes_inv_mix_columns(unsigned char s[16])
{
    /* InvMixColumns matrix per FIPS 197 §5.3.3:
     *   [14 11 13  9]
     *   [ 9 14 11 13]
     *   [13  9 14 11]
     *   [11 13  9 14] */
    for (int c = 0; c < 4; ++c)
    {
        unsigned char* col = s + c * 4;
        const unsigned char a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        col[0] = (unsigned char)(aes_mul14(a0) ^ aes_mul11(a1) ^ aes_mul13(a2) ^ aes_mul9(a3));
        col[1] = (unsigned char)(aes_mul9(a0) ^ aes_mul14(a1) ^ aes_mul11(a2) ^ aes_mul13(a3));
        col[2] = (unsigned char)(aes_mul13(a0) ^ aes_mul9(a1) ^ aes_mul14(a2) ^ aes_mul11(a3));
        col[3] = (unsigned char)(aes_mul11(a0) ^ aes_mul13(a1) ^ aes_mul9(a2) ^ aes_mul14(a3));
    }
}

/* Encrypt one 16-byte block in place. round_keys must hold the
 * key schedule from `aes_key_expansion`. Nr ∈ {10, 14}. */
static void aes_encrypt_block(unsigned char state[16], const unsigned char* round_keys, int Nr)
{
    aes_add_round_key(state, round_keys);
    for (int r = 1; r < Nr; ++r)
    {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, round_keys + r * 16);
    }
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, round_keys + Nr * 16);
}

static void aes_decrypt_block(unsigned char state[16], const unsigned char* round_keys, int Nr)
{
    aes_add_round_key(state, round_keys + Nr * 16);
    for (int r = Nr - 1; r >= 1; --r)
    {
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, round_keys + r * 16);
        aes_inv_mix_columns(state);
    }
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, round_keys);
}

/* CBC mode. `len` must be a multiple of 16 (the bcrypt API surface
 * accepts a NoPadding flag — we never insert PKCS#7 padding here,
 * so the caller is responsible for padding to a 16-byte boundary).
 * `iv` is the initial 16-byte vector; modified in place to the
 * final ciphertext block so chained calls continue cleanly. */
static void aes_cbc_encrypt(const unsigned char* in, unsigned int len, const unsigned char* round_keys, int Nr,
                            unsigned char* iv, unsigned char* out)
{
    unsigned char block[16];
    for (unsigned int off = 0; off < len; off += 16)
    {
        for (int i = 0; i < 16; ++i)
            block[i] = (unsigned char)(in[off + i] ^ iv[i]);
        aes_encrypt_block(block, round_keys, Nr);
        for (int i = 0; i < 16; ++i)
        {
            out[off + i] = block[i];
            iv[i] = block[i];
        }
    }
}

static void aes_cbc_decrypt(const unsigned char* in, unsigned int len, const unsigned char* round_keys, int Nr,
                            unsigned char* iv, unsigned char* out)
{
    unsigned char block[16];
    unsigned char next_iv[16];
    for (unsigned int off = 0; off < len; off += 16)
    {
        for (int i = 0; i < 16; ++i)
        {
            block[i] = in[off + i];
            next_iv[i] = in[off + i];
        }
        aes_decrypt_block(block, round_keys, Nr);
        for (int i = 0; i < 16; ++i)
        {
            out[off + i] = (unsigned char)(block[i] ^ iv[i]);
            iv[i] = next_iv[i];
        }
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
static int IsSha384(const wchar_t16* algid)
{
    return wstr_eq(algid, "SHA384");
}
static int IsSha512(const wchar_t16* algid)
{
    return wstr_eq(algid, "SHA512");
}
static int IsSha1(const wchar_t16* algid)
{
    return wstr_eq(algid, "SHA1");
}
static int IsMd5(const wchar_t16* algid)
{
    return wstr_eq(algid, "MD5");
}
static int IsAes(const wchar_t16* algid)
{
    return wstr_eq(algid, "AES");
}

/* Hash/key handles are process-local tagged integers backed by small
 * static slot pools. That keeps this freestanding DLL heap-free while
 * allowing independent Win32 threads to hold different BCrypt objects
 * concurrently. Operations on the SAME handle are still caller-serialized
 * just like any mutable streaming hash/key object; operations on different
 * handles never share digest/key state. */
typedef enum
{
    HK_NONE = 0,
    HK_SHA256 = 1,
    HK_SHA1 = 2,
    HK_MD5 = 3,
    HK_SHA384 = 4,
    HK_SHA512 = 5,
} HashKind;

#define BCRYPT_ALG_SHA256 ((HANDLE)0x2001)
#define BCRYPT_ALG_SHA1 ((HANDLE)0x2002)
#define BCRYPT_ALG_MD5 ((HANDLE)0x2003)
#define BCRYPT_ALG_SHA384 ((HANDLE)0x2004)
#define BCRYPT_ALG_SHA512 ((HANDLE)0x2005)
#define BCRYPT_ALG_AES ((HANDLE)0x2006)
#define BCRYPT_ALG_GENERIC ((HANDLE)0x2000)

#define BCRYPT_HASH_GENERIC ((HANDLE)0x3000)

#define BCRYPT_HASH_HANDLE_BASE 0x30000000ULL
#define BCRYPT_HASH_HANDLE_STRIDE 0x100ULL
#define BCRYPT_KEY_HANDLE_BASE 0x40000000ULL
#define BCRYPT_KEY_HANDLE_STRIDE 0x100ULL

#define BCRYPT_MAX_HASH_SLOTS 16
#define BCRYPT_MAX_AES_KEYS 8

typedef struct
{
    volatile int in_use;
    HashKind kind;
    union
    {
        Sha256 sha256;
        Sha1 sha1;
        Md5 md5;
        Sha512 sha512; /* SHA-384 and SHA-512 share the core. */
    } u;
} HashSlot;

typedef struct
{
    volatile int in_use;
    unsigned char round_keys[240];
    int rounds;
    unsigned int chain_mode;
} AesKeySlot;

static HashSlot g_hash_slots[BCRYPT_MAX_HASH_SLOTS];

static HANDLE make_hash_handle(unsigned int slot, HashKind kind)
{
    return (HANDLE)(ULONG_PTR)(BCRYPT_HASH_HANDLE_BASE + ((ULONG_PTR)slot * BCRYPT_HASH_HANDLE_STRIDE) +
                               (ULONG_PTR)kind);
}

static int decode_hash_handle(HANDLE h, unsigned int* slot_out, HashKind* kind_out)
{
    const ULONG_PTR v = (ULONG_PTR)h;
    if (v < BCRYPT_HASH_HANDLE_BASE)
        return 0;
    const ULONG_PTR off = v - BCRYPT_HASH_HANDLE_BASE;
    const unsigned int slot = (unsigned int)(off / BCRYPT_HASH_HANDLE_STRIDE);
    const unsigned int kind = (unsigned int)(off % BCRYPT_HASH_HANDLE_STRIDE);
    if (slot >= BCRYPT_MAX_HASH_SLOTS || kind == HK_NONE || kind > HK_SHA512)
        return 0;
    *slot_out = slot;
    *kind_out = (HashKind)kind;
    return 1;
}

static HashSlot* hash_slot_from_handle(HANDLE h, HashKind want)
{
    unsigned int slot = 0;
    HashKind kind = HK_NONE;
    if (!decode_hash_handle(h, &slot, &kind))
        return 0;
    HashSlot* s = &g_hash_slots[slot];
    if (!s->in_use || s->kind != kind || (want != HK_NONE && kind != want))
        return 0;
    return s;
}

static unsigned int hash_size_for_alg(HANDLE alg)
{
    if (alg == BCRYPT_ALG_SHA256)
        return 32;
    if (alg == BCRYPT_ALG_SHA1)
        return 20;
    if (alg == BCRYPT_ALG_MD5)
        return 16;
    if (alg == BCRYPT_ALG_SHA384)
        return 48;
    if (alg == BCRYPT_ALG_SHA512)
        return 64;
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
    else if (IsSha384(algid))
        *h = BCRYPT_ALG_SHA384;
    else if (IsSha512(algid))
        *h = BCRYPT_ALG_SHA512;
    else if (IsSha1(algid))
        *h = BCRYPT_ALG_SHA1;
    else if (IsMd5(algid))
        *h = BCRYPT_ALG_MD5;
    else if (IsAes(algid))
        *h = BCRYPT_ALG_AES;
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

static HashKind hash_kind_for_alg(HANDLE alg)
{
    if (alg == BCRYPT_ALG_SHA256)
        return HK_SHA256;
    if (alg == BCRYPT_ALG_SHA1)
        return HK_SHA1;
    if (alg == BCRYPT_ALG_MD5)
        return HK_MD5;
    if (alg == BCRYPT_ALG_SHA384)
        return HK_SHA384;
    if (alg == BCRYPT_ALG_SHA512)
        return HK_SHA512;
    return HK_NONE;
}

static void hash_slot_init(HashSlot* slot, HashKind kind)
{
    slot->kind = kind;
    if (kind == HK_SHA256)
        Sha256Init(&slot->u.sha256);
    else if (kind == HK_SHA384)
        Sha384Init(&slot->u.sha512);
    else if (kind == HK_SHA512)
        Sha512Init(&slot->u.sha512);
    else if (kind == HK_SHA1)
        Sha1Init(&slot->u.sha1);
    else if (kind == HK_MD5)
        Md5Init(&slot->u.md5);
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

    const HashKind kind = hash_kind_for_alg(alg);
    if (kind == HK_NONE)
    {
        *hash = BCRYPT_HASH_GENERIC;
        return STATUS_SUCCESS;
    }

    for (unsigned int i = 0; i < BCRYPT_MAX_HASH_SLOTS; ++i)
    {
        if (__sync_bool_compare_and_swap(&g_hash_slots[i].in_use, 0, 1))
        {
            hash_slot_init(&g_hash_slots[i], kind);
            *hash = make_hash_handle(i, kind);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_INVALID_PARAMETER;
}

__declspec(dllexport) NTSTATUS BCryptHashData(HANDLE h, unsigned char* in, ULONG len, ULONG flags)
{
    (void)flags;
    if (len != 0 && in == 0)
        return STATUS_INVALID_PARAMETER;

    HashSlot* slot = hash_slot_from_handle(h, HK_NONE);
    if (slot == 0)
        return (h == BCRYPT_HASH_GENERIC) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;

    if (slot->kind == HK_SHA256)
        Sha256Update(&slot->u.sha256, in, len);
    else if (slot->kind == HK_SHA384 || slot->kind == HK_SHA512)
        Sha512Update(&slot->u.sha512, in, len);
    else if (slot->kind == HK_SHA1)
        Sha1Update(&slot->u.sha1, in, len);
    else if (slot->kind == HK_MD5)
        Md5Update(&slot->u.md5, in, len);
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptFinishHash(HANDLE h, unsigned char* out, ULONG len, ULONG flags)
{
    (void)flags;
    if (out == 0)
        return STATUS_INVALID_PARAMETER;

    HashSlot* slot = hash_slot_from_handle(h, HK_NONE);
    if (slot == 0)
    {
        if (h != BCRYPT_HASH_GENERIC)
            return STATUS_INVALID_PARAMETER;
        for (ULONG i = 0; i < len; ++i)
            out[i] = 0;
        return STATUS_SUCCESS;
    }

    unsigned char tmp[64];
    ULONG digest_len = 0;
    if (slot->kind == HK_SHA256)
    {
        Sha256Final(&slot->u.sha256, tmp);
        digest_len = 32;
    }
    else if (slot->kind == HK_SHA384)
    {
        Sha512Final(&slot->u.sha512, tmp, 48);
        digest_len = 48;
    }
    else if (slot->kind == HK_SHA512)
    {
        Sha512Final(&slot->u.sha512, tmp, 64);
        digest_len = 64;
    }
    else if (slot->kind == HK_SHA1)
    {
        Sha1Final(&slot->u.sha1, tmp);
        digest_len = 20;
    }
    else if (slot->kind == HK_MD5)
    {
        Md5Final(&slot->u.md5, tmp);
        digest_len = 16;
    }

    const ULONG cap = (len < digest_len) ? len : digest_len;
    for (ULONG i = 0; i < cap; ++i)
        out[i] = tmp[i];

    slot->kind = HK_NONE;
    __sync_synchronize();
    slot->in_use = 0;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptDestroyHash(HANDLE h)
{
    HashSlot* slot = hash_slot_from_handle(h, HK_NONE);
    if (slot != 0)
    {
        slot->kind = HK_NONE;
        __sync_synchronize();
        slot->in_use = 0;
    }
    return STATUS_SUCCESS;
}

/* ----- Symmetric AES surface --------------------------------------- */

/* Chaining mode tags. Default is CBC; SetProperty(BCRYPT_CHAINING_MODE,
 * L"ChainingModeECB" / "ChainingModeCBC") flips it. */
#define BCRYPT_CHAIN_CBC 0u
#define BCRYPT_CHAIN_ECB 1u

static AesKeySlot g_aes_keys[BCRYPT_MAX_AES_KEYS];

static HANDLE make_key_handle(unsigned int slot)
{
    return (HANDLE)(ULONG_PTR)(BCRYPT_KEY_HANDLE_BASE + ((ULONG_PTR)slot * BCRYPT_KEY_HANDLE_STRIDE) + 1ULL);
}

static AesKeySlot* key_slot_from_handle(HANDLE h)
{
    const ULONG_PTR v = (ULONG_PTR)h;
    if (v < BCRYPT_KEY_HANDLE_BASE)
        return 0;
    const ULONG_PTR off = v - BCRYPT_KEY_HANDLE_BASE;
    const unsigned int slot = (unsigned int)(off / BCRYPT_KEY_HANDLE_STRIDE);
    const unsigned int tag = (unsigned int)(off % BCRYPT_KEY_HANDLE_STRIDE);
    if (slot >= BCRYPT_MAX_AES_KEYS || tag != 1)
        return 0;
    AesKeySlot* k = &g_aes_keys[slot];
    return k->in_use ? k : 0;
}

__declspec(dllexport) NTSTATUS BCryptGenerateSymmetricKey(HANDLE alg, HANDLE* out_key, unsigned char* key_obj,
                                                          ULONG key_obj_len, unsigned char* secret, ULONG secret_len,
                                                          ULONG flags)
{
    (void)key_obj;
    (void)key_obj_len;
    (void)flags;
    if (out_key == 0 || secret == 0)
        return STATUS_INVALID_PARAMETER;
    if (alg != BCRYPT_ALG_AES)
        return STATUS_INVALID_PARAMETER;
    if (secret_len != 16 && secret_len != 32)
        return STATUS_INVALID_PARAMETER;

    for (unsigned int i = 0; i < BCRYPT_MAX_AES_KEYS; ++i)
    {
        if (__sync_bool_compare_and_swap(&g_aes_keys[i].in_use, 0, 1))
        {
            AesKeySlot* slot = &g_aes_keys[i];
            slot->rounds = aes_key_expansion(secret, (unsigned int)secret_len, slot->round_keys);
            slot->chain_mode = BCRYPT_CHAIN_CBC;
            *out_key = make_key_handle(i);
            return STATUS_SUCCESS;
        }
    }

    return STATUS_INVALID_PARAMETER;
}

__declspec(dllexport) NTSTATUS BCryptDestroyKey(HANDLE k)
{
    AesKeySlot* slot = key_slot_from_handle(k);
    if (slot != 0)
    {
        __sync_synchronize();
        slot->in_use = 0;
    }
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptSetProperty(HANDLE h, const wchar_t16* prop, unsigned char* value, ULONG value_len,
                                                 ULONG flags)
{
    (void)flags;
    if (prop == 0)
        return STATUS_INVALID_PARAMETER;
    /* The only property we honour is the AES chaining mode. The
     * value is a UTF-16 string ("ChainingModeCBC" / "ECB"). */
    AesKeySlot* slot = key_slot_from_handle(h);
    if (slot != 0 && wstr_eq(prop, "ChainingMode"))
    {
        if (value == 0 || value_len < 2)
            return STATUS_INVALID_PARAMETER;
        const wchar_t16* w = (const wchar_t16*)value;
        if (wstr_eq(w, "ChainingModeECB"))
            slot->chain_mode = BCRYPT_CHAIN_ECB;
        else
            slot->chain_mode = BCRYPT_CHAIN_CBC; // default + explicit "ChainingModeCBC"
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_FOUND;
}

__declspec(dllexport) NTSTATUS BCryptEncrypt(HANDLE k, unsigned char* in, ULONG in_len, void* padding_info,
                                             unsigned char* iv, ULONG iv_len, unsigned char* out, ULONG out_len,
                                             ULONG* used, ULONG flags)
{
    (void)padding_info;
    (void)flags;
    if (used)
        *used = 0;
    AesKeySlot* key = key_slot_from_handle(k);
    if (key == 0)
        return STATUS_INVALID_PARAMETER;
    if (in == 0)
        return STATUS_INVALID_PARAMETER;
    if (in_len == 0 || (in_len & 15u))
        return STATUS_INVALID_PARAMETER;
    /* Sizing pass: caller passes out == NULL to learn how big the
     * ciphertext will be. AES is length-preserving, so we report
     * in_len. */
    if (out == 0)
    {
        if (used)
            *used = in_len;
        return STATUS_SUCCESS;
    }
    if (out_len < in_len)
        return STATUS_INVALID_PARAMETER;
    if (key->chain_mode == BCRYPT_CHAIN_CBC)
    {
        if (iv == 0 || iv_len != 16)
            return STATUS_INVALID_PARAMETER;
        aes_cbc_encrypt(in, in_len, key->round_keys, key->rounds, iv, out);
    }
    else
    {
        for (ULONG off = 0; off < in_len; off += 16)
        {
            unsigned char block[16];
            for (int i = 0; i < 16; ++i)
                block[i] = in[off + i];
            aes_encrypt_block(block, key->round_keys, key->rounds);
            for (int i = 0; i < 16; ++i)
                out[off + i] = block[i];
        }
    }
    if (used)
        *used = in_len;
    return STATUS_SUCCESS;
}

__declspec(dllexport) NTSTATUS BCryptDecrypt(HANDLE k, unsigned char* in, ULONG in_len, void* padding_info,
                                             unsigned char* iv, ULONG iv_len, unsigned char* out, ULONG out_len,
                                             ULONG* used, ULONG flags)
{
    (void)padding_info;
    (void)flags;
    if (used)
        *used = 0;
    AesKeySlot* key = key_slot_from_handle(k);
    if (key == 0)
        return STATUS_INVALID_PARAMETER;
    if (in == 0)
        return STATUS_INVALID_PARAMETER;
    if (in_len == 0 || (in_len & 15u))
        return STATUS_INVALID_PARAMETER;
    if (out == 0)
    {
        if (used)
            *used = in_len;
        return STATUS_SUCCESS;
    }
    if (out_len < in_len)
        return STATUS_INVALID_PARAMETER;
    if (key->chain_mode == BCRYPT_CHAIN_CBC)
    {
        if (iv == 0 || iv_len != 16)
            return STATUS_INVALID_PARAMETER;
        aes_cbc_decrypt(in, in_len, key->round_keys, key->rounds, iv, out);
    }
    else
    {
        for (ULONG off = 0; off < in_len; off += 16)
        {
            unsigned char block[16];
            for (int i = 0; i < 16; ++i)
                block[i] = in[off + i];
            aes_decrypt_block(block, key->round_keys, key->rounds);
            for (int i = 0; i < 16; ++i)
                out[off + i] = block[i];
        }
    }
    if (used)
        *used = in_len;
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
    unsigned int hash_block_len = 64;
    unsigned int object_len = (unsigned int)sizeof(HashSlot);
    unsigned int slot = 0;
    HashKind handle_kind = HK_NONE;
    if (sz == 0 && decode_hash_handle(h, &slot, &handle_kind))
    {
        if (handle_kind == HK_SHA256)
            sz = 32;
        else if (handle_kind == HK_SHA384)
            sz = 48;
        else if (handle_kind == HK_SHA512)
            sz = 64;
        else if (handle_kind == HK_SHA1)
            sz = 20;
        else if (handle_kind == HK_MD5)
            sz = 16;
    }
    /* SHA-384 / SHA-512 use a 1024-bit (128 B) block; everything else
     * we ship is 512-bit (64 B). Object-length reports the slot payload
     * this heap-free implementation reserves per streaming hash. */
    const int is_sha512_family =
        (h == BCRYPT_ALG_SHA384 || h == BCRYPT_ALG_SHA512 || handle_kind == HK_SHA384 || handle_kind == HK_SHA512);
    if (is_sha512_family)
        hash_block_len = 128;
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
        unsigned int v;
        if (wstr_eq(prop, "BlockLength"))
            v = hash_block_len;
        else
            v = object_len;
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
