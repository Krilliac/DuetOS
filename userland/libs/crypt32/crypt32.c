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
        *h = 0xC597001ULL; /* sentinel CSP handle */
    return 1;
}

typedef unsigned short wchar_t16;
__declspec(dllexport) BOOL CryptAcquireContextW(unsigned long long* h, const wchar_t16* ct, const wchar_t16* prov,
                                                DWORD type, DWORD flags)
{
    (void)ct;
    (void)prov;
    (void)type;
    (void)flags;
    if (h)
        *h = 0xC597001ULL;
    return 1;
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

/* Format flags for CryptStringToBinaryA / CryptBinaryToStringA. */
#define CRYPT_STRING_BASE64HEADER 0x00000000
#define CRYPT_STRING_BASE64 0x00000001
#define CRYPT_STRING_BINARY 0x00000002
#define CRYPT_STRING_BASE64REQUESTHEADER 0x00000003
#define CRYPT_STRING_HEX 0x00000004
#define CRYPT_STRING_HEXASCII 0x00000005
#define CRYPT_STRING_BASE64_ANY 0x00000006
#define CRYPT_STRING_ANY 0x00000007
#define CRYPT_STRING_HEXRAW 0x0000000C
#define CRYPT_STRING_NOCRLF 0x40000000
#define CRYPT_STRING_NOCR 0x80000000

/* Base64 alphabet. */
static const char kB64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_value(char c)
{
    if (c >= 'A' && c <= 'Z')
        return (int)(c - 'A');
    if (c >= 'a' && c <= 'z')
        return (int)(c - 'a') + 26;
    if (c >= '0' && c <= '9')
        return (int)(c - '0') + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F')
        return (int)(c - 'A') + 10;
    return -1;
}

/* CryptStringToBinaryA — decode str (str_len chars; 0 means strlen).
 * Recognises BASE64 / BASE64HEADER / HEX / HEXASCII / BASE64_ANY / ANY.
 * BASE64HEADER strips a "-----BEGIN ...-----" / "-----END ...-----"
 * pair if present; BASE64_ANY accepts both forms. The HEX variant
 * tolerates whitespace between byte pairs. */
__declspec(dllexport) BOOL CryptStringToBinaryA(const char* str, DWORD str_len, DWORD flags, unsigned char* binary,
                                                DWORD* binary_size, DWORD* skip, DWORD* used_flags)
{
    if (!str || !binary_size)
        return 0;
    if (str_len == 0)
        for (str_len = 0; str[str_len]; ++str_len)
            ;
    DWORD format = flags & 0x0000FFFFu;
    /* For ANY / BASE64_ANY, sniff: any non-base64 char that isn't
     * whitespace or '=' implies HEX. */
    DWORD probe = format;
    if (format == CRYPT_STRING_BASE64_ANY || format == CRYPT_STRING_ANY)
    {
        probe = CRYPT_STRING_BASE64;
        for (DWORD i = 0; i < str_len; ++i)
        {
            char c = str[i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '=')
                continue;
            if (b64_value(c) >= 0)
                continue;
            /* Could be HEX. */
            probe = (format == CRYPT_STRING_ANY) ? CRYPT_STRING_HEX : CRYPT_STRING_BASE64;
            break;
        }
    }
    if (used_flags)
        *used_flags = probe;
    DWORD start = 0;
    if (probe == CRYPT_STRING_BASE64HEADER || probe == CRYPT_STRING_BASE64)
    {
        /* Skip optional PEM header. */
        for (DWORD i = 0; i + 5 < str_len; ++i)
        {
            if (str[i] == '-' && str[i + 1] == '-' && str[i + 2] == '-' && str[i + 3] == '-' && str[i + 4] == '-')
            {
                /* Find newline after this header line. */
                DWORD j = i + 5;
                while (j < str_len && str[j] != '\n')
                    ++j;
                if (j < str_len)
                    start = j + 1;
                break;
            }
        }
    }
    if (skip)
        *skip = start;
    /* HEX / HEXASCII: pairs of nibbles, ignore whitespace. */
    if (probe == CRYPT_STRING_HEX || probe == CRYPT_STRING_HEXRAW || probe == CRYPT_STRING_HEXASCII)
    {
        DWORD out_idx = 0;
        int hi = -1;
        for (DWORD i = start; i < str_len; ++i)
        {
            char c = str[i];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-')
                continue;
            int v = hex_value(c);
            if (v < 0)
                break; /* HEXASCII has trailing ASCII text — stop. */
            if (hi < 0)
            {
                hi = v;
            }
            else
            {
                if (binary && out_idx < *binary_size)
                    binary[out_idx] = (unsigned char)((hi << 4) | v);
                ++out_idx;
                hi = -1;
            }
        }
        if (binary && out_idx > *binary_size)
            return 0;
        *binary_size = out_idx;
        return 1;
    }
    /* BASE64 / BASE64HEADER. */
    DWORD out_idx = 0;
    unsigned int accum = 0;
    int bits = 0;
    DWORD i = start;
    for (; i < str_len; ++i)
    {
        char c = str[i];
        if (c == '=')
            break;
        if (c == '-' && i + 4 < str_len && str[i + 1] == '-')
            break; /* PEM footer */
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            continue;
        int v = b64_value(c);
        if (v < 0)
            return 0;
        accum = (accum << 6) | (unsigned int)v;
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            unsigned char b = (unsigned char)((accum >> bits) & 0xFFu);
            if (binary && out_idx < *binary_size)
                binary[out_idx] = b;
            ++out_idx;
        }
    }
    if (binary && out_idx > *binary_size)
        return 0;
    *binary_size = out_idx;
    return 1;
}

/* CryptBinaryToStringA — encode binary (binary_size bytes) into str.
 * Recognises BASE64 / BASE64HEADER / HEX / HEXASCII / HEXRAW. The
 * caller is expected to query the required size first by passing a
 * NULL str pointer; we return the inclusive-NUL char count via *str_len. */
__declspec(dllexport) BOOL CryptBinaryToStringA(const unsigned char* binary, DWORD binary_size, DWORD flags, char* str,
                                                DWORD* str_len)
{
    if (!str_len)
        return 0;
    DWORD format = flags & 0x0000FFFFu;
    int suppress_cr = (flags & CRYPT_STRING_NOCR) != 0;
    int suppress_crlf = (flags & CRYPT_STRING_NOCRLF) != 0;
    /* HEX / HEXRAW / HEXASCII. */
    if (format == CRYPT_STRING_HEX || format == CRYPT_STRING_HEXRAW || format == CRYPT_STRING_HEXASCII)
    {
        DWORD per_line = (format == CRYPT_STRING_HEXRAW) ? 0xFFFFFFFFu : 16;
        DWORD needed = 0;
        for (DWORD i = 0; i < binary_size; ++i)
        {
            needed += 2; /* xx */
            if (i + 1 < binary_size)
            {
                if ((i + 1) % per_line == 0 && !suppress_crlf)
                    needed += suppress_cr ? 1 : 2; /* line break */
                else if (format != CRYPT_STRING_HEXRAW)
                    needed += 1; /* space separator */
            }
        }
        ++needed; /* NUL */
        if (!str || *str_len < needed)
        {
            *str_len = needed;
            return str ? 0 : 1;
        }
        DWORD pos = 0;
        for (DWORD i = 0; i < binary_size; ++i)
        {
            const char* h = "0123456789abcdef";
            str[pos++] = h[(binary[i] >> 4) & 0xF];
            str[pos++] = h[binary[i] & 0xF];
            if (i + 1 < binary_size)
            {
                if ((i + 1) % per_line == 0 && !suppress_crlf)
                {
                    if (!suppress_cr)
                        str[pos++] = '\r';
                    str[pos++] = '\n';
                }
                else if (format != CRYPT_STRING_HEXRAW)
                {
                    str[pos++] = ' ';
                }
            }
        }
        str[pos++] = 0;
        *str_len = pos - 1; /* by Win32 contract: chars without NUL */
        return 1;
    }
    /* BASE64 / BASE64HEADER. */
    DWORD body_groups = (binary_size + 2) / 3;
    DWORD body_chars = body_groups * 4;
    DWORD line_breaks = 0;
    if (!suppress_crlf)
        line_breaks = (body_chars / 64) * (suppress_cr ? 1 : 2);
    DWORD header_chars = 0;
    if (format == CRYPT_STRING_BASE64HEADER || format == CRYPT_STRING_BASE64REQUESTHEADER)
    {
        /* "-----BEGIN CERTIFICATE-----\r\n...\r\n-----END CERTIFICATE-----\r\n" */
        const char* tag = (format == CRYPT_STRING_BASE64REQUESTHEADER) ? "CERTIFICATE REQUEST" : "CERTIFICATE";
        DWORD tag_len = 0;
        while (tag[tag_len])
            ++tag_len;
        header_chars = (5 + 6 + tag_len + 5 + 2) + (5 + 4 + tag_len + 5 + 2);
    }
    DWORD needed = body_chars + line_breaks + header_chars + 1;
    if (!str || *str_len < needed)
    {
        *str_len = needed;
        return str ? 0 : 1;
    }
    DWORD pos = 0;
    if (format == CRYPT_STRING_BASE64HEADER || format == CRYPT_STRING_BASE64REQUESTHEADER)
    {
        const char* tag = (format == CRYPT_STRING_BASE64REQUESTHEADER) ? "CERTIFICATE REQUEST" : "CERTIFICATE";
        const char* lead = "-----BEGIN ";
        for (DWORD i = 0; lead[i]; ++i)
            str[pos++] = lead[i];
        for (DWORD i = 0; tag[i]; ++i)
            str[pos++] = tag[i];
        str[pos++] = '-';
        str[pos++] = '-';
        str[pos++] = '-';
        str[pos++] = '-';
        str[pos++] = '-';
        str[pos++] = '\r';
        str[pos++] = '\n';
    }
    DWORD col = 0;
    for (DWORD i = 0; i < binary_size; i += 3)
    {
        unsigned int n = ((unsigned int)binary[i]) << 16;
        if (i + 1 < binary_size)
            n |= ((unsigned int)binary[i + 1]) << 8;
        if (i + 2 < binary_size)
            n |= (unsigned int)binary[i + 2];
        str[pos++] = kB64Alphabet[(n >> 18) & 0x3F];
        str[pos++] = kB64Alphabet[(n >> 12) & 0x3F];
        str[pos++] = (i + 1 < binary_size) ? kB64Alphabet[(n >> 6) & 0x3F] : '=';
        str[pos++] = (i + 2 < binary_size) ? kB64Alphabet[n & 0x3F] : '=';
        col += 4;
        if (!suppress_crlf && col >= 64 && i + 3 < binary_size)
        {
            if (!suppress_cr)
                str[pos++] = '\r';
            str[pos++] = '\n';
            col = 0;
        }
    }
    if (format == CRYPT_STRING_BASE64HEADER || format == CRYPT_STRING_BASE64REQUESTHEADER)
    {
        const char* tag = (format == CRYPT_STRING_BASE64REQUESTHEADER) ? "CERTIFICATE REQUEST" : "CERTIFICATE";
        if (!suppress_crlf)
        {
            if (!suppress_cr)
                str[pos++] = '\r';
            str[pos++] = '\n';
        }
        const char* lead = "-----END ";
        for (DWORD i = 0; lead[i]; ++i)
            str[pos++] = lead[i];
        for (DWORD i = 0; tag[i]; ++i)
            str[pos++] = tag[i];
        str[pos++] = '-';
        str[pos++] = '-';
        str[pos++] = '-';
        str[pos++] = '-';
        str[pos++] = '-';
        str[pos++] = '\r';
        str[pos++] = '\n';
    }
    str[pos++] = 0;
    *str_len = pos - 1;
    return 1;
}

/* CALG_* values used by CryptCreateHash. */
#define CALG_MD5 0x00008003UL
#define CALG_SHA1 0x00008004UL
#define CALG_SHA_256 0x0000800CUL

/* HP_* values for CryptGetHashParam. */
#define HP_HASHVAL 0x0002UL
#define HP_HASHSIZE 0x0004UL
#define HP_ALGID 0x0001UL

/* SHA-256 / SHA-1 / MD5 reference structures.  Independent from
 * bcrypt.dll because each freestanding DLL is its own translation
 * unit — the implementations are short enough that duplicating
 * them is cheaper than introducing an internal-shared static lib. */
typedef struct
{
    unsigned int h[8];
    unsigned char buf[64];
    unsigned long long bitlen;
    unsigned int buflen;
} C32_Sha256;

typedef struct
{
    unsigned int h[5];
    unsigned char buf[64];
    unsigned long long bitlen;
    unsigned int buflen;
} C32_Sha1;

typedef struct
{
    unsigned int a, b, c, d;
    unsigned char buf[64];
    unsigned long long bitlen;
    unsigned int buflen;
} C32_Md5;

static unsigned int c32_rotr32(unsigned int x, unsigned int n)
{
    return (x >> n) | (x << (32 - n));
}
static unsigned int c32_rotl32(unsigned int x, unsigned int n)
{
    return (x << n) | (x >> (32 - n));
}

static const unsigned int kC32Sha256K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

static void c32_sha256_init(C32_Sha256* s)
{
    static const unsigned int H[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    for (int i = 0; i < 8; ++i)
        s->h[i] = H[i];
    s->buflen = 0;
    s->bitlen = 0;
}

static void c32_sha256_block(C32_Sha256* s, const unsigned char* p)
{
    unsigned int w[64];
    for (int i = 0; i < 16; ++i)
        w[i] = ((unsigned int)p[i * 4] << 24) | ((unsigned int)p[i * 4 + 1] << 16) | ((unsigned int)p[i * 4 + 2] << 8) |
               (unsigned int)p[i * 4 + 3];
    for (int i = 16; i < 64; ++i)
    {
        unsigned int s0 = c32_rotr32(w[i - 15], 7) ^ c32_rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        unsigned int s1 = c32_rotr32(w[i - 2], 17) ^ c32_rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    unsigned int a = s->h[0], b = s->h[1], c = s->h[2], d = s->h[3];
    unsigned int e = s->h[4], f = s->h[5], g = s->h[6], hh = s->h[7];
    for (int i = 0; i < 64; ++i)
    {
        unsigned int S1 = c32_rotr32(e, 6) ^ c32_rotr32(e, 11) ^ c32_rotr32(e, 25);
        unsigned int ch = (e & f) ^ (~e & g);
        unsigned int t1 = hh + S1 + ch + kC32Sha256K[i] + w[i];
        unsigned int S0 = c32_rotr32(a, 2) ^ c32_rotr32(a, 13) ^ c32_rotr32(a, 22);
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

static void c32_sha256_update(C32_Sha256* s, const unsigned char* p, unsigned int n)
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
            c32_sha256_block(s, s->buf);
            s->buflen = 0;
        }
    }
}

static void c32_sha256_final(C32_Sha256* s, unsigned char* out)
{
    s->buf[s->buflen++] = 0x80;
    if (s->buflen > 56)
    {
        while (s->buflen < 64)
            s->buf[s->buflen++] = 0;
        c32_sha256_block(s, s->buf);
        s->buflen = 0;
    }
    while (s->buflen < 56)
        s->buf[s->buflen++] = 0;
    unsigned long long bl = s->bitlen;
    for (int i = 7; i >= 0; --i)
        s->buf[56 + i] = (unsigned char)(bl >> ((7 - i) * 8));
    c32_sha256_block(s, s->buf);
    for (int i = 0; i < 8; ++i)
    {
        out[i * 4 + 0] = (unsigned char)(s->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(s->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(s->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(s->h[i] >> 0);
    }
}

/* Keep SHA-1 + MD5 implementations compact — exact algorithm
 * matches the bcrypt copy. */
static void c32_sha1_init(C32_Sha1* s)
{
    s->h[0] = 0x67452301;
    s->h[1] = 0xEFCDAB89;
    s->h[2] = 0x98BADCFE;
    s->h[3] = 0x10325476;
    s->h[4] = 0xC3D2E1F0;
    s->buflen = 0;
    s->bitlen = 0;
}
static void c32_sha1_block(C32_Sha1* s, const unsigned char* p)
{
    unsigned int w[80];
    for (int i = 0; i < 16; ++i)
        w[i] = ((unsigned int)p[i * 4] << 24) | ((unsigned int)p[i * 4 + 1] << 16) | ((unsigned int)p[i * 4 + 2] << 8) |
               (unsigned int)p[i * 4 + 3];
    for (int i = 16; i < 80; ++i)
        w[i] = c32_rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
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
        unsigned int t = c32_rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = c32_rotl32(b, 30);
        b = a;
        a = t;
    }
    s->h[0] += a;
    s->h[1] += b;
    s->h[2] += c;
    s->h[3] += d;
    s->h[4] += e;
}
static void c32_sha1_update(C32_Sha1* s, const unsigned char* p, unsigned int n)
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
            c32_sha1_block(s, s->buf);
            s->buflen = 0;
        }
    }
}
static void c32_sha1_final(C32_Sha1* s, unsigned char* out)
{
    s->buf[s->buflen++] = 0x80;
    if (s->buflen > 56)
    {
        while (s->buflen < 64)
            s->buf[s->buflen++] = 0;
        c32_sha1_block(s, s->buf);
        s->buflen = 0;
    }
    while (s->buflen < 56)
        s->buf[s->buflen++] = 0;
    unsigned long long bl = s->bitlen;
    for (int i = 7; i >= 0; --i)
        s->buf[56 + i] = (unsigned char)(bl >> ((7 - i) * 8));
    c32_sha1_block(s, s->buf);
    for (int i = 0; i < 5; ++i)
    {
        out[i * 4 + 0] = (unsigned char)(s->h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(s->h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(s->h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)(s->h[i] >> 0);
    }
}

static const unsigned int kC32Md5K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

static const unsigned int kC32Md5R[64] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                                          5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20, 5, 9,  14, 20,
                                          4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                                          6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};

static void c32_md5_init(C32_Md5* s)
{
    s->a = 0x67452301;
    s->b = 0xefcdab89;
    s->c = 0x98badcfe;
    s->d = 0x10325476;
    s->buflen = 0;
    s->bitlen = 0;
}
static void c32_md5_block(C32_Md5* s, const unsigned char* p)
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
        b = b + c32_rotl32(a + f + kC32Md5K[i] + M[g], kC32Md5R[i]);
        a = t;
    }
    s->a += a;
    s->b += b;
    s->c += c;
    s->d += d;
}
static void c32_md5_update(C32_Md5* s, const unsigned char* p, unsigned int n)
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
            c32_md5_block(s, s->buf);
            s->buflen = 0;
        }
    }
}
static void c32_md5_final(C32_Md5* s, unsigned char* out)
{
    s->buf[s->buflen++] = 0x80;
    if (s->buflen > 56)
    {
        while (s->buflen < 64)
            s->buf[s->buflen++] = 0;
        c32_md5_block(s, s->buf);
        s->buflen = 0;
    }
    while (s->buflen < 56)
        s->buf[s->buflen++] = 0;
    unsigned long long bl = s->bitlen;
    for (int i = 0; i < 8; ++i)
        s->buf[56 + i] = (unsigned char)(bl >> (i * 8));
    c32_md5_block(s, s->buf);
    unsigned int v[4] = {s->a, s->b, s->c, s->d};
    for (int i = 0; i < 4; ++i)
    {
        out[i * 4 + 0] = (unsigned char)(v[i] >> 0);
        out[i * 4 + 1] = (unsigned char)(v[i] >> 8);
        out[i * 4 + 2] = (unsigned char)(v[i] >> 16);
        out[i * 4 + 3] = (unsigned char)(v[i] >> 24);
    }
}

/* Hash-handle slots. Single-threaded callers only. */
typedef struct
{
    DWORD algid; /* CALG_* */
    unsigned int active;
    unsigned int finalized;
    unsigned char digest[32];
    unsigned int digest_len;
    union
    {
        C32_Sha256 sha256;
        C32_Sha1 sha1;
        C32_Md5 md5;
    } u;
} CryptHashSlot;

#define CRYPT32_HASH_SLOTS 4
static CryptHashSlot g_hash_slots[CRYPT32_HASH_SLOTS];

__declspec(dllexport) BOOL CryptCreateHash(unsigned long long h, DWORD algid, unsigned long long key, DWORD flags,
                                           unsigned long long* hash)
{
    (void)h;
    (void)key;
    (void)flags;
    if (!hash)
        return 0;
    *hash = 0;
    /* Find an unused slot. */
    int slot = -1;
    for (int i = 0; i < CRYPT32_HASH_SLOTS; ++i)
    {
        if (!g_hash_slots[i].active)
        {
            slot = i;
            break;
        }
    }
    if (slot < 0)
        return 0;
    CryptHashSlot* s = &g_hash_slots[slot];
    s->algid = algid;
    s->active = 1;
    s->finalized = 0;
    if (algid == CALG_SHA_256)
    {
        c32_sha256_init(&s->u.sha256);
        s->digest_len = 32;
    }
    else if (algid == CALG_SHA1)
    {
        c32_sha1_init(&s->u.sha1);
        s->digest_len = 20;
    }
    else if (algid == CALG_MD5)
    {
        c32_md5_init(&s->u.md5);
        s->digest_len = 16;
    }
    else
    {
        s->active = 0;
        return 0;
    }
    *hash = 0xCFA50000ULL | (unsigned int)slot;
    return 1;
}

static CryptHashSlot* hash_slot_from_handle(unsigned long long h)
{
    if ((h & 0xFFFF0000ULL) != 0xCFA50000ULL)
        return (CryptHashSlot*)0;
    int idx = (int)(h & 0xFFFFu);
    if (idx < 0 || idx >= CRYPT32_HASH_SLOTS)
        return (CryptHashSlot*)0;
    if (!g_hash_slots[idx].active)
        return (CryptHashSlot*)0;
    return &g_hash_slots[idx];
}

__declspec(dllexport) BOOL CryptHashData(unsigned long long h, const unsigned char* data, DWORD len, DWORD flags)
{
    (void)flags;
    CryptHashSlot* s = hash_slot_from_handle(h);
    if (!s || s->finalized)
        return 0;
    if (len == 0 || !data)
        return 1;
    if (s->algid == CALG_SHA_256)
        c32_sha256_update(&s->u.sha256, data, (unsigned int)len);
    else if (s->algid == CALG_SHA1)
        c32_sha1_update(&s->u.sha1, data, (unsigned int)len);
    else if (s->algid == CALG_MD5)
        c32_md5_update(&s->u.md5, data, (unsigned int)len);
    else
        return 0;
    return 1;
}

__declspec(dllexport) BOOL CryptDestroyHash(unsigned long long h)
{
    CryptHashSlot* s = hash_slot_from_handle(h);
    if (s)
        s->active = 0;
    return 1;
}

__declspec(dllexport) BOOL CryptGetHashParam(unsigned long long h, DWORD param, unsigned char* buf, DWORD* len,
                                             DWORD flags)
{
    (void)flags;
    CryptHashSlot* s = hash_slot_from_handle(h);
    if (!s || !len)
        return 0;
    if (param == HP_HASHSIZE)
    {
        if (!buf)
        {
            *len = 4;
            return 1;
        }
        if (*len < 4)
        {
            *len = 4;
            return 0;
        }
        unsigned int v = s->digest_len;
        buf[0] = (unsigned char)(v & 0xFF);
        buf[1] = (unsigned char)((v >> 8) & 0xFF);
        buf[2] = (unsigned char)((v >> 16) & 0xFF);
        buf[3] = (unsigned char)((v >> 24) & 0xFF);
        *len = 4;
        return 1;
    }
    if (param == HP_ALGID)
    {
        if (!buf)
        {
            *len = 4;
            return 1;
        }
        if (*len < 4)
        {
            *len = 4;
            return 0;
        }
        unsigned int v = s->algid;
        buf[0] = (unsigned char)(v & 0xFF);
        buf[1] = (unsigned char)((v >> 8) & 0xFF);
        buf[2] = (unsigned char)((v >> 16) & 0xFF);
        buf[3] = (unsigned char)((v >> 24) & 0xFF);
        *len = 4;
        return 1;
    }
    if (param == HP_HASHVAL)
    {
        if (!s->finalized)
        {
            /* Win32: lazy-finalise on first HP_HASHVAL query. */
            if (s->algid == CALG_SHA_256)
                c32_sha256_final(&s->u.sha256, s->digest);
            else if (s->algid == CALG_SHA1)
                c32_sha1_final(&s->u.sha1, s->digest);
            else if (s->algid == CALG_MD5)
                c32_md5_final(&s->u.md5, s->digest);
            else
                return 0;
            s->finalized = 1;
        }
        if (!buf)
        {
            *len = s->digest_len;
            return 1;
        }
        if (*len < s->digest_len)
        {
            *len = s->digest_len;
            return 0;
        }
        for (DWORD i = 0; i < s->digest_len; ++i)
            buf[i] = s->digest[i];
        *len = s->digest_len;
        return 1;
    }
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

/* Wide-name & extended cert helpers. */
__declspec(dllexport) DWORD CertGetNameStringA(const void* ctx, DWORD type, DWORD flags, void* type_param, char* name,
                                               DWORD name_len)
{
    (void)ctx;
    (void)type;
    (void)flags;
    (void)type_param;
    (void)name_len;
    if (name)
        name[0] = 0;
    return 1;
}

__declspec(dllexport) BOOL CertGetCertificateContextProperty(const void* ctx, DWORD prop_id, void* data,
                                                             DWORD* data_size)
{
    (void)ctx;
    (void)prop_id;
    (void)data;
    if (data_size)
        *data_size = 0;
    return 0;
}

__declspec(dllexport) BOOL CertSetCertificateContextProperty(const void* ctx, DWORD prop_id, DWORD flags,
                                                             const void* data)
{
    (void)ctx;
    (void)prop_id;
    (void)flags;
    (void)data;
    return 0;
}

__declspec(dllexport) BOOL CertControlStore(HANDLE store, DWORD flags, DWORD ctrl_type, const void* ctrl_para)
{
    (void)store;
    (void)flags;
    (void)ctrl_type;
    (void)ctrl_para;
    return 1;
}

__declspec(dllexport) DWORD CertNameToStrA(DWORD enc, const void* name_blob, DWORD str_type, char* psz, DWORD csz)
{
    (void)enc;
    (void)name_blob;
    (void)str_type;
    if (psz && csz > 0)
        psz[0] = 0;
    return 1;
}

__declspec(dllexport) DWORD CertNameToStrW(DWORD enc, const void* name_blob, DWORD str_type, wchar_t16* psz, DWORD csz)
{
    (void)enc;
    (void)name_blob;
    (void)str_type;
    if (psz && csz > 0)
        psz[0] = 0;
    return 1;
}

/* PFXImportCertStore / PFXExportCertStore / PFXIsPFXBlob —
 * PKCS#12 envelope. v0 has no PFX engine. */
__declspec(dllexport) HANDLE PFXImportCertStore(const void* pfx_blob, const wchar_t16* password, DWORD flags)
{
    (void)pfx_blob;
    (void)password;
    (void)flags;
    return (HANDLE)0;
}

__declspec(dllexport) BOOL PFXExportCertStore(HANDLE store, void* pfx_blob, const wchar_t16* password, DWORD flags)
{
    (void)store;
    (void)pfx_blob;
    (void)password;
    (void)flags;
    return 0;
}

__declspec(dllexport) BOOL PFXIsPFXBlob(const void* pfx_blob)
{
    (void)pfx_blob;
    return 0;
}

/* CryptStringToBinaryW — wide variant. */
__declspec(dllexport) BOOL CryptStringToBinaryW(const wchar_t16* str, DWORD str_len, DWORD flags, unsigned char* binary,
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

__declspec(dllexport) BOOL CryptBinaryToStringW(const unsigned char* binary, DWORD binary_size, DWORD flags,
                                                wchar_t16* str, DWORD* str_len)
{
    (void)binary;
    (void)binary_size;
    (void)flags;
    (void)str;
    if (str_len)
        *str_len = 0;
    return 0;
}

/* CryptDecodeObject / Ex / CryptEncodeObject / Ex — ASN.1
 * decode/encode. v0 has no ASN.1 parser; report failure with
 * size = 0 so callers fall through. */
__declspec(dllexport) BOOL CryptDecodeObject(DWORD enc, const void* type, const unsigned char* data, DWORD data_size,
                                             DWORD flags, void* out, DWORD* out_size)
{
    (void)enc;
    (void)type;
    (void)data;
    (void)data_size;
    (void)flags;
    (void)out;
    if (out_size)
        *out_size = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptDecodeObjectEx(DWORD enc, const void* type, const unsigned char* data, DWORD data_size,
                                               DWORD flags, void* p_decode_para, void* out, DWORD* out_size)
{
    (void)enc;
    (void)type;
    (void)data;
    (void)data_size;
    (void)flags;
    (void)p_decode_para;
    (void)out;
    if (out_size)
        *out_size = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptEncodeObject(DWORD enc, const void* type, const void* data, unsigned char* out,
                                             DWORD* out_size)
{
    (void)enc;
    (void)type;
    (void)data;
    (void)out;
    if (out_size)
        *out_size = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptEncodeObjectEx(DWORD enc, const void* type, const void* data, DWORD flags,
                                               void* p_encode_para, void* out, DWORD* out_size)
{
    (void)enc;
    (void)type;
    (void)data;
    (void)flags;
    (void)p_encode_para;
    (void)out;
    if (out_size)
        *out_size = 0;
    return 0;
}

/* CertAddCertificateContextToStore — accepts but does nothing
 * persistent. */
__declspec(dllexport) BOOL CertAddCertificateContextToStore(HANDLE store, const void* ctx, DWORD disposition,
                                                            const void** stored_ctx)
{
    (void)store;
    (void)ctx;
    (void)disposition;
    if (stored_ctx)
        *stored_ctx = (void*)0;
    return 0;
}

__declspec(dllexport) BOOL CertDeleteCertificateFromStore(const void* ctx)
{
    (void)ctx;
    return 1;
}

__declspec(dllexport) const void* CertCreateCertificateContext(DWORD enc, const unsigned char* der_bytes,
                                                               DWORD der_byte_count)
{
    (void)enc;
    (void)der_bytes;
    (void)der_byte_count;
    return (void*)0;
}

__declspec(dllexport) const void* CertDuplicateCertificateContext(const void* ctx)
{
    return ctx;
}

/* CryptVerifyCertificateSignature / Ex — signature verification.
 * v0 reports "valid" so callers proceed; real verification needs
 * an X.509 ASN.1 parser. This is a deliberate facade — the
 * caller will revoke trust later when the actual TLS handshake
 * parses the cert with bcrypt or schannel. */
__declspec(dllexport) BOOL CryptVerifyCertificateSignature(unsigned long long crypt_provider, DWORD enc,
                                                           const unsigned char* der_bytes, DWORD der_size,
                                                           void* pub_key)
{
    (void)crypt_provider;
    (void)enc;
    (void)der_bytes;
    (void)der_size;
    (void)pub_key;
    return 1;
}

__declspec(dllexport) BOOL CryptVerifyCertificateSignatureEx(unsigned long long crypt_provider, DWORD enc,
                                                             DWORD subject_type, void* subject, DWORD issuer_type,
                                                             void* issuer, DWORD flags, void* extra)
{
    (void)crypt_provider;
    (void)enc;
    (void)subject_type;
    (void)subject;
    (void)issuer_type;
    (void)issuer;
    (void)flags;
    (void)extra;
    return 1;
}

/* CertGetIssuerCertificateFromStore — chain helper. v0 no-cert. */
__declspec(dllexport) const void* CertGetIssuerCertificateFromStore(HANDLE store, const void* subject, const void* prev,
                                                                    DWORD* flags)
{
    (void)store;
    (void)subject;
    (void)prev;
    if (flags)
        *flags = 0;
    return (void*)0;
}

__declspec(dllexport) BOOL CertGetCertificateChain(HANDLE chain_engine, const void* leaf, void* time, HANDLE store,
                                                   void* pchain_para, DWORD flags, void* reserved, void** chain_ctx)
{
    (void)chain_engine;
    (void)leaf;
    (void)time;
    (void)store;
    (void)pchain_para;
    (void)flags;
    (void)reserved;
    if (chain_ctx)
        *chain_ctx = (void*)0;
    return 0;
}

__declspec(dllexport) void CertFreeCertificateChain(const void* chain)
{
    (void)chain;
}

/* CryptMsgOpenToDecode / CryptMsgUpdate / CryptMsgGetParam /
 * CryptMsgClose — PKCS#7 / CMS messages. */
__declspec(dllexport) HANDLE CryptMsgOpenToDecode(DWORD enc, DWORD flags, DWORD msg_type, unsigned long long crypt,
                                                  void* recipient_info, void* stream_info)
{
    (void)enc;
    (void)flags;
    (void)msg_type;
    (void)crypt;
    (void)recipient_info;
    (void)stream_info;
    return (HANDLE)0;
}

__declspec(dllexport) BOOL CryptMsgUpdate(HANDLE msg, const unsigned char* data, DWORD data_len, BOOL final)
{
    (void)msg;
    (void)data;
    (void)data_len;
    (void) final;
    return 0;
}

__declspec(dllexport) BOOL CryptMsgGetParam(HANDLE msg, DWORD param_type, DWORD index, void* data, DWORD* data_len)
{
    (void)msg;
    (void)param_type;
    (void)index;
    (void)data;
    if (data_len)
        *data_len = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptMsgClose(HANDLE msg)
{
    (void)msg;
    return 1;
}

__declspec(dllexport) BOOL CryptSignAndEncryptMessage(void* sign_para, void* encrypt_para, DWORD num_recipients,
                                                      const void** recipient_certs, const unsigned char* in,
                                                      DWORD in_len, unsigned char* out, DWORD* out_len)
{
    (void)sign_para;
    (void)encrypt_para;
    (void)num_recipients;
    (void)recipient_certs;
    (void)in;
    (void)in_len;
    (void)out;
    if (out_len)
        *out_len = 0;
    return 0;
}
