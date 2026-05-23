/*
 * DuetOS — on-target package manager (v0 scaffold).
 *
 * `duet-pkg` runs as a ring-3 native ELF spawned from /bin/duet-pkg.
 * v0 carries the architectural skeleton:
 *
 *   subcommands:
 *     selftest        — exercise the bundled SHA-256 impl against
 *                       known-answer vectors. Returns 0 on match.
 *     hash <string>   — print SHA-256 of an argv string.
 *     version | --version | -V
 *     help    | --help | -h
 *
 * Deferred to follow-on slices:
 *   - network fetch over SYS_SOCKET_OP (153)
 *   - RSA-PSS signature verify (needs RSA + bigint primitives
 *     in userland; ~1.5k LOC reference impl).
 *   - manifest parsing (subset of TOML)
 *   - dependency resolver + installer
 *
 * The host-side equivalent lives in tools/pkg/ and remains the
 * authoritative implementation until the on-target port reaches
 * feature parity. This file proves the architecture exists end-
 * to-end (ELF spawn -> argv -> crypto -> exit code) so subsequent
 * slices have something to extend.
 *
 * Crypto provenance: the SHA-256 implementation below is a clean-
 * room reference of FIPS 180-4 §6.2, paraphrased from the standard
 * — block size 64 B, output 32 B, K constants per §4.2.2. Verified
 * against the three NIST test vectors in `selftest()`.
 */

#include "stdio.h"
#include "string.h"
#include "unistd.h"

#define DUETPKG_VERSION "0.1.0-scaffold"

/* ----------------------------------------------------------------
 * SHA-256 — FIPS 180-4 reference implementation.
 * ---------------------------------------------------------------- */

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long u64;

#define SHA256_DIGEST_BYTES 32
#define SHA256_BLOCK_BYTES 64

static const u32 kSha256K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static u32 RotR(u32 x, u32 n)
{
    return (x >> n) | (x << (32 - n));
}

typedef struct
{
    u32 h[8];
    u64 bytes_processed;
    u8 buf[SHA256_BLOCK_BYTES];
    u32 buf_len;
} Sha256Ctx;

static void Sha256Init(Sha256Ctx* c)
{
    c->h[0] = 0x6a09e667u;
    c->h[1] = 0xbb67ae85u;
    c->h[2] = 0x3c6ef372u;
    c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu;
    c->h[5] = 0x9b05688cu;
    c->h[6] = 0x1f83d9abu;
    c->h[7] = 0x5be0cd19u;
    c->bytes_processed = 0;
    c->buf_len = 0;
}

static void Sha256Compress(Sha256Ctx* c, const u8 block[SHA256_BLOCK_BYTES])
{
    u32 w[64];
    for (u32 i = 0; i < 16; ++i)
    {
        const u32 b0 = (u32)block[i * 4 + 0];
        const u32 b1 = (u32)block[i * 4 + 1];
        const u32 b2 = (u32)block[i * 4 + 2];
        const u32 b3 = (u32)block[i * 4 + 3];
        w[i] = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }
    for (u32 i = 16; i < 64; ++i)
    {
        const u32 s0 = RotR(w[i - 15], 7) ^ RotR(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const u32 s1 = RotR(w[i - 2], 17) ^ RotR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    u32 a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    u32 e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (u32 i = 0; i < 64; ++i)
    {
        const u32 S1 = RotR(e, 6) ^ RotR(e, 11) ^ RotR(e, 25);
        const u32 ch = (e & f) ^ ((~e) & g);
        const u32 t1 = h + S1 + ch + kSha256K[i] + w[i];
        const u32 S0 = RotR(a, 2) ^ RotR(a, 13) ^ RotR(a, 22);
        const u32 mj = (a & b) ^ (a & cc) ^ (b & cc);
        const u32 t2 = S0 + mj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = cc;
        cc = b;
        b = a;
        a = t1 + t2;
    }
    c->h[0] += a;
    c->h[1] += b;
    c->h[2] += cc;
    c->h[3] += d;
    c->h[4] += e;
    c->h[5] += f;
    c->h[6] += g;
    c->h[7] += h;
}

static void Sha256Update(Sha256Ctx* c, const void* data, size_t len)
{
    const u8* p = (const u8*)data;
    c->bytes_processed += (u64)len;
    while (len > 0)
    {
        const size_t take =
            (len < (size_t)(SHA256_BLOCK_BYTES - c->buf_len)) ? len : (size_t)(SHA256_BLOCK_BYTES - c->buf_len);
        for (size_t i = 0; i < take; ++i)
            c->buf[c->buf_len + i] = p[i];
        c->buf_len += (u32)take;
        p += take;
        len -= take;
        if (c->buf_len == SHA256_BLOCK_BYTES)
        {
            Sha256Compress(c, c->buf);
            c->buf_len = 0;
        }
    }
}

static void Sha256Final(Sha256Ctx* c, u8 out[SHA256_DIGEST_BYTES])
{
    const u64 bit_len = c->bytes_processed * 8;
    c->buf[c->buf_len++] = 0x80;
    if (c->buf_len > 56)
    {
        while (c->buf_len < SHA256_BLOCK_BYTES)
            c->buf[c->buf_len++] = 0;
        Sha256Compress(c, c->buf);
        c->buf_len = 0;
    }
    while (c->buf_len < 56)
        c->buf[c->buf_len++] = 0;
    for (int i = 7; i >= 0; --i)
        c->buf[c->buf_len++] = (u8)(bit_len >> (i * 8));
    Sha256Compress(c, c->buf);
    for (u32 i = 0; i < 8; ++i)
    {
        out[i * 4 + 0] = (u8)(c->h[i] >> 24);
        out[i * 4 + 1] = (u8)(c->h[i] >> 16);
        out[i * 4 + 2] = (u8)(c->h[i] >> 8);
        out[i * 4 + 3] = (u8)(c->h[i]);
    }
}

static void Sha256OneShot(const void* data, size_t len, u8 out[SHA256_DIGEST_BYTES])
{
    Sha256Ctx c;
    Sha256Init(&c);
    Sha256Update(&c, data, len);
    Sha256Final(&c, out);
}

/* ----------------------------------------------------------------
 * Helpers.
 * ---------------------------------------------------------------- */

static size_t StrLenLocal(const char* s)
{
    size_t n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

static int StrEqLocal(const char* a, const char* b)
{
    while (*a != '\0' && *b != '\0' && *a == *b)
    {
        ++a;
        ++b;
    }
    return *a == '\0' && *b == '\0';
}

static void PrintHex32(const u8 d[SHA256_DIGEST_BYTES])
{
    const char* hex = "0123456789abcdef";
    char out[SHA256_DIGEST_BYTES * 2 + 1];
    for (u32 i = 0; i < SHA256_DIGEST_BYTES; ++i)
    {
        out[i * 2 + 0] = hex[(d[i] >> 4) & 0x0F];
        out[i * 2 + 1] = hex[d[i] & 0x0F];
    }
    out[SHA256_DIGEST_BYTES * 2] = '\0';
    puts_str(out);
}

static int DigestEqual(const u8 a[SHA256_DIGEST_BYTES], const u8 b[SHA256_DIGEST_BYTES])
{
    for (u32 i = 0; i < SHA256_DIGEST_BYTES; ++i)
        if (a[i] != b[i])
            return 0;
    return 1;
}

/* ----------------------------------------------------------------
 * Subcommands.
 * ---------------------------------------------------------------- */

static int CmdVersion(void)
{
    println("duet-pkg " DUETPKG_VERSION);
    println("DuetOS on-target package manager (v0 scaffold).");
    return 0;
}

static int CmdHelp(void)
{
    println("USAGE: duet-pkg <subcommand> [args...]");
    println("");
    println("Subcommands:");
    println("  selftest         — exercise built-in SHA-256 against NIST vectors");
    println("  hash <string>    — print SHA-256 of argv string");
    println("  version          — print version + exit");
    println("  help             — this message");
    println("");
    println("Deferred to follow-on slices: install, fetch, verify, search,");
    println("repo. Today's host-side `duet-pkg` (tools/pkg/) remains the");
    println("authoritative implementation for those.");
    return 0;
}

static int CmdHash(int argc, char** argv)
{
    if (argc < 3)
    {
        println("duet-pkg hash: USAGE: duet-pkg hash <string>");
        return 2;
    }
    const char* s = argv[2];
    u8 d[SHA256_DIGEST_BYTES];
    Sha256OneShot(s, StrLenLocal(s), d);
    puts_str("[duet-pkg] sha256=\"");
    PrintHex32(d);
    puts_str("\" input=\"");
    puts_str(s);
    println("\"");
    return 0;
}

/* NIST FIPS 180-2 test vectors. */
static const struct
{
    const char* input;
    size_t input_len;
    u8 expected[SHA256_DIGEST_BYTES];
} kSha256Vectors[] = {
    {
        /* "abc" */
        .input = "abc",
        .input_len = 3,
        .expected = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                     0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad},
    },
    {
        /* empty string */
        .input = "",
        .input_len = 0,
        .expected = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
                     0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55},
    },
    {
        /* "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" — 448 bits */
        .input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        .input_len = 56,
        .expected = {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                     0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1},
    },
};

static int CmdSelftest(void)
{
    println("[duet-pkg-selftest] starting");
    int failures = 0;
    const u32 n_vectors = (u32)(sizeof(kSha256Vectors) / sizeof(kSha256Vectors[0]));
    for (u32 i = 0; i < n_vectors; ++i)
    {
        u8 got[SHA256_DIGEST_BYTES];
        Sha256OneShot(kSha256Vectors[i].input, kSha256Vectors[i].input_len, got);
        if (!DigestEqual(got, kSha256Vectors[i].expected))
        {
            puts_str("[duet-pkg-selftest] sha256 vector ");
            print_int((long)i);
            puts_str(" FAILED: got=");
            PrintHex32(got);
            println("");
            ++failures;
        }
    }
    /* Streaming-update equivalence: hashing "abc" in one shot vs.
     * three single-byte updates must produce identical digests.
     * This catches buffer-state bugs that one-shot tests miss. */
    {
        u8 oneshot[SHA256_DIGEST_BYTES];
        u8 streamed[SHA256_DIGEST_BYTES];
        Sha256OneShot("abc", 3, oneshot);
        Sha256Ctx c;
        Sha256Init(&c);
        Sha256Update(&c, "a", 1);
        Sha256Update(&c, "b", 1);
        Sha256Update(&c, "c", 1);
        Sha256Final(&c, streamed);
        if (!DigestEqual(oneshot, streamed))
        {
            println("[duet-pkg-selftest] streaming-update parity FAILED");
            ++failures;
        }
    }
    if (failures == 0)
    {
        println("[duet-pkg-selftest] PASS (sha256 vectors + streaming parity)");
        return 0;
    }
    puts_str("[duet-pkg-selftest] ");
    print_int((long)failures);
    println(" failure(s) — see above");
    return 1;
}

/* ----------------------------------------------------------------
 * Entry point.
 * ---------------------------------------------------------------- */

int main(int argc, char** argv)
{
    /* No argv means a smoke-style "just spawn me and exit" boot
     * test. Run the selftest so the boot log carries a PASS line
     * — that's the live signal the on-target binary actually
     * functions, not just that the spawn worked. */
    if (argc < 2)
    {
        println("[duet-pkg] no subcommand — running selftest");
        return CmdSelftest();
    }
    const char* sub = argv[1];
    if (StrEqLocal(sub, "selftest"))
        return CmdSelftest();
    if (StrEqLocal(sub, "version") || StrEqLocal(sub, "--version") || StrEqLocal(sub, "-V"))
        return CmdVersion();
    if (StrEqLocal(sub, "help") || StrEqLocal(sub, "--help") || StrEqLocal(sub, "-h"))
        return CmdHelp();
    if (StrEqLocal(sub, "hash"))
        return CmdHash(argc, argv);
    puts_str("[duet-pkg] unknown subcommand: ");
    println(sub);
    return CmdHelp();
}
