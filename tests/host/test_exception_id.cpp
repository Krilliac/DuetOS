// Hosted tests for security-exception identity + boot-token parsing.
//
// This is the logic that decides WHICH image an operator vouched
// for. Getting it wrong in the lenient direction grants an exception
// nobody asked for; getting it wrong in the strict direction denies
// an image the operator explicitly pre-authorised. Both are cheaper
// to catch here than by booting a kernel.

#include "host_test_helper.h"
#include "security/exception_id.h"

using duetos::u32;
using duetos::u8;
using duetos::security::CmdlineCountKey;
using duetos::security::CmdlineFindNthValue;
using duetos::security::CsvField;
using duetos::security::CsvFieldCount;
using duetos::security::DigestEqual;
using duetos::security::FormatHexDigest;
using duetos::security::kImageDigestBytes;
using duetos::security::kImageDigestHexChars;
using duetos::security::ParseHexDigest;

namespace
{

const char* const kDigestA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const char* const kDigestB = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

void TestDigestRoundTrip()
{
    u8 d[kImageDigestBytes] = {};
    EXPECT_TRUE(ParseHexDigest(kDigestA, 64, d));
    EXPECT_EQ(d[0], 0x01u);
    EXPECT_EQ(d[1], 0x23u);
    EXPECT_EQ(d[31], 0xefu);

    char hex[kImageDigestHexChars + 1] = {};
    FormatHexDigest(d, hex);
    hex[kImageDigestHexChars] = '\0';
    EXPECT_STREQ(hex, kDigestA);

    // Uppercase input must parse to the same digest — an operator
    // pasting a digest from a tool that emits uppercase should not
    // silently get a non-match.
    const char* upper = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    u8 d2[kImageDigestBytes] = {};
    EXPECT_TRUE(ParseHexDigest(upper, 64, d2));
    EXPECT_TRUE(DigestEqual(d, d2));

    u8 d3[kImageDigestBytes] = {};
    EXPECT_TRUE(ParseHexDigest(kDigestB, 64, d3));
    EXPECT_TRUE(!DigestEqual(d, d3));
}

void TestDigestRejectsMalformed()
{
    u8 d[kImageDigestBytes] = {};

    // Too short — a truncated paste must never be accepted, because
    // a shorter prefix would name a different image than the one the
    // operator inspected.
    EXPECT_TRUE(!ParseHexDigest(kDigestA, 63, d));
    EXPECT_TRUE(!ParseHexDigest("", 0, d));
    EXPECT_TRUE(!ParseHexDigest(nullptr, 64, d));

    // Non-hex inside the run.
    const char* bad = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg";
    EXPECT_TRUE(!ParseHexDigest(bad, 64, d));

    // 65 hex characters: a typo, not a digest with a trailing byte.
    // Accepting the first 64 would vouch for an image the operator
    // never named.
    const char* toolong = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefa";
    EXPECT_TRUE(!ParseHexDigest(toolong, 65, d));

    // A non-hex terminator at position 64 IS the normal case
    // (newline in the store, comma in a cmdline list, NUL).
    const char* terminated = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    EXPECT_TRUE(ParseHexDigest(terminated, 65, d));
    const char* comma = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef,x";
    EXPECT_TRUE(ParseHexDigest(comma, 66, d));
}

void TestDigestFailureLeavesOutputUntouched()
{
    // A rejected parse must not have written a partial digest: the
    // caller's buffer is often a stack array it is about to compare
    // against the allowlist.
    u8 d[kImageDigestBytes];
    for (u32 i = 0; i < kImageDigestBytes; ++i)
        d[i] = 0xAA;
    const char* bad = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeZ";
    EXPECT_TRUE(!ParseHexDigest(bad, 64, d));
    for (u32 i = 0; i < kImageDigestBytes; ++i)
        EXPECT_EQ(d[i], 0xAAu);
}

void TestCmdlineScan()
{
    const char* cl = "root=/dev/nvme0 guard-allow=aaa smoke=ring3 guard-allow=bbb,ccc quiet";
    EXPECT_EQ(CmdlineCountKey(cl, "guard-allow"), 2u);

    const char* v = nullptr;
    u32 n = 0;
    EXPECT_TRUE(CmdlineFindNthValue(cl, "guard-allow", 0, &v, &n));
    EXPECT_EQ(n, 3u);
    EXPECT_TRUE(v[0] == 'a' && v[1] == 'a' && v[2] == 'a');

    EXPECT_TRUE(CmdlineFindNthValue(cl, "guard-allow", 1, &v, &n));
    EXPECT_EQ(n, 7u);
    EXPECT_TRUE(v[0] == 'b' && v[4] == 'c');

    EXPECT_TRUE(!CmdlineFindNthValue(cl, "guard-allow", 2, &v, &n));

    // Absent key, null cmdline.
    EXPECT_TRUE(!CmdlineFindNthValue(cl, "fw-allow", 0, &v, &n));
    EXPECT_TRUE(!CmdlineFindNthValue(nullptr, "guard-allow", 0, &v, &n));
    EXPECT_EQ(CmdlineCountKey(nullptr, "guard-allow"), 0u);

    // A key must match the WHOLE token before '='. Otherwise
    // `guard-allow-nothing=x` or a suffix like `xguard-allow=` would
    // be read as a real seed.
    const char* tricky = "xguard-allow=zzz guard-allow-extra=yyy";
    EXPECT_EQ(CmdlineCountKey(tricky, "guard-allow"), 0u);

    // Empty value is found, with length 0 — callers warn rather than
    // treating `guard-allow=` as absent.
    const char* empty = "a=1 guard-allow= b=2";
    EXPECT_TRUE(CmdlineFindNthValue(empty, "guard-allow", 0, &v, &n));
    EXPECT_EQ(n, 0u);

    // Tab and newline separate tokens too.
    const char* ws = "a=1\tguard-allow=ddd\nb=2";
    EXPECT_TRUE(CmdlineFindNthValue(ws, "guard-allow", 0, &v, &n));
    EXPECT_EQ(n, 3u);

    // Value at end of string, no trailing separator.
    const char* tail = "quiet guard-allow=eee";
    EXPECT_TRUE(CmdlineFindNthValue(tail, "guard-allow", 0, &v, &n));
    EXPECT_EQ(n, 3u);
}

void TestCsv()
{
    const char* s = "aa,bb,cc";
    EXPECT_EQ(CsvFieldCount(s, 8), 3u);

    const char* f = nullptr;
    u32 n = 0;
    EXPECT_TRUE(CsvField(s, 8, 0, &f, &n));
    EXPECT_EQ(n, 2u);
    EXPECT_TRUE(f[0] == 'a');
    EXPECT_TRUE(CsvField(s, 8, 2, &f, &n));
    EXPECT_EQ(n, 2u);
    EXPECT_TRUE(f[0] == 'c');
    EXPECT_TRUE(!CsvField(s, 8, 3, &f, &n));

    // Single field, no commas.
    EXPECT_EQ(CsvFieldCount("solo", 4), 1u);
    // Empty input has no fields.
    EXPECT_EQ(CsvFieldCount("", 0), 0u);
    EXPECT_EQ(CsvFieldCount(nullptr, 5), 0u);
    // Empty fields are preserved so the caller can reject them.
    EXPECT_EQ(CsvFieldCount("a,,b", 4), 3u);
    EXPECT_TRUE(CsvField("a,,b", 4, 1, &f, &n));
    EXPECT_EQ(n, 0u);
}

void TestEndToEndSeedParse()
{
    // The exact shape GuardSeedExceptionsFromCmdline walks: two
    // tokens, one carrying two digests, one of them malformed.
    char cl[512];
    std::snprintf(cl, sizeof(cl), "quiet guard-allow=%s,notadigest guard-allow=%s smoke=none", kDigestA, kDigestB);

    u32 accepted = 0;
    u32 rejected = 0;
    const char* v = nullptr;
    u32 vlen = 0;
    for (u32 tok = 0; CmdlineFindNthValue(cl, "guard-allow", tok, &v, &vlen); ++tok)
    {
        const u32 fields = CsvFieldCount(v, vlen);
        for (u32 i = 0; i < fields; ++i)
        {
            const char* fld = nullptr;
            u32 flen = 0;
            EXPECT_TRUE(CsvField(v, vlen, i, &fld, &flen));
            u8 d[kImageDigestBytes];
            if (ParseHexDigest(fld, flen, d))
                ++accepted;
            else
                ++rejected;
        }
    }
    EXPECT_EQ(accepted, 2u);
    EXPECT_EQ(rejected, 1u);
}

} // namespace

int main()
{
    TestDigestRoundTrip();
    TestDigestRejectsMalformed();
    TestDigestFailureLeavesOutputUntouched();
    TestCmdlineScan();
    TestCsv();
    TestEndToEndSeedParse();
    return duetos_host_test::finish_main("exception_id");
}
