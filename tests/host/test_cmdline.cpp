// test_cmdline.cpp — hosted unit test for the kernel command-line
// token parser.
//
// Covers kernel/util/cmdline.h:
//   CmdlineGet — whitespace-delimited `key=value` lookup, including the
//                prefix-collision case that a naive strncmp gets wrong
//   HexDecode  — operator-supplied digest decoding, and its refusal to
//                accept malformed input
//
// Both are consumed by kernel/diag/stress_driver.cpp (stress= tokens)
// and kernel/drivers/tpm/tpm_measure.cpp (tpm.baseline=). The TPM
// tripwire is the reason the strict-rejection behaviour matters: a
// baseline that silently decoded wrong would report "boot chain
// changed" forever, training the operator to ignore the one signal the
// feature exists to produce.

#include "host_test_helper.h"

#include "util/cmdline.h"

using namespace duetos_host_test;

using duetos::u32;
using duetos::u8;
using duetos::core::CmdlineGet;
using duetos::core::HexDecode;

int main()
{
    char value[64] = {};

    // --- basic lookup ------------------------------------------------
    EXPECT_TRUE(CmdlineGet("stress=mem secs=10", "stress", value, sizeof(value)));
    EXPECT_STREQ(value, "mem");

    EXPECT_TRUE(CmdlineGet("stress=mem secs=10", "secs", value, sizeof(value)));
    EXPECT_STREQ(value, "10");

    // Leading and repeated whitespace, and tabs, are all separators.
    EXPECT_TRUE(CmdlineGet("   \t loglevel=debug  \t tpm.baseline=ab", "tpm.baseline", value, sizeof(value)));
    EXPECT_STREQ(value, "ab");

    // --- misses ------------------------------------------------------
    EXPECT_FALSE(CmdlineGet("stress=mem", "missing", value, sizeof(value)));
    EXPECT_FALSE(CmdlineGet(nullptr, "stress", value, sizeof(value)));
    EXPECT_FALSE(CmdlineGet("stress=mem", nullptr, value, sizeof(value)));
    EXPECT_FALSE(CmdlineGet("stress=mem", "stress", nullptr, sizeof(value)));
    EXPECT_FALSE(CmdlineGet("stress=mem", "stress", value, 0));

    // A bare flag with no '=' is not a key=value token.
    EXPECT_FALSE(CmdlineGet("quiet", "quiet", value, sizeof(value)));

    // --- prefix collisions -------------------------------------------
    // "stress" must not match the token "stress-secs", and vice versa.
    // Getting this wrong silently hands a caller the wrong value.
    EXPECT_FALSE(CmdlineGet("stress-secs=30", "stress", value, sizeof(value)));
    EXPECT_TRUE(CmdlineGet("stress-secs=30", "stress-secs", value, sizeof(value)));
    EXPECT_STREQ(value, "30");

    // A longer key than the token present must not match either.
    EXPECT_FALSE(CmdlineGet("tpm=1", "tpm.baseline", value, sizeof(value)));

    // --- truncation --------------------------------------------------
    // A value longer than the buffer is truncated but stays
    // NUL-terminated rather than overflowing.
    {
        char small[4] = {};
        EXPECT_TRUE(CmdlineGet("key=abcdefgh", "key", small, sizeof(small)));
        EXPECT_STREQ(small, "abc");
    }

    // --- empty value -------------------------------------------------
    EXPECT_TRUE(CmdlineGet("key= next=1", "key", value, sizeof(value)));
    EXPECT_STREQ(value, "");

    // --- HexDecode ---------------------------------------------------
    u8 out[32] = {};
    EXPECT_TRUE(HexDecode("00ff10AB", 8, out, sizeof(out)));
    EXPECT_EQ(out[0], 0x00);
    EXPECT_EQ(out[1], 0xFF);
    EXPECT_EQ(out[2], 0x10);
    EXPECT_EQ(out[3], 0xAB);

    // A full 64-character SHA-256 digest is the real use.
    {
        const char* full = "0123456789abcdef0123456789abcdef"
                           "0123456789ABCDEF0123456789ABCDEF";
        EXPECT_TRUE(HexDecode(full, 64, out, sizeof(out)));
        EXPECT_EQ(out[0], 0x01);
        EXPECT_EQ(out[31], 0xEF);
    }

    // Rejections: non-hex, odd length, oversize, nulls.
    EXPECT_FALSE(HexDecode("00fg", 4, out, sizeof(out)));
    EXPECT_FALSE(HexDecode("0 ff", 4, out, sizeof(out)));
    EXPECT_FALSE(HexDecode("abc", 3, out, sizeof(out)));
    EXPECT_FALSE(HexDecode("00112233", 8, out, 2));
    EXPECT_FALSE(HexDecode(nullptr, 4, out, sizeof(out)));
    EXPECT_FALSE(HexDecode("0011", 4, nullptr, sizeof(out)));

    // A rejected decode must leave the destination untouched, so a
    // caller that ignores the return value cannot end up comparing
    // against half-decoded bytes.
    out[0] = 0x5A;
    EXPECT_FALSE(HexDecode("zz", 2, out, sizeof(out)));
    EXPECT_EQ(out[0], 0x5A);

    return finish_main("cmdline");
}
