// test_kernel32_nls.cpp — hosted unit test for the kernel32.dll NLS
// number-formatting core.
//
// Covers: userland/libs/kernel32/kernel32_nls_format.h
//   (num_format_core_a, used by GetNumberFormatA/W + GetCurrencyFormatA)
//
// Expected outputs are pinned to the Win32 GetNumberFormat contract
// (learn.microsoft.com/.../nf-winnls-getnumberformatw): the fractional
// part is ROUNDED half-away-from-zero to NumDigits with carry
// propagating into the integer part, and Grouping uses the NUMBERFMT
// digit-stack encoding (3 => repeating 3; 32 => 2 then repeating 3; a
// trailing 0 digit stops repetition).

#include "host_test_helper.h"

#include "../../userland/libs/kernel32/kernel32_nls_format.h"

using namespace duetos_host_test;

namespace
{

// Convenience: format `num` with the given fields, return into a static
// buffer so EXPECT_STREQ can read it.
const char* fmt(const char* num, unsigned int numDigits, unsigned int leadingZero, unsigned int grouping,
                unsigned int negOrder)
{
    static char out[128];
    DUETOS_NUMBERFMT_A nf;
    nf.NumDigits = numDigits;
    nf.LeadingZero = leadingZero;
    nf.Grouping = grouping;
    nf.lpDecimalSep = ".";
    nf.lpThousandSep = ",";
    nf.NegativeOrder = negOrder;
    num_format_core_a(num, &nf, out, (int)sizeof(out));
    return out;
}

} // namespace

int main()
{
    // --- Plain integer, no grouping -------------------------------
    EXPECT_STREQ(fmt("1234", 0, 1, 0, 1), "1234");
    EXPECT_STREQ(fmt("0", 0, 1, 0, 1), "0");

    // --- Grouping = 3 (en-US default) -----------------------------
    EXPECT_STREQ(fmt("123", 0, 1, 3, 1), "123");
    EXPECT_STREQ(fmt("1234", 0, 1, 3, 1), "1,234");
    EXPECT_STREQ(fmt("1234567", 0, 1, 3, 1), "1,234,567");
    EXPECT_STREQ(fmt("123456789", 0, 1, 3, 1), "123,456,789");

    // --- Rounding to NumDigits (the truncation bug) ---------------
    // 12345.6789 @ 2dp rounds 0.6789 -> 0.68.
    EXPECT_STREQ(fmt("12345.6789", 2, 1, 3, 1), "12,345.68");
    // Cut digit exactly 5 rounds away from zero.
    EXPECT_STREQ(fmt("2.345", 2, 1, 0, 1), "2.35");
    // Pad shorter fraction out to NumDigits.
    EXPECT_STREQ(fmt("12.5", 2, 1, 0, 1), "12.50");
    // Round with carry rippling through the fraction.
    EXPECT_STREQ(fmt("9.999", 2, 1, 0, 1), "10.00");
    // Carry that rolls the integer part across a grouping boundary.
    EXPECT_STREQ(fmt("999.999", 2, 1, 3, 1), "1,000.00");
    // Rounding with NumDigits == 0 carries into the integer and emits
    // no decimal separator.
    EXPECT_STREQ(fmt("1234.9", 0, 1, 3, 1), "1,235");
    EXPECT_STREQ(fmt("0.5", 0, 1, 0, 1), "1");

    // --- LeadingZero ----------------------------------------------
    EXPECT_STREQ(fmt("0.5", 1, 0, 0, 1), ".5");
    EXPECT_STREQ(fmt("0.5", 1, 1, 0, 1), "0.5");

    // --- NegativeOrder 0..4 ---------------------------------------
    EXPECT_STREQ(fmt("-1234.5", 2, 1, 3, 0), "(1,234.50)");
    EXPECT_STREQ(fmt("-1234.5", 2, 1, 3, 1), "-1,234.50");
    EXPECT_STREQ(fmt("-1234.5", 2, 1, 3, 2), "- 1,234.50");
    EXPECT_STREQ(fmt("-1234.5", 2, 1, 3, 3), "1,234.50-");
    EXPECT_STREQ(fmt("-1234.5", 2, 1, 3, 4), "1,234.50 -");

    // --- Digit-stack Grouping (the % 100 bug) ---------------------
    // 3 => repeating groups of three.
    EXPECT_STREQ(fmt("1234567", 0, 1, 3, 1), "1,234,567");
    // 32 => least-significant group of 2, then repeating groups of 3
    // (South-Asian lakh grouping).
    EXPECT_STREQ(fmt("123456789", 0, 1, 32, 1), "12,34,56,789");
    EXPECT_STREQ(fmt("1234567", 0, 1, 32, 1), "12,34,567");
    // 30 => one group of 3, then STOP (trailing 0 terminates repeat).
    EXPECT_STREQ(fmt("1234567", 0, 1, 30, 1), "1234,567");

    // --- Currency (GetCurrencyFormatA core) -----------------------
    {
        DUETOS_NUMBERFMT_A cf;
        cf.NumDigits = 2;
        cf.LeadingZero = 1;
        cf.Grouping = 3;
        cf.lpDecimalSep = ".";
        cf.lpThousandSep = ",";
        cf.NegativeOrder = 1;
        char cb[128];
        currency_format_core_a("1234.5", &cf, "$", cb, (int)sizeof(cb));
        EXPECT_STREQ(cb, "$1,234.50");
        currency_format_core_a("-1234.5", &cf, "$", cb, (int)sizeof(cb));
        EXPECT_STREQ(cb, "($1,234.50)");
        currency_format_core_a("0", &cf, "$", cb, (int)sizeof(cb));
        EXPECT_STREQ(cb, "$0.00");
        // Currency rounds through the same core as numbers.
        currency_format_core_a("9.999", &cf, "$", cb, (int)sizeof(cb));
        EXPECT_STREQ(cb, "$10.00");
    }

    // --- GetLocaleInfo LOCALE_RETURN_NUMBER lookup ----------------
    {
        unsigned int v = 0xFFFFFFFFu;
        EXPECT_EQ(nls_locale_number(0x0011u, &v), 1); // LOCALE_IDIGITS
        EXPECT_EQ(v, 2u);
        EXPECT_EQ(nls_locale_number(0x0001u, &v), 1); // LOCALE_ILANGUAGE
        EXPECT_EQ(v, 0x0409u);
        EXPECT_EQ(nls_locale_number(0x1010u, &v), 1); // LOCALE_INEGNUMBER
        EXPECT_EQ(v, 1u);
        EXPECT_EQ(nls_locale_number(0x0020u, &v), 0); // LOCALE_SLONGDATE (string, not numeric)
    }

    return finish_main("kernel32_nls");
}
