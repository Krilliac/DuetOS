// test_kernel32_nls.cpp — hosted unit test for the freestanding NLS /
// string-format cores shared by the userland Win32 DLLs.
//
// Covers:
//   userland/libs/kernel32/kernel32_nls_format.h
//     (num_format_core_a + currency_format_core_a, used by
//      GetNumberFormatA/W + GetCurrencyFormatA/W; nls_widen_expand,
//      the W-path wide-separator carrier; nls_sortkey_core, used by
//      LCMapStringW LCMAP_SORTKEY)
//   userland/libs/user32/user32_wsprintf_core.h
//     (duetos_wvsnprintf_a/_w, used by user32 wsprintfA/W and
//      shlwapi wnsprintfA/W)
//   userland/libs/shlwapi/shlwapi_parse.h
//     (str_to_int_ex_core_a/_w, used by shlwapi StrToIntExA/W)
//
// Expected outputs are pinned to the Win32 GetNumberFormat contract
// (learn.microsoft.com/.../nf-winnls-getnumberformatw): the fractional
// part is ROUNDED half-away-from-zero to NumDigits with carry
// propagating into the integer part, and Grouping uses the NUMBERFMT
// digit-stack encoding (3 => repeating 3; 32 => 2 then repeating 3; a
// trailing 0 digit stops repetition).

#include "host_test_helper.h"

#include "../../userland/libs/kernel32/kernel32_nls_format.h"
#include "../../userland/libs/shlwapi/shlwapi_parse.h"
#include "../../userland/libs/user32/user32_wsprintf_core.h"

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

// Convenience: format `num` as currency with en-US numeric defaults
// (2 digits, leading zero, group 3, "."/",") and the given order
// fields + symbol, return into a static buffer.
const char* cur(const char* num, unsigned int negOrder, unsigned int posOrder, const char* symbol)
{
    static char out[128];
    DUETOS_CURRENCYFMT_A cf;
    cf.NumDigits = 2;
    cf.LeadingZero = 1;
    cf.Grouping = 3;
    cf.lpDecimalSep = ".";
    cf.lpThousandSep = ",";
    cf.NegativeOrder = negOrder;
    cf.PositiveOrder = posOrder;
    cf.lpCurrencySymbol = symbol;
    currency_format_core_a(num, &cf, out, (int)sizeof(out));
    return out;
}

// Varargs shims so the bounded printf engines can be driven directly.
int tfmt_a(char* out, int cap, const char* fmt, ...)
{
    duetos_valist ap;
    __builtin_va_start(ap, fmt);
    int r = duetos_wvsnprintf_a(out, cap, fmt, ap);
    __builtin_va_end(ap);
    return r;
}

int tfmt_w(unsigned short* out, int cap, const unsigned short* fmt, ...)
{
    duetos_valist ap;
    __builtin_va_start(ap, fmt);
    int r = duetos_wvsnprintf_w(out, cap, fmt, ap);
    __builtin_va_end(ap);
    return r;
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

    // --- Currency (GetCurrencyFormatA/W core) ---------------------
    // en-US defaults: PositiveOrder 0 ($1.1), NegativeOrder 0 (($1.1)).
    EXPECT_STREQ(cur("1234.5", 0, 0, "$"), "$1,234.50");
    EXPECT_STREQ(cur("-1234.5", 0, 0, "$"), "($1,234.50)");
    EXPECT_STREQ(cur("0", 0, 0, "$"), "$0.00");
    // Currency rounds through the same core as numbers.
    EXPECT_STREQ(cur("9.999", 0, 0, "$"), "$10.00");
    // PositiveOrder 0..3 (LOCALE_ICURRENCY).
    EXPECT_STREQ(cur("1234.5", 0, 1, "$"), "1,234.50$");
    EXPECT_STREQ(cur("1234.5", 0, 2, "$"), "$ 1,234.50");
    EXPECT_STREQ(cur("1234.5", 0, 3, "$"), "1,234.50 $");
    // NegativeOrder 0..15 (LOCALE_INEGCURR) — spot-check the table.
    EXPECT_STREQ(cur("-1234.5", 1, 0, "$"), "-$1,234.50");
    EXPECT_STREQ(cur("-1234.5", 2, 0, "$"), "$-1,234.50");
    EXPECT_STREQ(cur("-1234.5", 3, 0, "$"), "$1,234.50-");
    EXPECT_STREQ(cur("-1234.5", 5, 0, "$"), "-1,234.50$");
    EXPECT_STREQ(cur("-1234.5", 8, 0, "$"), "-1,234.50 $");
    EXPECT_STREQ(cur("-1234.5", 14, 0, "$"), "($ 1,234.50)");
    EXPECT_STREQ(cur("-1234.5", 15, 0, "$"), "(1,234.50 $)");
    // Multi-char symbol.
    EXPECT_STREQ(cur("1234.5", 0, 3, "EUR"), "1,234.50 EUR");
    // Numeric fields are honoured too (NumDigits 0, no grouping).
    {
        DUETOS_CURRENCYFMT_A cf;
        cf.NumDigits = 0;
        cf.LeadingZero = 1;
        cf.Grouping = 0;
        cf.lpDecimalSep = ".";
        cf.lpThousandSep = ",";
        cf.NegativeOrder = 0;
        cf.PositiveOrder = 0;
        cf.lpCurrencySymbol = "$";
        char cb[128];
        currency_format_core_a("1234.9", &cf, cb, (int)sizeof(cb));
        EXPECT_STREQ(cb, "$1235");
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

    // --- Wide separator round-trip (nls_widen_expand) -------------
    // The W formatters run the narrow core with sentinel separators
    // and substitute the caller's wide strings while widening, so
    // non-ASCII NUMBERFMTW/CURRENCYFMTW separators survive intact.
    {
        const unsigned short wdec[] = {0x066B, 0};         // ARABIC DECIMAL SEPARATOR
        const unsigned short wtho[] = {0x2009, 0x2009, 0}; // two THIN SPACEs (multi-char)
        const unsigned short wsym[] = {0x20AC, 0};         // EURO SIGN
        const char narrow[] = {'1', DUETOS_NLS_SENT_THOUSAND, '2', '3', '4', DUETOS_NLS_SENT_DECIMAL, '5', '0', 0};
        unsigned short wide[32];
        int n = nls_widen_expand(narrow, wdec, wtho, wsym, wide, 32);
        EXPECT_EQ(n, 9); // thousands sentinel expanded to TWO wide chars
        EXPECT_EQ(wide[0], (unsigned short)'1');
        EXPECT_EQ(wide[1], (unsigned short)0x2009);
        EXPECT_EQ(wide[2], (unsigned short)0x2009);
        EXPECT_EQ(wide[6], (unsigned short)0x066B);
        EXPECT_EQ(wide[9], (unsigned short)0);
        const char symed[] = {DUETOS_NLS_SENT_SYMBOL, '9', 0};
        n = nls_widen_expand(symed, wdec, wtho, wsym, wide, 32);
        EXPECT_EQ(n, 2);
        EXPECT_EQ(wide[0], (unsigned short)0x20AC);
        EXPECT_EQ(wide[1], (unsigned short)'9');
    }

    // --- LCMAP_SORTKEY core ----------------------------------------
    {
        const unsigned short abc[] = {'a', 'B', 'c'};
        const unsigned short upr[] = {'A', 'B', 'C'};
        unsigned char key[8];
        unsigned char key2[8];
        EXPECT_EQ(nls_sortkey_core(abc, 3, (unsigned char*)0, 0), 4); // sizing call
        EXPECT_EQ(nls_sortkey_core(abc, 3, key, 8), 4);
        EXPECT_EQ(key[0], (unsigned char)'A'); // upcased ordinal weight
        EXPECT_EQ(key[2], (unsigned char)'C');
        EXPECT_EQ(key[3], (unsigned char)0); // 0x00 terminator, counted
        nls_sortkey_core(upr, 3, key2, 8);
        EXPECT_EQ(std::memcmp(key, key2, 4), 0);        // case-insensitive: equal keys
        EXPECT_EQ(nls_sortkey_core(abc, 3, key, 3), 0); // dest too small
    }

    // --- Bounded restricted printf (user32 core, shlwapi wnsprintf) --
    {
        char b[64];
        EXPECT_EQ(tfmt_a(b, 64, "%d items, %u%%, 0x%X", -5, 7u, 0xBEEFu), 20);
        EXPECT_STREQ(b, "-5 items, 7%, 0xBEEF");
        tfmt_a(b, 64, "[%04d|%4d|%x]", 42, 42, 255u);
        EXPECT_STREQ(b, "[0042|  42|ff]");
        tfmt_a(b, 64, "%5s/%c", "abc", 'Z');
        EXPECT_STREQ(b, "  abc/Z");
        tfmt_a(b, 64, "%s", (const char*)0);
        EXPECT_STREQ(b, "(null)");
        // Bounded: truncation NUL-terminates and returns negative.
        EXPECT_TRUE(tfmt_a(b, 4, "%d", 12345) < 0);
        EXPECT_STREQ(b, "123");
        // Exact fit is not truncation.
        EXPECT_EQ(tfmt_a(b, 6, "hello"), 5);
        EXPECT_STREQ(b, "hello");
        // Trailing lone '%' must not run past the format string.
        EXPECT_EQ(tfmt_a(b, 8, "100%"), 4);
        EXPECT_STREQ(b, "100%");
        // Wide engine: same conversions, wide output.
        const unsigned short wfmt[] = {'%', 'd', '/', '%', 's', 0};
        const unsigned short warg[] = {'o', 'k', 0};
        unsigned short wb[16];
        EXPECT_EQ(tfmt_w(wb, 16, wfmt, -3, warg), 5);
        EXPECT_EQ(wb[0], (unsigned short)'-');
        EXPECT_EQ(wb[1], (unsigned short)'3');
        EXPECT_EQ(wb[3], (unsigned short)'o');
        EXPECT_EQ(wb[5], (unsigned short)0);
        EXPECT_TRUE(tfmt_w(wb, 3, wfmt, -3, warg) < 0); // bounded W
    }

    // --- StrToIntEx parse core --------------------------------------
    {
        int v = 0;
        EXPECT_EQ(str_to_int_ex_core_a("42", 0, &v), 1);
        EXPECT_EQ(v, 42);
        EXPECT_EQ(str_to_int_ex_core_a("  -17", 0, &v), 1);
        EXPECT_EQ(v, -17);
        EXPECT_EQ(str_to_int_ex_core_a("+9", 0, &v), 1);
        EXPECT_EQ(v, 9);
        EXPECT_EQ(str_to_int_ex_core_a("0x1A", DUETOS_STIF_SUPPORT_HEX, &v), 1);
        EXPECT_EQ(v, 26);
        EXPECT_EQ(str_to_int_ex_core_a("0xff", DUETOS_STIF_SUPPORT_HEX, &v), 1);
        EXPECT_EQ(v, 255);
        // Without the hex flag, "0x1A" parses the leading decimal 0.
        EXPECT_EQ(str_to_int_ex_core_a("0x1A", 0, &v), 1);
        EXPECT_EQ(v, 0);
        // Trailing junk is ignored once digits were seen.
        EXPECT_EQ(str_to_int_ex_core_a("12abc", 0, &v), 1);
        EXPECT_EQ(v, 12);
        EXPECT_EQ(str_to_int_ex_core_a("abc", 0, &v), 0);
        EXPECT_EQ(str_to_int_ex_core_a("", 0, &v), 0);
        const unsigned short whex[] = {'0', 'x', '7', 'F', 0};
        const unsigned short wneg[] = {'-', '4', 0};
        EXPECT_EQ(str_to_int_ex_core_w(whex, DUETOS_STIF_SUPPORT_HEX, &v), 1);
        EXPECT_EQ(v, 127);
        EXPECT_EQ(str_to_int_ex_core_w(wneg, 0, &v), 1);
        EXPECT_EQ(v, -4);
    }

    return finish_main("kernel32_nls");
}
