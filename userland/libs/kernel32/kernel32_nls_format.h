/*
 * userland/libs/kernel32/kernel32_nls_format.h
 *
 * Freestanding NLS number / currency formatting core shared by the
 * kernel32.dll translation unit (kernel32_io.c) and the fast hosted
 * regression test (tests/host/test_kernel32_nls.cpp).
 *
 * This header is deliberately self-contained: no __declspec, no
 * syscalls, no CRT — only plain char-buffer transforms. That is what
 * lets the same code run both under the freestanding
 * clang --target=x86_64-pc-windows-msvc DLL build AND under the host
 * compiler in tests/host, so GetNumberFormat / GetCurrencyFormat
 * behaviour is pinned by a millisecond unit test instead of only a
 * full QEMU boot.
 *
 * Semantics follow the Win32 NUMBERFMT contract
 * (learn.microsoft.com/.../nf-winnls-getnumberformatw):
 *   - the fractional part is ROUNDED (half-up) to NumDigits, with carry
 *     propagating into the integer part;
 *   - Grouping uses the NUMBERFMT digit-stack encoding (3 => repeating
 *     groups of 3; 32 => least-significant group of 2 then repeating 3;
 *     a trailing 0 digit terminates repetition).
 */
#pragma once

/* Win32 NUMBERFMTA layout (narrow separator strings). */
typedef struct
{
    unsigned int NumDigits;
    unsigned int LeadingZero;
    unsigned int Grouping;
    const char* lpDecimalSep;
    const char* lpThousandSep;
    unsigned int NegativeOrder;
} DUETOS_NUMBERFMT_A;

/* Core number formatter: formats the string `num` according to `nf`
 * into out[0..out_cap-1] (NUL-terminated). Returns the number of
 * characters written (excluding NUL). See header comment for the
 * rounding + grouping contract.
 */
static inline int num_format_core_a(const char* num, const DUETOS_NUMBERFMT_A* nf, char* out, int out_cap)
{
    if (out_cap <= 1)
        return 0;

    /* Default locale separators if struct fields are NULL. */
    const char* dec_sep = (nf->lpDecimalSep && nf->lpDecimalSep[0]) ? nf->lpDecimalSep : ".";
    const char* tho_sep = (nf->lpThousandSep) ? nf->lpThousandSep : ",";

    /* 1. Parse: skip leading whitespace, capture sign. */
    const char* p = num;
    while (*p == ' ' || *p == '\t')
        ++p;
    int negative = 0;
    if (*p == '-')
    {
        negative = 1;
        ++p;
    }
    else if (*p == '+')
        ++p;

    /* Collect integer digits (before any '.'). */
    char int_digits[64];
    int int_len = 0;
    while (*p >= '0' && *p <= '9' && int_len < 63)
        int_digits[int_len++] = *p++;

    /* Collect fractional digits (after '.'). */
    char frac_digits[32];
    int frac_len = 0;
    if (*p == '.' || *p == ',') /* accept either separator in input */
    {
        ++p;
        while (*p >= '0' && *p <= '9' && frac_len < 31)
            frac_digits[frac_len++] = *p++;
    }

    /* 2. Build the significant integer digits (strip leading zeros, keep
     * at least one) into a MUTABLE buffer so rounding can carry into it. */
    char ipart[68];
    int ilen = 0;
    {
        int fnz = 0;
        while (fnz < int_len - 1 && int_digits[fnz] == '0')
            ++fnz;
        for (int i = fnz; i < int_len && ilen < 66; ++i)
            ipart[ilen++] = int_digits[i];
        if (ilen == 0) /* input had no integer digit (".5") -> value 0.x */
            ipart[ilen++] = '0';
    }

    /* 3. Round the fraction to NumDigits, half-away-from-zero, with the
     * carry rippling through the kept fraction and into the integer
     * part. (Win32 GetNumberFormat rounds; it does NOT truncate.) */
    unsigned int ndig = nf->NumDigits;
    if (ndig > 34u)
        ndig = 34u; /* Win32 caps at 9; clamp defensively */
    char frac_buf[36];
    for (unsigned int i = 0; i < ndig; ++i)
        frac_buf[i] = (i < (unsigned int)frac_len) ? frac_digits[i] : '0';
    frac_buf[ndig] = 0;

    int carry = ((unsigned int)frac_len > ndig && frac_digits[ndig] >= '5') ? 1 : 0;
    if (carry)
    {
        int i = (int)ndig - 1;
        while (i >= 0)
        {
            if (frac_buf[i] == '9')
            {
                frac_buf[i] = '0';
                --i;
            }
            else
            {
                ++frac_buf[i];
                carry = 0;
                break;
            }
        }
        if (carry) /* fraction overflowed -> add 1 to the integer part */
        {
            int j = ilen - 1;
            while (j >= 0)
            {
                if (ipart[j] == '9')
                {
                    ipart[j] = '0';
                    --j;
                }
                else
                {
                    ++ipart[j];
                    carry = 0;
                    break;
                }
            }
            if (carry && ilen < 66) /* all nines: 999 -> 1000, shift right */
            {
                for (int k = ilen; k > 0; --k)
                    ipart[k] = ipart[k - 1];
                ipart[0] = '1';
                ++ilen;
            }
        }
    }

    /* 4. Build the grouped integer string into int_buf.
     *
     * NUMBERFMT.Grouping is the digit-stack encoding: its decimal digits,
     * read left-to-right, are group widths starting at the group nearest
     * the decimal point and moving left; the LAST digit repeats, and a
     * width of 0 stops grouping. So 3 => repeating 3 (1,234,567); 32 =>
     * rightmost group 3 then repeating 2 (12,34,567); 30 => one group of
     * 3 then stop (1234,567). */
    char int_buf[128];
    int ib = 0;
    int suppress_zero = (ilen == 1 && ipart[0] == '0' && ndig > 0 && nf->LeadingZero == 0);
    if (suppress_zero)
    {
        int_buf[0] = 0; /* value < 1 with LeadingZero off -> ".5" form */
    }
    else
    {
        /* Decode the group widths (gw[0] = group nearest decimal). */
        int gw[8];
        int gn = 0;
        {
            unsigned int gv = nf->Grouping;
            char tmp[12];
            int tn = 0;
            if (gv == 0)
                tn = 0; /* no grouping */
            else
                while (gv > 0 && tn < 11)
                {
                    tmp[tn++] = (char)('0' + (gv % 10u));
                    gv /= 10u;
                }
            /* tmp is least-significant-decimal-digit first; the integer's
             * written order (MS digit first) is the group order from the
             * decimal point outward, so reverse tmp back into gw. */
            for (int i = tn - 1; i >= 0 && gn < 8; --i)
                gw[gn++] = tmp[i] - '0';
        }

        int sep_len = 0;
        while (tho_sep[sep_len])
            ++sep_len;

        /* Walk the integer digits from the right, emitting reversed. */
        char rev[140];
        int rn = 0;
        int gi = 0;                     /* which group (from right) */
        int cur = (gn > 0) ? gw[0] : 0; /* current group width, 0 => no grouping */
        int placed = 0;                 /* digits in current group */
        int stop = (gn == 0);           /* no grouping at all */
        for (int pos = ilen - 1; pos >= 0; --pos)
        {
            if (!stop && cur > 0 && placed == cur)
            {
                for (int si = sep_len - 1; si >= 0 && rn < 138; --si)
                    rev[rn++] = tho_sep[si];
                ++gi;
                int wi = (gi < gn) ? gi : gn - 1; /* last width repeats */
                cur = gw[wi];
                placed = 0;
                if (cur == 0) /* width 0 => stop grouping from here on */
                    stop = 1;
            }
            if (rn < 138)
                rev[rn++] = ipart[pos];
            ++placed;
        }
        for (int i = rn - 1; i >= 0 && ib < 127; --i)
            int_buf[ib++] = rev[i];
        int_buf[ib] = 0;
    }

    /* 5. Compose result with NegativeOrder.
     *   0: (1.1)      1: -1.1      2: - 1.1
     *   3: 1.1-       4: 1.1 -     (others treated as 1) */
    int pos = 0;
#define EMIT_STR(s)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        const char* _s = (s);                                                                                          \
        while (*_s && pos < out_cap - 1)                                                                               \
            out[pos++] = *_s++;                                                                                        \
    } while (0)
#define EMIT_CH(c)                                                                                                     \
    do                                                                                                                 \
    {                                                                                                                  \
        if (pos < out_cap - 1)                                                                                         \
            out[pos++] = (char)(c);                                                                                    \
    } while (0)

    if (negative)
    {
        switch (nf->NegativeOrder)
        {
        case 0: /* (1.1) */
            EMIT_CH('(');
            EMIT_STR(int_buf);
            if (nf->NumDigits > 0)
            {
                EMIT_STR(dec_sep);
                EMIT_STR(frac_buf);
            }
            EMIT_CH(')');
            break;
        case 2: /* - 1.1 */
            EMIT_CH('-');
            EMIT_CH(' ');
            EMIT_STR(int_buf);
            if (nf->NumDigits > 0)
            {
                EMIT_STR(dec_sep);
                EMIT_STR(frac_buf);
            }
            break;
        case 3: /* 1.1- */
            EMIT_STR(int_buf);
            if (nf->NumDigits > 0)
            {
                EMIT_STR(dec_sep);
                EMIT_STR(frac_buf);
            }
            EMIT_CH('-');
            break;
        case 4: /* 1.1 - */
            EMIT_STR(int_buf);
            if (nf->NumDigits > 0)
            {
                EMIT_STR(dec_sep);
                EMIT_STR(frac_buf);
            }
            EMIT_CH(' ');
            EMIT_CH('-');
            break;
        default: /* 1: -1.1 and catch-all */
            EMIT_CH('-');
            EMIT_STR(int_buf);
            if (nf->NumDigits > 0)
            {
                EMIT_STR(dec_sep);
                EMIT_STR(frac_buf);
            }
            break;
        }
    }
    else
    {
        EMIT_STR(int_buf);
        if (nf->NumDigits > 0)
        {
            EMIT_STR(dec_sep);
            EMIT_STR(frac_buf);
        }
    }

#undef EMIT_STR
#undef EMIT_CH

    out[pos] = 0;
    return pos;
}

/* Currency formatter: formats `num`'s magnitude through the number core
 * (so grouping + rounding match GetNumberFormat) and wraps it with the
 * currency `symbol`, applying the en-US default negative order
 * (parentheses — LOCALE_INEGCURR 0): "$1,234.50" / "($1,234.50)".
 * Returns chars written (excluding NUL). */
static inline int currency_format_core_a(const char* num, const DUETOS_NUMBERFMT_A* nf, const char* symbol, char* out,
                                         int out_cap)
{
    if (out_cap <= 1)
        return 0;

    const char* p = num;
    while (*p == ' ' || *p == '\t')
        ++p;
    int negative = 0;
    if (*p == '-')
    {
        negative = 1;
        ++p;
    }
    else if (*p == '+')
        ++p;

    char body[128];
    int blen = num_format_core_a(p, nf, body, (int)sizeof(body));

    int s = 0;
    if (negative && s < out_cap - 1)
        out[s++] = '(';
    for (int i = 0; symbol[i] && s < out_cap - 1; ++i)
        out[s++] = symbol[i];
    for (int i = 0; i < blen && s < out_cap - 1; ++i)
        out[s++] = body[i];
    if (negative && s < out_cap - 1)
        out[s++] = ')';
    out[s] = 0;
    return s;
}

/* GetLocaleInfo LOCALE_RETURN_NUMBER lookup: for the numeric LCTypes,
 * yields the binary DWORD value. Returns 1 if `lctype` (already masked
 * to its low 28 bits) is a known numeric type, 0 otherwise. */
static inline int nls_locale_number(unsigned int lctype, unsigned int* out)
{
    switch (lctype)
    {
    case 0x0001: /* LOCALE_ILANGUAGE  */
        *out = 0x0409;
        return 1;
    case 0x0005: /* LOCALE_ICOUNTRY   */
        *out = 1;
        return 1;
    case 0x0011: /* LOCALE_IDIGITS    */
        *out = 2;
        return 1;
    case 0x0012: /* LOCALE_ILZERO     */
        *out = 1;
        return 1;
    case 0x1010: /* LOCALE_INEGNUMBER */
        *out = 1;
        return 1;
    default:
        return 0;
    }
}
