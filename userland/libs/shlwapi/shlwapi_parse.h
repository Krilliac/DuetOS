/*
 * userland/libs/shlwapi/shlwapi_parse.h
 *
 * Freestanding StrToIntEx parse core shared by shlwapi.c and the
 * hosted test tests/host/test_kernel32_nls.cpp (same pattern as
 * kernel32_nls_format.h: pure char-buffer logic, no syscalls, no CRT).
 *
 * Win32 contract (STIF_DEFAULT = 0, STIF_SUPPORT_HEX = 1): optional
 * leading whitespace, optional '+'/'-' (decimal only), then decimal
 * digits; with STIF_SUPPORT_HEX a leading "0x"/"0X" switches to
 * unsigned hex. Trailing junk is ignored once digits were seen, and a
 * bare "0x" parses as 0 (the '0' prefix already counts — Windows /
 * Wine parity). Returns 1 and stores the value, or 0 if no number was
 * parsed.
 */
#pragma once

#define DUETOS_STIF_SUPPORT_HEX 0x00000001u

static inline int str_to_int_ex_core_a(const char* s, unsigned int flags, int* out)
{
    if (s == 0 || out == 0)
        return 0;
    while (*s == ' ' || *s == '\t')
        ++s;
    if ((flags & DUETOS_STIF_SUPPORT_HEX) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        s += 2;
        unsigned int v = 0;
        for (;; ++s)
        {
            unsigned int d;
            if (*s >= '0' && *s <= '9')
                d = (unsigned int)(*s - '0');
            else if (*s >= 'a' && *s <= 'f')
                d = (unsigned int)(*s - 'a' + 10);
            else if (*s >= 'A' && *s <= 'F')
                d = (unsigned int)(*s - 'A' + 10);
            else
                break;
            v = v * 16u + d;
        }
        *out = (int)v;
        return 1;
    }
    int negative = 0;
    if (*s == '-')
    {
        negative = 1;
        ++s;
    }
    else if (*s == '+')
        ++s;
    unsigned int v = 0;
    int any = 0;
    while (*s >= '0' && *s <= '9')
    {
        v = v * 10u + (unsigned int)(*s - '0');
        any = 1;
        ++s;
    }
    if (!any)
        return 0;
    *out = negative ? -(int)v : (int)v;
    return 1;
}

static inline int str_to_int_ex_core_w(const unsigned short* s, unsigned int flags, int* out)
{
    if (s == 0 || out == 0)
        return 0;
    while (*s == ' ' || *s == '\t')
        ++s;
    if ((flags & DUETOS_STIF_SUPPORT_HEX) && s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        s += 2;
        unsigned int v = 0;
        for (;; ++s)
        {
            unsigned int d;
            if (*s >= '0' && *s <= '9')
                d = (unsigned int)(*s - '0');
            else if (*s >= 'a' && *s <= 'f')
                d = (unsigned int)(*s - 'a' + 10);
            else if (*s >= 'A' && *s <= 'F')
                d = (unsigned int)(*s - 'A' + 10);
            else
                break;
            v = v * 16u + d;
        }
        *out = (int)v;
        return 1;
    }
    int negative = 0;
    if (*s == '-')
    {
        negative = 1;
        ++s;
    }
    else if (*s == '+')
        ++s;
    unsigned int v = 0;
    int any = 0;
    while (*s >= '0' && *s <= '9')
    {
        v = v * 10u + (unsigned int)(*s - '0');
        any = 1;
        ++s;
    }
    if (!any)
        return 0;
    *out = negative ? -(int)v : (int)v;
    return 1;
}
