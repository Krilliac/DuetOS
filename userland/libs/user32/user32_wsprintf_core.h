/*
 * userland/libs/user32/user32_wsprintf_core.h
 *
 * Freestanding restricted-printf engine shared by user32.dll
 * (wsprintfA/W, wvsprintfA/W — unbounded legacy contract) and
 * shlwapi.dll (wnsprintfA/W — bounded), and pinned by the hosted test
 * tests/host/test_kernel32_nls.cpp. One engine per character width so
 * the format logic is never duplicated across DLLs.
 *
 * Conversion set is the documented wsprintf subset: %d/%i %u %x %X %s
 * %c plus '%%', the '0' pad flag, a numeric field width, and the
 * 'l'/'h' length modifiers (ignored — args promote to 32-bit in v0).
 * Floats are unsupported, exactly as on Windows.
 *
 * `cap` is the output buffer size in characters INCLUDING the
 * terminating NUL. The engine always NUL-terminates (cap >= 1) and
 * returns the count written excluding the NUL, or -1 if the output was
 * truncated / the arguments were invalid (the wnsprintf contract;
 * user32 passes a huge cap so its unbounded contract is unchanged).
 */
#pragma once

typedef __builtin_va_list duetos_valist;

static inline int duetos_uint_to_dec(unsigned int v, char* out)
{
    char rev[16];
    int n = 0;
    if (v == 0)
        rev[n++] = '0';
    while (v)
    {
        rev[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    for (int i = 0; i < n; ++i)
        out[i] = rev[n - 1 - i];
    return n;
}

static inline int duetos_int_to_dec(int v, char* out)
{
    if (v < 0)
    {
        out[0] = '-';
        unsigned int mag = (unsigned int)(-(v + 1)) + 1u; /* INT_MIN-safe */
        return 1 + duetos_uint_to_dec(mag, out + 1);
    }
    return duetos_uint_to_dec((unsigned int)v, out);
}

static inline int duetos_uint_to_hex(unsigned int v, char* out, int upper)
{
    const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    char rev[16];
    int n = 0;
    if (v == 0)
        rev[n++] = '0';
    while (v)
    {
        rev[n++] = digits[v & 0xF];
        v >>= 4;
    }
    for (int i = 0; i < n; ++i)
        out[i] = rev[n - 1 - i];
    return n;
}

/* Bounded emit: drops the char and latches `trunc` once the buffer
 * (minus NUL space) is full. Relies on locals pos / cap / out / trunc
 * in both engine bodies below; #undef'd after the second engine. */
#define DUETOS_WSPF_PUT(ch)                                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        if (pos < cap - 1)                                                                                             \
            out[pos++] = (ch);                                                                                         \
        else                                                                                                           \
            trunc = 1;                                                                                                 \
    } while (0)

static inline int duetos_wvsnprintf_a(char* out, int cap, const char* fmt, duetos_valist ap)
{
    if (out == 0 || fmt == 0 || cap < 1)
        return -1;
    int pos = 0;
    int trunc = 0;
    for (const char* p = fmt; *p; ++p)
    {
        if (*p != '%')
        {
            DUETOS_WSPF_PUT(*p);
            continue;
        }
        ++p;
        if (*p == 0) /* lone trailing '%' — emit it, don't run off the end */
        {
            DUETOS_WSPF_PUT('%');
            break;
        }
        if (*p == '%')
        {
            DUETOS_WSPF_PUT('%');
            continue;
        }
        int zero = 0, width = 0;
        if (*p == '0')
        {
            zero = 1;
            ++p;
        }
        while (*p >= '0' && *p <= '9')
        {
            width = width * 10 + (int)(*p - '0');
            ++p;
        }
        if (*p == 'l' || *p == 'h')
            ++p;
        char tmp[32];
        int n = 0;
        if (*p == 'd' || *p == 'i')
            n = duetos_int_to_dec(__builtin_va_arg(ap, int), tmp);
        else if (*p == 'u')
            n = duetos_uint_to_dec(__builtin_va_arg(ap, unsigned int), tmp);
        else if (*p == 'x')
            n = duetos_uint_to_hex(__builtin_va_arg(ap, unsigned int), tmp, 0);
        else if (*p == 'X')
            n = duetos_uint_to_hex(__builtin_va_arg(ap, unsigned int), tmp, 1);
        else if (*p == 'c')
        {
            tmp[0] = (char)__builtin_va_arg(ap, int);
            n = 1;
        }
        else if (*p == 's')
        {
            const char* s = __builtin_va_arg(ap, const char*);
            if (!s)
                s = "(null)";
            int sl = 0;
            while (s[sl])
                ++sl;
            for (int i = sl; i < width; ++i)
                DUETOS_WSPF_PUT(' ');
            for (int i = 0; i < sl; ++i)
                DUETOS_WSPF_PUT(s[i]);
            continue;
        }
        else
        {
            DUETOS_WSPF_PUT('%');
            DUETOS_WSPF_PUT(*p);
            continue;
        }
        for (int i = n; i < width; ++i)
            DUETOS_WSPF_PUT(zero ? '0' : ' ');
        for (int i = 0; i < n; ++i)
            DUETOS_WSPF_PUT(tmp[i]);
    }
    out[pos] = 0;
    return trunc ? -1 : pos;
}

static inline int duetos_wvsnprintf_w(unsigned short* out, int cap, const unsigned short* fmt, duetos_valist ap)
{
    if (out == 0 || fmt == 0 || cap < 1)
        return -1;
    int pos = 0;
    int trunc = 0;
    for (const unsigned short* p = fmt; *p; ++p)
    {
        if (*p != (unsigned short)'%')
        {
            DUETOS_WSPF_PUT(*p);
            continue;
        }
        ++p;
        if (*p == 0) /* lone trailing '%' — emit it, don't run off the end */
        {
            DUETOS_WSPF_PUT((unsigned short)'%');
            break;
        }
        if (*p == (unsigned short)'%')
        {
            DUETOS_WSPF_PUT((unsigned short)'%');
            continue;
        }
        int zero = 0, width = 0;
        if (*p == (unsigned short)'0')
        {
            zero = 1;
            ++p;
        }
        while (*p >= (unsigned short)'0' && *p <= (unsigned short)'9')
        {
            width = width * 10 + (int)(*p - (unsigned short)'0');
            ++p;
        }
        if (*p == (unsigned short)'l' || *p == (unsigned short)'h')
            ++p;
        char tmp[32];
        int n = 0;
        if (*p == (unsigned short)'d' || *p == (unsigned short)'i')
            n = duetos_int_to_dec(__builtin_va_arg(ap, int), tmp);
        else if (*p == (unsigned short)'u')
            n = duetos_uint_to_dec(__builtin_va_arg(ap, unsigned int), tmp);
        else if (*p == (unsigned short)'x')
            n = duetos_uint_to_hex(__builtin_va_arg(ap, unsigned int), tmp, 0);
        else if (*p == (unsigned short)'X')
            n = duetos_uint_to_hex(__builtin_va_arg(ap, unsigned int), tmp, 1);
        else if (*p == (unsigned short)'c')
        {
            tmp[0] = (char)__builtin_va_arg(ap, int);
            n = 1;
        }
        else if (*p == (unsigned short)'s')
        {
            const unsigned short* s = __builtin_va_arg(ap, const unsigned short*);
            int sl = 0;
            if (s)
                while (s[sl])
                    ++sl;
            for (int i = sl; i < width; ++i)
                DUETOS_WSPF_PUT((unsigned short)' ');
            for (int i = 0; i < sl; ++i)
                DUETOS_WSPF_PUT(s[i]);
            continue;
        }
        else
        {
            DUETOS_WSPF_PUT((unsigned short)'%');
            DUETOS_WSPF_PUT(*p);
            continue;
        }
        for (int i = n; i < width; ++i)
            DUETOS_WSPF_PUT(zero ? (unsigned short)'0' : (unsigned short)' ');
        for (int i = 0; i < n; ++i)
            DUETOS_WSPF_PUT((unsigned short)(unsigned char)tmp[i]);
    }
    out[pos] = 0;
    return trunc ? -1 : pos;
}

#undef DUETOS_WSPF_PUT
