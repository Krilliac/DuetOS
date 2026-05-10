/*
 * DuetOS — userland stdio helpers, v0.
 *
 * Companion to `include/stdio.h`. Every output path eventually
 * lands in `write(STDOUT_FILENO, ...)`. The format spec is a
 * tight subset (see header) — a future workload that needs the
 * full ISO C printf surface gets a separate dedicated library.
 */

#include "stdio.h"
#include "string.h"
#include "unistd.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

size_t puts_char(char c)
{
    char buf[1] = {c};
    const ssize_t rc = write(STDOUT_FILENO, buf, 1);
    return rc > 0 ? (size_t)rc : 0;
}

size_t puts_str(const char* s)
{
    if (s == NULL)
        return 0;
    const size_t n = strlen(s);
    if (n == 0)
        return 0;
    const ssize_t rc = write(STDOUT_FILENO, s, n);
    return rc > 0 ? (size_t)rc : 0;
}

size_t println(const char* s)
{
    return puts_str(s) + puts_char('\n');
}

/* Convert |v| into base-10 ASCII at `out` (caller-sized buffer
 * of at least 21 bytes for INT64_MIN). Returns the number of
 * bytes written. */
static size_t format_decimal(long v, char* out)
{
    char tmp[24];
    size_t n = 0;
    int negative = (v < 0);
    /* Use unsigned arithmetic to handle INT64_MIN cleanly. */
    unsigned long u = negative ? (unsigned long)(-(v + 1)) + 1ul : (unsigned long)v;
    if (u == 0)
    {
        tmp[n++] = '0';
    }
    while (u > 0 && n < sizeof(tmp))
    {
        tmp[n++] = (char)('0' + (u % 10));
        u /= 10;
    }
    size_t w = 0;
    if (negative)
        out[w++] = '-';
    while (n > 0)
        out[w++] = tmp[--n];
    return w;
}

size_t print_int(long v)
{
    char buf[24];
    const size_t w = format_decimal(v, buf);
    const ssize_t rc = write(STDOUT_FILENO, buf, w);
    return rc > 0 ? (size_t)rc : 0;
}

/* Format `v` as hex into `out`. Always emits at least one digit;
 * pads with leading zeros up to `width` (capped at 16). When
 * `prefix` is non-zero, prepends "0x". Returns bytes written. */
static size_t format_hex(unsigned long v, unsigned width, int prefix, char* out)
{
    static const char kHex[] = "0123456789abcdef";
    if (width > 16)
        width = 16;
    char tmp[16];
    size_t n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    while (v > 0 && n < sizeof(tmp))
    {
        tmp[n++] = kHex[v & 0xF];
        v >>= 4;
    }
    /* Pad. */
    while (n < width && n < sizeof(tmp))
        tmp[n++] = '0';
    size_t w = 0;
    if (prefix)
    {
        out[w++] = '0';
        out[w++] = 'x';
    }
    while (n > 0)
        out[w++] = tmp[--n];
    return w;
}

size_t print_hex(unsigned long v, unsigned width)
{
    char buf[24];
    const size_t w = format_hex(v, width, /*prefix=*/(width != 0 || v != 0) ? 1 : 0, buf);
    const ssize_t rc = write(STDOUT_FILENO, buf, w);
    return rc > 0 ? (size_t)rc : 0;
}

/* Tiny printf — see header for the supported specifier subset.
 * Walks the format string char-by-char, batches plain ASCII into
 * a single write() per literal run, then handles each `%X`
 * directive separately. */
size_t print_fmt(const char* fmt, ...)
{
    if (fmt == NULL)
        return 0;
    va_list ap;
    va_start(ap, fmt);
    size_t total = 0;
    const char* run = fmt;
    while (*fmt != '\0')
    {
        if (*fmt != '%')
        {
            ++fmt;
            continue;
        }
        /* Flush the literal run before the '%'. */
        if (fmt > run)
        {
            const ssize_t rc = write(STDOUT_FILENO, run, (size_t)(fmt - run));
            if (rc > 0)
                total += (size_t)rc;
        }
        ++fmt; /* past '%' */
        int is_long = 0;
        if (*fmt == 'l')
        {
            is_long = 1;
            ++fmt;
        }
        switch (*fmt)
        {
        case 's':
        {
            const char* s = va_arg(ap, const char*);
            total += puts_str(s != NULL ? s : "(null)");
            break;
        }
        case 'c':
        {
            const int c = va_arg(ap, int);
            total += puts_char((char)c);
            break;
        }
        case 'd':
        {
            const long v = is_long ? va_arg(ap, long) : (long)va_arg(ap, int);
            total += print_int(v);
            break;
        }
        case 'u':
        {
            char buf[24];
            const unsigned long u = is_long ? va_arg(ap, unsigned long) : (unsigned long)va_arg(ap, unsigned);
            const size_t w = format_decimal((long)u, buf);
            const ssize_t rc = write(STDOUT_FILENO, buf, w);
            if (rc > 0)
                total += (size_t)rc;
            break;
        }
        case 'x':
        {
            const unsigned long v = is_long ? va_arg(ap, unsigned long) : (unsigned long)va_arg(ap, unsigned);
            char buf[24];
            const size_t w = format_hex(v, 0, /*prefix=*/0, buf);
            const ssize_t rc = write(STDOUT_FILENO, buf, w);
            if (rc > 0)
                total += (size_t)rc;
            break;
        }
        case 'p':
        {
            void* p = va_arg(ap, void*);
            char buf[24];
            const size_t w = format_hex((unsigned long)p, 16, /*prefix=*/1, buf);
            const ssize_t rc = write(STDOUT_FILENO, buf, w);
            if (rc > 0)
                total += (size_t)rc;
            break;
        }
        case '%':
        {
            total += puts_char('%');
            break;
        }
        default:
            /* Echo the unrecognised directive verbatim so
             * mistakes are visible. */
            total += puts_char('%');
            total += puts_char(*fmt);
            break;
        }
        ++fmt;
        run = fmt;
    }
    if (fmt > run)
    {
        const ssize_t rc = write(STDOUT_FILENO, run, (size_t)(fmt - run));
        if (rc > 0)
            total += (size_t)rc;
    }
    va_end(ap);
    return total;
}
