#pragma once

#include "util/types.h"

/*
 * DuetOS — kernel command-line token lookup.
 *
 * FREESTANDING on purpose: pure functions over a caller-owned NUL-
 * terminated string, no allocation and no globals, so
 * `tests/host/test_cmdline.cpp` can exercise the parser directly.
 *
 * This started life as a file-local helper in
 * `kernel/diag/stress_driver.cpp`, whose comment said it was kept
 * local only "before the first additional consumer". The TPM
 * measured-boot tripwire is that consumer, so it moved here rather
 * than being copied a third time.
 */

namespace duetos::core
{

/// Linear scan: true iff `cmdline` contains a whitespace-delimited
/// token `key=value`; copies the value into `out` (up to `cap - 1`
/// bytes, always NUL-terminated).
///
/// A nullptr cmdline, a nullptr `out`, or a zero `cap` is false. A
/// bare `key` with no `=` does NOT match — callers wanting a valueless
/// flag should test for `key=1` or use a token predicate.
inline bool CmdlineGet(const char* cmdline, const char* key, char* out, u32 cap)
{
    if (cmdline == nullptr || key == nullptr || out == nullptr || cap == 0)
    {
        return false;
    }
    out[0] = '\0';

    const char* p = cmdline;
    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t')
        {
            ++p;
        }
        if (*p == '\0')
        {
            break;
        }

        const char* token = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
        {
            ++p;
        }

        const char* k = key;
        const char* t = token;
        while (*k != '\0' && t < p && *t == *k)
        {
            ++k;
            ++t;
        }
        if (*k == '\0' && t < p && *t == '=')
        {
            ++t;
            u32 i = 0;
            while (t < p && i + 1 < cap)
            {
                out[i++] = *t++;
            }
            out[i] = '\0';
            return true;
        }
    }
    return false;
}

/// Decode `length` hex characters into `out`. Returns false — leaving
/// `out` untouched — on any non-hex character or an odd length, so a
/// mistyped operator-supplied digest is rejected rather than silently
/// decoded into something that will never match.
inline bool HexDecode(const char* text, u32 length, u8* out, u32 out_capacity)
{
    if (text == nullptr || out == nullptr || (length % 2) != 0 || length / 2 > out_capacity)
    {
        return false;
    }

    for (u32 i = 0; i < length; i += 2)
    {
        u8 byte = 0;
        for (u32 nibble = 0; nibble < 2; ++nibble)
        {
            const char c = text[i + nibble];
            u8 value = 0;
            if (c >= '0' && c <= '9')
            {
                value = static_cast<u8>(c - '0');
            }
            else if (c >= 'a' && c <= 'f')
            {
                value = static_cast<u8>(c - 'a' + 10);
            }
            else if (c >= 'A' && c <= 'F')
            {
                value = static_cast<u8>(c - 'A' + 10);
            }
            else
            {
                return false;
            }
            byte = static_cast<u8>((byte << 4) | value);
        }
        out[i / 2] = byte;
    }
    return true;
}

} // namespace duetos::core
