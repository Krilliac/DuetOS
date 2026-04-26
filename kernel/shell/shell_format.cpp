/*
 * DuetOS — kernel shell: shared console-output formatters.
 *
 * Sibling TU of shell.cpp. Houses the four numeric printers
 * (WriteU64Dec, WriteU8TwoDigits, WriteU64Hex, WriteI64Dec)
 * used by virtually every shell command that emits a value.
 *
 * Hoisted out of shell.cpp so the sibling TUs (shell_core,
 * shell_security, shell_process, shell_storage, ...) can drop
 * their local copies and reach the formatters through
 * shell_internal.h.
 */

#include "shell/shell_internal.h"

#include "drivers/video/console.h"

namespace duetos::core::shell::internal
{

using duetos::drivers::video::ConsoleWrite;
using duetos::drivers::video::ConsoleWriteChar;

void WriteU64Dec(u64 v)
{
    if (v == 0)
    {
        ConsoleWriteChar('0');
        return;
    }
    char tmp[24];
    u32 n = 0;
    while (v > 0 && n < sizeof(tmp))
    {
        tmp[n++] = static_cast<char>('0' + (v % 10));
        v /= 10;
    }
    for (u32 i = 0; i < n; ++i)
    {
        ConsoleWriteChar(tmp[n - 1 - i]);
    }
}

void WriteU8TwoDigits(u8 v)
{
    ConsoleWriteChar(static_cast<char>('0' + (v / 10)));
    ConsoleWriteChar(static_cast<char>('0' + (v % 10)));
}

// Fixed-width hex writer: prints `digits` nibbles of `v`, high
// nibble first, with a leading "0x". digits == 0 trims leading
// zeros (min 1). Used by every register-dump / MSR / CPUID
// command.
void WriteU64Hex(u64 v, u32 digits)
{
    ConsoleWrite("0x");
    if (digits == 0)
    {
        // Strip leading zeros — find highest non-zero nibble.
        digits = 1;
        for (u32 i = 16; i > 0; --i)
        {
            if (((v >> ((i - 1) * 4)) & 0xF) != 0)
            {
                digits = i;
                break;
            }
        }
    }
    if (digits > 16)
    {
        digits = 16;
    }
    for (u32 i = digits; i > 0; --i)
    {
        const u8 nib = static_cast<u8>((v >> ((i - 1) * 4)) & 0xF);
        const char c = (nib < 10) ? static_cast<char>('0' + nib) : static_cast<char>('A' + nib - 10);
        ConsoleWriteChar(c);
    }
}

void WriteI64Dec(i64 v)
{
    if (v < 0)
    {
        ConsoleWriteChar('-');
        WriteU64Dec(static_cast<u64>(-v));
    }
    else
    {
        WriteU64Dec(static_cast<u64>(v));
    }
}

} // namespace duetos::core::shell::internal
