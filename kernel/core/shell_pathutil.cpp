/*
 * DuetOS — kernel shell: path / parse helpers.
 *
 * Sibling TU of shell.cpp. Houses the four pure string helpers
 * shared across every shell sibling TU: TmpLeaf + FatLeaf strip
 * the /tmp + /fat mount prefixes, ParseU64Str + ParseInt parse
 * decimal-or-0x-hex numeric arguments. None of these helpers
 * touch global state or call any subsystem — they're pure
 * functions over their input string.
 *
 * Hoisted out of shell.cpp so the Fat* family / CmdRead /
 * CmdLinuxexec / CmdExec / CmdReadelf / CmdTranslate slices
 * have a public surface to share.
 */

#include "shell_internal.h"

namespace duetos::core::shell::internal
{

// `/tmp` is served by the writable tmpfs, not the static
// ramfs. Returns nullptr if `path` doesn't name /tmp or a
// /tmp/<leaf>, otherwise a pointer to the leaf name inside
// the original string (empty when the path is exactly "/tmp").
const char* TmpLeaf(const char* path)
{
    if (path == nullptr)
    {
        return nullptr;
    }
    const char prefix[] = "/tmp";
    u32 i = 0;
    for (; prefix[i] != '\0'; ++i)
    {
        if (path[i] != prefix[i])
        {
            return nullptr;
        }
    }
    if (path[i] == '\0')
    {
        return path + i; // ""
    }
    if (path[i] == '/')
    {
        return path + i + 1;
    }
    return nullptr;
}

// Same shape as TmpLeaf, but for the FAT32 mount surfaced at /fat.
// /fat          -> "" (list volume 0's root)
// /fat/FILE     -> "FILE"   (look up FILE in volume 0's root)
// anything else -> nullptr  (falls through to ramfs / tmpfs)
//
// Hard-coded to volume 0 for now: the shell has no syntax for
// picking a different mount, and the first (and only) FAT32 volume
// we probe in tests is at index 0. The `fatcat` raw command still
// lets an operator poke any volume by index if they need to.
const char* FatLeaf(const char* path)
{
    if (path == nullptr)
    {
        return nullptr;
    }
    const char prefix[] = "/fat";
    u32 i = 0;
    for (; prefix[i] != '\0'; ++i)
    {
        if (path[i] != prefix[i])
        {
            return nullptr;
        }
    }
    if (path[i] == '\0')
    {
        return path + i; // ""
    }
    if (path[i] == '/')
    {
        return path + i + 1;
    }
    return nullptr;
}

// Shared helper: parse decimal (default) or hex (0x prefix) into u64.
// Returns true + writes `*out` on success. Used by `read` + any future
// command taking a sector number / address.
bool ParseU64Str(const char* s, u64* out)
{
    if (s == nullptr || out == nullptr || s[0] == 0)
        return false;
    u64 v = 0;
    u32 base = 10;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        s += 2;
        base = 16;
    }
    if (*s == 0)
        return false;
    for (; *s != 0; ++s)
    {
        u64 d;
        if (*s >= '0' && *s <= '9')
            d = static_cast<u64>(*s - '0');
        else if (base == 16 && *s >= 'a' && *s <= 'f')
            d = static_cast<u64>(*s - 'a' + 10);
        else if (base == 16 && *s >= 'A' && *s <= 'F')
            d = static_cast<u64>(*s - 'A' + 10);
        else
            return false;
        v = v * base + d;
    }
    *out = v;
    return true;
}

// Convenience integer parser used by commands that take a small
// positive count (e.g. `crtrace show 64`). Returns the parsed
// value on success; any parse failure or value above i64-max
// returns 0 so the caller's `if (parsed > 0)` guard falls
// through to the default. Reuses ParseU64Str so decimal +
// 0x-hex syntax stay aligned across the shell.
i64 ParseInt(const char* s)
{
    u64 v = 0;
    if (!ParseU64Str(s, &v))
        return 0;
    if (v > 0x7FFFFFFFFFFFFFFFull)
        return 0;
    return static_cast<i64>(v);
}

} // namespace duetos::core::shell::internal
