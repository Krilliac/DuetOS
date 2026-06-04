#include "apps/browser/privileged/scope.h"

namespace duetos::apps::browser::priv
{
using duetos::u32;

namespace
{
char Lower(char c)
{
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
}

bool EqCI(const char* a, const char* b)
{
    u32 i = 0;
    for (; a[i] != '\0' && b[i] != '\0'; ++i)
        if (Lower(a[i]) != Lower(b[i]))
            return false;
    return a[i] == b[i];
}

// A byte legal in a privileged path: printable ASCII only, and never a
// backslash (FAT/NTFS separator confusion) or colon (NTFS ADS / drive letter).
// Rejecting >=0x80 conservatively closes NFD/NFC + homoglyph aliasing.
bool ByteOk(char c)
{
    const unsigned char b = static_cast<unsigned char>(c);
    return b >= 0x20 && b < 0x80 && c != '\\' && c != ':';
}

// Resolve `.`/`..`, collapse `//`, reject control/non-ASCII/backslash/colon and
// any segment with a trailing '.' or ' ' (FAT/NTFS strips those — an alias for
// e.g. `audit.log`). Writes a canonical absolute path to out. Fail-closed.
bool Canonicalize(const char* in, char* out, u32 cap)
{
    if (in == nullptr || in[0] != '/')
        return false;
    for (u32 i = 0; in[i] != '\0'; ++i)
        if (!ByteOk(in[i]))
            return false;

    u32 olen = 0;
    out[olen++] = '/';
    u32 i = 0;
    while (in[i] != '\0')
    {
        while (in[i] == '/')
            ++i;
        if (in[i] == '\0')
            break;
        const u32 s = i;
        while (in[i] != '\0' && in[i] != '/')
            ++i;
        const u32 n = i - s;

        if (n == 1 && in[s] == '.')
            continue; // "." — no-op
        if (n == 2 && in[s] == '.' && in[s + 1] == '.')
        {
            if (olen > 1) // pop the last segment (clamped at root)
            {
                while (olen > 1 && out[olen - 1] != '/')
                    --olen;
                if (olen > 1)
                    --olen;
            }
            continue;
        }
        // Reject a segment with a trailing '.' or ' ' (FAT/NTFS alias).
        if (in[s + n - 1] == '.' || in[s + n - 1] == ' ')
            return false;

        if (out[olen - 1] != '/')
        {
            if (olen + 1 >= cap)
                return false;
            out[olen++] = '/';
        }
        if (olen + n >= cap)
            return false;
        for (u32 k = 0; k < n; ++k)
            out[olen++] = in[s + k];
    }
    out[olen] = '\0';
    if (olen == 0)
    {
        out[0] = '/';
        out[1] = '\0';
    }
    return true;
}

// canon == prefix, OR canon starts with prefix + '/' (a path boundary).
bool UnderOrEqualCI(const char* canon, const char* prefix)
{
    u32 i = 0;
    for (; prefix[i] != '\0'; ++i)
        if (Lower(canon[i]) != Lower(prefix[i]))
            return false;
    return canon[i] == '\0' || canon[i] == '/';
}

const char* Basename(const char* p)
{
    const char* b = p;
    for (u32 i = 0; p[i] != '\0'; ++i)
        if (p[i] == '/')
            b = &p[i + 1];
    return b;
}

bool IsRefused(const char* canon)
{
    if (canon[0] == '/' && canon[1] == '\0')
        return true; // the root itself
    if (UnderOrEqualCI(canon, "/dev") || UnderOrEqualCI(canon, "/proc") || UnderOrEqualCI(canon, "/sys") ||
        UnderOrEqualCI(canon, "/boot"))
        return true;
    if (EqCI(Basename(canon), "audit.log")) // case-insensitive; trailing-dot/colon already refused upstream
        return true;
    return false;
}

// Byte-exact (case-SENSITIVE) boundary containment: a case mismatch fails closed.
bool IsWithin(const char* canon, const char* root)
{
    if (root == nullptr)
        return false;
    u32 i = 0;
    for (; root[i] != '\0'; ++i)
        if (canon[i] != root[i])
            return false;
    return canon[i] == '\0' || canon[i] == '/';
}
} // namespace

CapSet DefaultArmScope()
{
    CapSet s;
    s.Add(Cap::FsRead);
    s.Add(Cap::FsWrite);
    s.Add(Cap::ProcSpawn);
    s.Add(Cap::KernelRead);
    s.Add(Cap::Net);
    return s;
}

bool CanonicalizeAndContain(const char* in, const Roots& roots, char* out, u32 cap)
{
    char canon[512];
    if (!Canonicalize(in, canon, sizeof(canon)))
        return false;
    if (IsRefused(canon))
        return false;
    for (u32 i = 0; i < roots.count; ++i)
    {
        if (IsWithin(canon, roots.root[i]))
        {
            u32 j = 0;
            for (; canon[j] != '\0' && j + 1 < cap; ++j)
                out[j] = canon[j];
            out[j] = '\0';
            return canon[j] == '\0'; // false if the output buffer truncated.
        }
    }
    return false;
}

} // namespace duetos::apps::browser::priv
