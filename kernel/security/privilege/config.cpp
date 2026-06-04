#include "security/privilege/config.h"

namespace duetos::security::privilege
{
using duetos::u32;

namespace
{
constexpr const char* kFlag = "--allow-claude-system-access";
constexpr const char* kDefaultRoot = "/home/user";

u32 Len(const char* s)
{
    u32 n = 0;
    while (s[n] != '\0')
        ++n;
    return n;
}

bool MemEq(const char* a, const char* b, u32 n)
{
    for (u32 i = 0; i < n; ++i)
        if (a[i] != b[i])
            return false;
    return true;
}

// Copy a root string [s, s+n) into cfg.storage and register it. Bounded by 4
// roots and the storage buffer; silently drops overflow.
void AddRoot(PrivConfig& cfg, const char* s, u32 n, u32& storeUsed)
{
    if (cfg.roots.count >= 4 || n == 0)
        return;
    if (storeUsed + n + 1 > sizeof(cfg.storage))
        return;
    char* dst = &cfg.storage[storeUsed];
    for (u32 i = 0; i < n; ++i)
        dst[i] = s[i];
    dst[n] = '\0';
    cfg.roots.root[cfg.roots.count++] = dst;
    storeUsed += n + 1;
}

// Parse `=a:b:c` (the part after '=') into roots.
void ParseRoots(PrivConfig& cfg, const char* p, u32 len, u32& storeUsed)
{
    u32 i = 0;
    while (i < len)
    {
        const u32 s = i;
        while (i < len && p[i] != ':')
            ++i;
        AddRoot(cfg, &p[s], i - s, storeUsed);
        if (i < len && p[i] == ':')
            ++i;
    }
}
} // namespace

namespace
{
PrivConfig g_current; // boot-time config; default {available=false} until wired.
} // namespace

const PrivConfig& PrivConfigCurrent()
{
    return g_current;
}

void PrivConfigSetCurrent(const PrivConfig& cfg)
{
    // NOTE: PrivConfig.roots.root[] point INTO storage[]; a by-value copy would
    // leave them aimed at the source's storage (dangling once the source — a
    // boot-time stack temporary — returns). Copy the bytes, then re-base each
    // root pointer by its offset into g_current.storage.
    g_current.available = cfg.available;
    g_current.roots.count = 0;
    for (u32 i = 0; i < sizeof(g_current.storage); ++i)
        g_current.storage[i] = cfg.storage[i];
    for (u32 i = 0; i < cfg.roots.count && i < 4; ++i)
    {
        if (cfg.roots.root[i] == nullptr)
            continue;
        const duetos::uptr off =
            reinterpret_cast<duetos::uptr>(cfg.roots.root[i]) - reinterpret_cast<duetos::uptr>(&cfg.storage[0]);
        if (off < sizeof(g_current.storage))
            g_current.roots.root[g_current.roots.count++] = &g_current.storage[off];
    }
}

void PrivConfigParse(const char* cmdline, PrivConfig& cfg)
{
    cfg.available = false;
    cfg.roots.count = 0;
    if (cmdline == nullptr)
        return;

    const u32 fl = Len(kFlag);
    u32 storeUsed = 0;
    u32 i = 0;
    while (cmdline[i] != '\0')
    {
        while (cmdline[i] == ' ')
            ++i;
        if (cmdline[i] == '\0')
            break;
        const u32 s = i;
        while (cmdline[i] != '\0' && cmdline[i] != ' ')
            ++i;
        const u32 n = i - s;

        if (n >= fl && MemEq(&cmdline[s], kFlag, fl))
        {
            if (n == fl) // bare flag → default root
            {
                cfg.available = true;
                AddRoot(cfg, kDefaultRoot, Len(kDefaultRoot), storeUsed);
                break;
            }
            if (cmdline[s + fl] == '=') // flag=roots
            {
                cfg.available = true;
                ParseRoots(cfg, &cmdline[s + fl + 1], n - fl - 1, storeUsed);
                if (cfg.roots.count == 0) // `=` with no roots → default
                    AddRoot(cfg, kDefaultRoot, Len(kDefaultRoot), storeUsed);
                break;
            }
            // else: a longer token like `--allow-claude-system-accessX` — not a match.
        }
    }
}

} // namespace duetos::security::privilege
