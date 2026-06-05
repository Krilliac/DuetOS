// See boot_cmdline.h. Mechanical extraction from main.cpp's
// anonymous namespace; the cache + parse logic is unchanged.

#include "core/boot_cmdline.h"

#include "mm/multiboot2.h"
#include "util/types.h"

namespace duetos::core
{

namespace
{

// Cached copy of the boot cmdline. Populated on the first
// FindBootCmdline call that resolves a non-null string while the
// Multiboot2 info struct is still reachable through the low
// identity map (early boot, before MmFinalizePaging tears that
// map down). Later callers — KbdReader / ui-ticker setup at
// kernel_main+~4300, the `idlelock=<seconds>` parser, anything
// running after the heavy boot phases — read from this cache
// instead of re-walking the original info buffer at the now-
// unmapped low VA.
//
// 4 KiB is well over Multiboot2's per-tag size for cmdline (the
// loader caps it at 1 KiB on every implementation we've
// surveyed); a longer string truncates with a trailing NUL
// rather than corrupting adjacent data.
constinit char g_boot_cmdline_cache[4096] = {};
constinit bool g_boot_cmdline_cached = false;

} // namespace

// Walk the Multiboot2 tag list for type-1 (boot cmdline) and
// return its NUL-terminated string, or nullptr if absent.
//
// Caches the result on first success: subsequent calls hand back
// the cached copy without dereferencing `info_phys`. This is
// required because `info_phys` is the LOW identity-mapped address
// the boot loader handed us, and that mapping disappears once
// MmFinalizePaging tears the early page tables down. A late-boot
// caller passing the same `info_phys` would page-fault inside
// this function (observed in CI as `arch/traps msg="#PF Page
// fault" cr2=0x92000` at FindBootCmdline+0x40, with the bringup
// smoke crashing right after `[bringup-tail] kbd-reader spawned`).
const char* FindBootCmdline(duetos::uptr info_phys)
{
    if (g_boot_cmdline_cached)
    {
        return g_boot_cmdline_cache[0] != '\0' ? g_boot_cmdline_cache : nullptr;
    }
    if (info_phys == 0)
    {
        return nullptr;
    }
    const auto* info = reinterpret_cast<const duetos::mm::MultibootInfoHeader*>(info_phys);
    duetos::uptr cursor = info_phys + sizeof(duetos::mm::MultibootInfoHeader);
    const duetos::uptr end = info_phys + info->total_size;
    while (cursor < end)
    {
        const auto* tag = reinterpret_cast<const duetos::mm::MultibootTagHeader*>(cursor);
        if (tag->type == duetos::mm::kMultibootTagEnd)
        {
            break;
        }
        if (tag->type == duetos::mm::kMultibootTagCmdline)
        {
            // String starts right after the 8-byte {type, size} header.
            const char* src = reinterpret_cast<const char*>(cursor + sizeof(duetos::mm::MultibootTagHeader));
            // Copy into the cache so callers after MmFinalizePaging
            // still have a valid pointer. Truncate at the buffer
            // size minus 1 to keep the trailing NUL.
            duetos::usize i = 0;
            while (i + 1 < sizeof(g_boot_cmdline_cache) && src[i] != '\0')
            {
                g_boot_cmdline_cache[i] = src[i];
                ++i;
            }
            g_boot_cmdline_cache[i] = '\0';
            g_boot_cmdline_cached = true;
            return g_boot_cmdline_cache;
        }
        cursor += (tag->size + 7u) & ~duetos::uptr{7};
    }
    // No cmdline tag — record the absence so a re-call short-
    // circuits without re-walking the (potentially-unmapped) info.
    g_boot_cmdline_cache[0] = '\0';
    g_boot_cmdline_cached = true;
    return nullptr;
}

// Return true iff `cmdline` contains the whitespace-delimited
// token "key=value" where `value` matches `want`. Case-sensitive.
// A nullptr cmdline returns false. This is the smallest thing
// that'll work for "boot=tty" / "boot=desktop"; a full parser
// lands with the first cmdline-heavy consumer.
bool CmdlineMatches(const char* cmdline, const char* key, const char* want)
{
    if (cmdline == nullptr)
    {
        return false;
    }
    // Walk tokens. A token is a run of non-whitespace, separated
    // by spaces. Compare key prefix + '=' then the value tail.
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
        // [token, p) is the current token.
        // Match key+'=' prefix.
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
            // Compare [t, p) against want.
            const char* w = want;
            while (*w != '\0' && t < p && *t == *w)
            {
                ++t;
                ++w;
            }
            if (*w == '\0' && t == p)
            {
                return true;
            }
        }
    }
    return false;
}

namespace
{
// Cached "debugstub=1" result. Parsed once by DebugStubInit early in
// boot; DebugStubAttached() reads this. constinit so it lives in .bss
// with a defined value before any constructor runs.
constinit bool g_debug_stub = false;
} // namespace

void DebugStubInit(const char* cmdline)
{
    g_debug_stub = CmdlineMatches(cmdline, "debugstub", "1");
}

bool DebugStubAttached()
{
    return g_debug_stub;
}

} // namespace duetos::core
