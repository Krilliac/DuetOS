#include "apps/about.h"

#include "arch/x86_64/serial.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/widget.h"
#include "fs/fat32.h"
#include "mm/kheap.h"
#include "time/tick.h"
#include "util/build_config.h"
#include "util/string.h"

namespace duetos::apps::about
{

namespace
{

using duetos::drivers::video::ChromeTextDraw;
using duetos::drivers::video::ChromeTextRole;
using duetos::drivers::video::ChromeTextWeight;
using duetos::drivers::video::FramebufferFillRect;
using duetos::drivers::video::kWindowInvalid;
using duetos::drivers::video::ThemeCurrent;
using duetos::drivers::video::ThemeIdName;
using duetos::drivers::video::ThemeRole;
using duetos::drivers::video::WindowHandle;
using duetos::drivers::video::WindowRegistryCount;
using duetos::drivers::video::WindowSetContentDraw;

constexpr u32 kRowH = 12;

struct State
{
    WindowHandle handle;
};

constinit State g_state = {kWindowInvalid};

// Append a decimal u64 to `dst` at `*pos`, advancing `*pos`. Caps
// at `cap-1` to leave room for a NUL. Caller is responsible for
// terminating the string.
void AppendU64(char* dst, u32* pos, u32 cap, u64 v)
{
    char tmp[24];
    u32 n = 0;
    if (v == 0)
    {
        tmp[n++] = '0';
    }
    else
    {
        while (v > 0 && n < sizeof(tmp))
        {
            tmp[n++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
    }
    while (n > 0 && *pos + 1 < cap)
    {
        dst[(*pos)++] = tmp[--n];
    }
}

using duetos::core::AppendStr;

// Produce a human-friendly byte size. Picks the largest unit that
// keeps the integer part under 1024. e.g. 2_097_152 → "2 MiB",
// 65_536 → "64 KiB", 5 → "5 B". No fractional digits — keeps the
// formatter trivial and the common values (rounded-down) readable.
void AppendBytes(char* dst, u32* pos, u32 cap, u64 bytes)
{
    if (bytes >= (1ULL << 30))
    {
        AppendU64(dst, pos, cap, bytes >> 30);
        AppendStr(dst, pos, cap, " GiB");
    }
    else if (bytes >= (1ULL << 20))
    {
        AppendU64(dst, pos, cap, bytes >> 20);
        AppendStr(dst, pos, cap, " MiB");
    }
    else if (bytes >= (1ULL << 10))
    {
        AppendU64(dst, pos, cap, bytes >> 10);
        AppendStr(dst, pos, cap, " KiB");
    }
    else
    {
        AppendU64(dst, pos, cap, bytes);
        AppendStr(dst, pos, cap, " B");
    }
}

// HH:MM:SS form for an uptime expressed in scheduler ticks. Wraps
// at 99:59:59 (any longer uptime keeps showing 99:59:59 — for v0
// that's fine; nobody runs DuetOS for four days yet).
void AppendUptime(char* dst, u32* pos, u32 cap, u64 ticks, u64 hz)
{
    if (hz == 0)
    {
        AppendStr(dst, pos, cap, "(no tick)");
        return;
    }
    u64 secs = ticks / hz;
    if (secs > 99ULL * 3600 + 59 * 60 + 59)
    {
        secs = 99ULL * 3600 + 59 * 60 + 59;
    }
    const u64 hh = secs / 3600;
    const u64 mm = (secs / 60) % 60;
    const u64 ss = secs % 60;
    if (*pos + 9 < cap)
    {
        dst[(*pos)++] = static_cast<char>('0' + (hh / 10) % 10);
        dst[(*pos)++] = static_cast<char>('0' + hh % 10);
        dst[(*pos)++] = ':';
        dst[(*pos)++] = static_cast<char>('0' + (mm / 10) % 10);
        dst[(*pos)++] = static_cast<char>('0' + mm % 10);
        dst[(*pos)++] = ':';
        dst[(*pos)++] = static_cast<char>('0' + (ss / 10) % 10);
        dst[(*pos)++] = static_cast<char>('0' + ss % 10);
    }
}

// All body rows render through ChromeTextDraw with the requested
// role. Defaults to Body — the row labels + values that dominate
// the panel. Callers pick Title (Bold) for the hero header and
// Caption for the footer hint.
void DrawLine(u32 cx, u32 y, const char* line, u32 fg, u32 bg, ChromeTextRole role = ChromeTextRole::Body,
              ChromeTextWeight weight = ChromeTextWeight::Regular)
{
    ChromeTextDraw(role, cx + 12, y, line, fg, bg, weight);
}

void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* /*cookie*/)
{
    namespace fat = fs::fat32;
    const auto& th = ThemeCurrent();
    const u32 bg = th.role_client[static_cast<u32>(ThemeRole::About)];
    const u32 fg = th.console_fg;
    const u32 dim = th.banner_fg;
    FramebufferFillRect(cx, cy, cw, ch, bg);

    if (cw < 200 || ch < 60)
    {
        return; // window too small; nothing useful to paint
    }

    char line[96];
    u32 p = 0;

    // Header — Title + Bold so the panel name reads as the
    // window's hero label rather than another row.
    p = 0;
    AppendStr(line, &p, sizeof(line), "DUETOS v0 — system info");
    line[p] = '\0';
    DrawLine(cx, cy + 8, line, dim, bg, ChromeTextRole::Title, ChromeTextWeight::Bold);

    u32 y = cy + 8 + kRowH + 6;

    // Build banner / flavor.
    p = 0;
    AppendStr(line, &p, sizeof(line), "BUILD:    ");
#if defined(DUETOS_BUILD_FLAVOR) && DUETOS_BUILD_FLAVOR == 1
    AppendStr(line, &p, sizeof(line), "DEBUG");
#elif defined(DUETOS_BUILD_FLAVOR) && DUETOS_BUILD_FLAVOR == 2
    AppendStr(line, &p, sizeof(line), "RELEASE");
#else
    AppendStr(line, &p, sizeof(line), "(unspecified)");
#endif
#if defined(DUETOS_KASLR) && DUETOS_KASLR == 1
    AppendStr(line, &p, sizeof(line), " +KASLR");
#endif
#if defined(DUETOS_ASSERTS) && DUETOS_ASSERTS == 1
    AppendStr(line, &p, sizeof(line), " +ASSERT");
#endif
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Git commit hash (captured at configure time). Trailing '+'
    // means the working tree was dirty when CMake configured —
    // the running image is the named commit *plus* uncommitted
    // edits. "unknown" means CMake couldn't reach git (not a
    // checkout, or git not installed during configure).
    p = 0;
    AppendStr(line, &p, sizeof(line), "COMMIT:   ");
    AppendStr(line, &p, sizeof(line), duetos::core::BuildGitHash());
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Uptime.
    p = 0;
    AppendStr(line, &p, sizeof(line), "UPTIME:   ");
    AppendUptime(line, &p, sizeof(line), time::TickCount(), time::TickHz());
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Theme name.
    p = 0;
    AppendStr(line, &p, sizeof(line), "THEME:    ");
    AppendStr(line, &p, sizeof(line), ThemeIdName(duetos::drivers::video::ThemeCurrentId()));
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Framebuffer.
    const auto fb = duetos::drivers::video::FramebufferGet();
    p = 0;
    AppendStr(line, &p, sizeof(line), "DISPLAY:  ");
    AppendU64(line, &p, sizeof(line), fb.width);
    AppendStr(line, &p, sizeof(line), "x");
    AppendU64(line, &p, sizeof(line), fb.height);
    AppendStr(line, &p, sizeof(line), "  ");
    AppendU64(line, &p, sizeof(line), fb.bpp);
    AppendStr(line, &p, sizeof(line), "-bpp");
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // FAT32 status.
    p = 0;
    AppendStr(line, &p, sizeof(line), "DISK:     ");
    const fat::Volume* v = fat::Fat32Volume(0);
    if (v == nullptr)
    {
        AppendStr(line, &p, sizeof(line), "(no FAT32 volume)");
    }
    else
    {
        AppendStr(line, &p, sizeof(line), "FAT32 mounted, root entries=");
        AppendU64(line, &p, sizeof(line), v->root_entry_count);
    }
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Heap.
    const auto h = mm::KernelHeapStatsRead();
    p = 0;
    AppendStr(line, &p, sizeof(line), "HEAP:     ");
    AppendBytes(line, &p, sizeof(line), h.used_bytes);
    AppendStr(line, &p, sizeof(line), " used, ");
    AppendBytes(line, &p, sizeof(line), h.free_bytes);
    AppendStr(line, &p, sizeof(line), " free / ");
    AppendBytes(line, &p, sizeof(line), h.pool_bytes);
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    p = 0;
    AppendStr(line, &p, sizeof(line), "          allocs=");
    AppendU64(line, &p, sizeof(line), h.alloc_count);
    AppendStr(line, &p, sizeof(line), " frees=");
    AppendU64(line, &p, sizeof(line), h.free_count);
    AppendStr(line, &p, sizeof(line), " frags=");
    AppendU64(line, &p, sizeof(line), h.free_chunk_count);
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH;

    // Window count — walks the registry counting alive entries so
    // a number that drifts when an app is closed shows the real
    // live state, not the lifetime registration count.
    u32 alive = 0;
    const u32 reg_n = WindowRegistryCount();
    for (u32 i = 0; i < reg_n; ++i)
    {
        if (duetos::drivers::video::WindowIsAlive(i))
            ++alive;
    }
    p = 0;
    AppendStr(line, &p, sizeof(line), "WINDOWS:  ");
    AppendU64(line, &p, sizeof(line), alive);
    AppendStr(line, &p, sizeof(line), " alive / ");
    AppendU64(line, &p, sizeof(line), reg_n);
    AppendStr(line, &p, sizeof(line), " slots");
    line[p] = '\0';
    DrawLine(cx, y, line, fg, bg);
    y += kRowH + 6;

    // Footer hint — Caption role for the secondary "how this
    // panel behaves" annotation, distinct from the row content.
    if (y + kRowH < cy + ch)
    {
        DrawLine(cx, y, "Refreshes on every compositor tick.", dim, bg, ChromeTextRole::Caption);
    }
}

} // namespace

void AboutInit(WindowHandle handle)
{
    g_state.handle = handle;
    WindowSetContentDraw(handle, DrawFn, nullptr);
}

WindowHandle AboutWindow()
{
    return g_state.handle;
}

void AboutSelfTest()
{
    using arch::SerialWrite;
    bool pass = true;

    // AppendU64.
    char buf[64];
    u32 p = 0;
    AppendU64(buf, &p, sizeof(buf), 0);
    if (p != 1 || buf[0] != '0')
        pass = false;
    p = 0;
    AppendU64(buf, &p, sizeof(buf), 12345);
    buf[p] = '\0';
    if (p != 5 || buf[0] != '1' || buf[4] != '5')
        pass = false;

    // AppendBytes — boundary-test each tier.
    p = 0;
    AppendBytes(buf, &p, sizeof(buf), 5);
    buf[p] = '\0';
    if (buf[0] != '5' || buf[1] != ' ' || buf[2] != 'B')
        pass = false;
    p = 0;
    AppendBytes(buf, &p, sizeof(buf), 1024);
    buf[p] = '\0';
    if (buf[0] != '1' || buf[1] != ' ' || buf[2] != 'K')
        pass = false;
    p = 0;
    AppendBytes(buf, &p, sizeof(buf), 1ULL << 20);
    buf[p] = '\0';
    if (buf[0] != '1' || buf[2] != 'M')
        pass = false;
    p = 0;
    AppendBytes(buf, &p, sizeof(buf), 1ULL << 30);
    buf[p] = '\0';
    if (buf[0] != '1' || buf[2] != 'G')
        pass = false;

    // AppendUptime — 1h2m3s should produce "01:02:03".
    p = 0;
    AppendUptime(buf, &p, sizeof(buf), 100ULL * (3600 + 2 * 60 + 3), 100);
    buf[p] = '\0';
    if (p != 8 || buf[0] != '0' || buf[1] != '1' || buf[2] != ':' || buf[3] != '0' || buf[4] != '2' || buf[5] != ':' ||
        buf[6] != '0' || buf[7] != '3')
        pass = false;
    // Cap at 99:59:59 so a hostile / corrupt tick can't spam the screen.
    p = 0;
    AppendUptime(buf, &p, sizeof(buf), 100ULL * (1000 * 3600), 100);
    buf[p] = '\0';
    if (buf[0] != '9' || buf[1] != '9' || buf[3] != '5' || buf[4] != '9')
        pass = false;
    // hz==0 path emits a sentinel rather than dividing by zero.
    p = 0;
    AppendUptime(buf, &p, sizeof(buf), 1, 0);
    buf[p] = '\0';
    if (p == 0 || buf[0] != '(')
        pass = false;

    SerialWrite(pass ? "[about] self-test OK (number formatting + uptime)\n" : "[about] self-test FAILED\n");
}

} // namespace duetos::apps::about
