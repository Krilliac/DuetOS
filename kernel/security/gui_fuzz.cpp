#include "security/gui_fuzz.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/serial.h"
#include "arch/x86_64/timer.h"
#include "drivers/input/ps2kbd.h"
#include "drivers/input/ps2mouse.h"
#include "drivers/video/cursor.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/widget.h"
#include "log/klog.h"
#include "mm/kheap.h"
#include "sched/sched.h"
#include "security/login.h"

namespace duetos::security
{

namespace
{

using duetos::arch::SerialWrite;
using duetos::core::LoginIsActive;
using duetos::drivers::input::KeyboardInjectEvent;
using duetos::drivers::input::KeyEvent;
using duetos::drivers::input::kKeyModAlt;
using duetos::drivers::input::kKeyModCtrl;
using duetos::drivers::input::kKeyModShift;
using duetos::drivers::input::kMouseButtonLeft;
using duetos::drivers::input::kMouseButtonMiddle;
using duetos::drivers::input::kMouseButtonRight;
using duetos::drivers::input::MouseInjectPacket;
using duetos::drivers::input::MousePacket;

struct Config
{
    bool armed = false;
    duetos::u32 secs = 20;
    duetos::u64 seed = 0x9E3779B97F4A7C15ULL;
};

Config g_cfg = {};

// Linear cmdline scan: `key=value` → copy value into out. Mirrors
// the helper in diag/stress_driver.cpp; kept local to avoid
// widening the cmdline surface for a debug-only consumer.
bool CmdlineGet(const char* cmdline, const char* key, char* out, duetos::u32 cap)
{
    if (cmdline == nullptr || out == nullptr || cap == 0)
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
        const char* tok = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
        {
            ++p;
        }
        const char* k = key;
        const char* q = tok;
        while (*k != '\0' && q < p && *q == *k)
        {
            ++k;
            ++q;
        }
        if (*k == '\0' && q < p && *q == '=')
        {
            ++q;
            duetos::u32 n = 0;
            while (q < p && n + 1 < cap)
            {
                out[n++] = *q++;
            }
            out[n] = '\0';
            return true;
        }
        // Bare token form (`gui-fuzz` with no `=value`).
        if (*k == '\0' && q == p)
        {
            out[0] = '\0';
            return true;
        }
    }
    return false;
}

bool ParseU64(const char* s, duetos::u64* out)
{
    if (s == nullptr || s[0] == '\0')
    {
        return false;
    }
    duetos::u64 v = 0;
    for (duetos::u32 i = 0; s[i] != '\0'; ++i)
    {
        char c = s[i];
        duetos::u64 d;
        if (c >= '0' && c <= '9')
        {
            d = static_cast<duetos::u64>(c - '0');
        }
        else if (c >= 'a' && c <= 'f')
        {
            d = static_cast<duetos::u64>(c - 'a' + 10);
        }
        else if (c >= 'A' && c <= 'F')
        {
            d = static_cast<duetos::u64>(c - 'A' + 10);
        }
        else
        {
            return false;
        }
        // Decimal unless it has a hex digit; ParseU64 is only used
        // for the seed (any base) and secs (decimal) — treat all
        // input as base-16-safe by scaling on the digit set seen.
        v = v * 16 + d;
    }
    *out = v;
    return true;
}

bool ParseU32Dec(const char* s, duetos::u32* out)
{
    if (s == nullptr || s[0] == '\0')
    {
        return false;
    }
    duetos::u32 v = 0;
    for (duetos::u32 i = 0; s[i] != '\0'; ++i)
    {
        if (s[i] < '0' || s[i] > '9')
        {
            return false;
        }
        v = v * 10 + static_cast<duetos::u32>(s[i] - '0');
    }
    *out = v;
    return true;
}

// xorshift64* — deterministic so a crashing run reproduces from
// the logged seed.
duetos::u64 g_rng = 0;
duetos::u64 Rng()
{
    duetos::u64 x = g_rng;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    g_rng = x;
    return x * 0x2545F4914F6CDD1DULL;
}
duetos::u32 RngMod(duetos::u32 m)
{
    return m == 0 ? 0 : static_cast<duetos::u32>(Rng() % m);
}
duetos::i32 RngRange(duetos::i32 lo, duetos::i32 hi)
{
    return lo + static_cast<duetos::i32>(RngMod(static_cast<duetos::u32>(hi - lo + 1)));
}

void SerialU64(duetos::u64 v)
{
    char buf[24];
    duetos::u32 n = 0;
    if (v == 0)
    {
        buf[n++] = '0';
    }
    else
    {
        char tmp[24];
        duetos::u32 t = 0;
        while (v != 0)
        {
            tmp[t++] = static_cast<char>('0' + (v % 10));
            v /= 10;
        }
        while (t > 0)
        {
            buf[n++] = tmp[--t];
        }
    }
    buf[n] = '\0';
    SerialWrite(buf);
}

void InjectKey(duetos::u16 code, duetos::u8 mods)
{
    KeyEvent ev{};
    ev.code = code;
    ev.modifiers = mods;
    ev.is_release = false;
    KeyboardInjectEvent(ev);
    ev.is_release = true;
    KeyboardInjectEvent(ev);
}

void InjectMouse(duetos::i32 dx, duetos::i32 dy, duetos::i32 dz, duetos::u8 buttons)
{
    MousePacket p{};
    p.dx = dx;
    p.dy = dy;
    p.dz = dz;
    p.buttons = buttons;
    MouseInjectPacket(p);
}

// Key pool. kKeyArrow* / kKeyF* are the 0x100+ codes; the rest
// are printable ASCII the dispatch treats as text or hotkey
// letters. 'k' is deliberately absent: Ctrl+Alt+K locks the
// screen and would re-arm the login gate for the rest of the run,
// collapsing desktop coverage. Every other hotkey letter is in.
const duetos::u16 kKeyPool[] = {
    'a',
    'b',
    'c',
    'd',
    'e',
    'l',
    'm',
    'p',
    't',
    'y',
    'q',
    'w',
    's',
    'z',
    'x',
    'n',
    'o',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '0',
    ' ',
    ',',
    '.',
    '/',
    '-',
    duetos::drivers::input::kKeyEsc,
    duetos::drivers::input::kKeyEnter,
    duetos::drivers::input::kKeyTab,
    duetos::drivers::input::kKeyBackspace,
    duetos::drivers::input::kKeyArrowUp,
    duetos::drivers::input::kKeyArrowDown,
    duetos::drivers::input::kKeyArrowLeft,
    duetos::drivers::input::kKeyArrowRight,
    duetos::drivers::input::kKeyHome,
    duetos::drivers::input::kKeyEnd,
    duetos::drivers::input::kKeyPageUp,
    duetos::drivers::input::kKeyPageDown,
    duetos::drivers::input::kKeyInsert,
    duetos::drivers::input::kKeyDelete,
    duetos::drivers::input::kKeyF1,
    duetos::drivers::input::kKeyF2,
    duetos::drivers::input::kKeyF3,
    duetos::drivers::input::kKeyF4,
    duetos::drivers::input::kKeyF5,
    duetos::drivers::input::kKeyF6,
    duetos::drivers::input::kKeyF9,
    duetos::drivers::input::kKeyF10,
    duetos::drivers::input::kKeyF11,
    duetos::drivers::input::kKeyF12,
};
constexpr duetos::u32 kKeyPoolN = sizeof(kKeyPool) / sizeof(kKeyPool[0]);

// Walk the cursor toward an absolute target with a few injected
// relative packets, exercising the move path along the way.
void MoveToward(duetos::u32 tx, duetos::u32 ty)
{
    duetos::u32 cx = 0, cy = 0;
    duetos::drivers::video::CursorPosition(&cx, &cy);
    duetos::i32 dx = static_cast<duetos::i32>(tx) - static_cast<duetos::i32>(cx);
    duetos::i32 dy = static_cast<duetos::i32>(ty) - static_cast<duetos::i32>(cy);
    for (duetos::u32 step = 0; step < 4; ++step)
    {
        InjectMouse(dx / 4, dy / 4, 0, 0);
    }
}

[[noreturn]] void Runner(void*)
{
    using duetos::drivers::video::DisplayMode;

    g_rng = g_cfg.seed != 0 ? g_cfg.seed : 0x9E3779B97F4A7C15ULL;

    SerialWrite("[gui-fuzz] start secs=");
    SerialU64(g_cfg.secs);
    SerialWrite(" seed=");
    SerialU64(g_cfg.seed);
    SerialWrite("\n");

    // Wait for the login session to open. Pair with autologin=1 so
    // this resolves in the first second; bail loud after ~15s so a
    // boot-ordering regression is obvious rather than silently
    // fuzzing nothing.
    for (duetos::u32 waited = 0; waited < 1500; ++waited)
    {
        if (!LoginIsActive())
        {
            break;
        }
        duetos::sched::SchedSleepTicks(1);
    }
    if (LoginIsActive())
    {
        SerialWrite("[gui-fuzz] FAIL — login session never opened (need autologin=1)\n");
        duetos::arch::TestExit(0x10);
    }

    const auto fb = duetos::drivers::video::FramebufferGet();
    const duetos::u32 w = fb.width != 0 ? fb.width : 1024;
    const duetos::u32 h = fb.height != 0 ? fb.height : 768;
    SerialWrite("[gui-fuzz] desktop up fb=");
    SerialU64(w);
    SerialWrite("x");
    SerialU64(h);
    SerialWrite("\n");

    const duetos::u64 start = duetos::arch::TimerTicks();
    const duetos::u64 deadline = start + static_cast<duetos::u64>(g_cfg.secs) * 100ULL;
    duetos::u64 iters = 0;
    duetos::u64 next_progress = start + 200; // ~2 s

    while (duetos::arch::TimerTicks() < deadline)
    {
        const duetos::u32 roll = RngMod(100);
        if (roll < 42)
        {
            // Random-walk motion; 1-in-8 a long warp to a random
            // point or a screen corner (titlebars, taskbar, start
            // button, tray, window edges all live at the margins).
            if (RngMod(8) == 0)
            {
                duetos::u32 tx, ty;
                switch (RngMod(6))
                {
                case 0:
                    tx = 0;
                    ty = 0;
                    break;
                case 1:
                    tx = w - 1;
                    ty = 0;
                    break;
                case 2:
                    tx = 0;
                    ty = h - 1;
                    break;
                case 3:
                    tx = w - 1;
                    ty = h - 1;
                    break;
                case 4:
                    tx = 0;
                    ty = h - 12;
                    break; // start button band
                default:
                    tx = RngMod(w);
                    ty = RngMod(h);
                    break;
                }
                MoveToward(tx, ty);
            }
            else
            {
                InjectMouse(RngRange(-34, 34), RngRange(-34, 34), 0, 0);
            }
        }
        else if (roll < 62)
        {
            // Click: press, jiggle, release. ~1-in-5 doubled.
            duetos::u8 b = kMouseButtonLeft;
            const duetos::u32 bsel = RngMod(10);
            if (bsel == 8)
            {
                b = kMouseButtonRight;
            }
            else if (bsel == 9)
            {
                b = kMouseButtonMiddle;
            }
            const duetos::u32 clicks = (RngMod(5) == 0) ? 2 : 1;
            for (duetos::u32 c = 0; c < clicks; ++c)
            {
                InjectMouse(RngRange(-2, 2), RngRange(-2, 2), 0, b);
                InjectMouse(0, 0, 0, 0);
            }
        }
        else if (roll < 74)
        {
            // Drag: hold left, several motion frames, release.
            const duetos::u32 frames = 5 + RngMod(12);
            for (duetos::u32 f = 0; f < frames; ++f)
            {
                InjectMouse(RngRange(-26, 26), RngRange(-26, 26), 0, kMouseButtonLeft);
            }
            InjectMouse(0, 0, 0, 0);
        }
        else if (roll < 78)
        {
            // Wheel ticks (scrollbars, list views, zoom paths).
            InjectMouse(0, 0, RngRange(-3, 3), 0);
        }
        else
        {
            // Key event. Modifiers: mostly bare, sometimes Shift,
            // and a healthy share of Ctrl+Alt so the whole hotkey
            // matrix in boot_tasks.cpp gets hammered.
            const duetos::u16 code = kKeyPool[RngMod(kKeyPoolN)];
            duetos::u8 mods = 0;
            switch (RngMod(8))
            {
            case 0:
            case 1:
                mods = kKeyModCtrl | kKeyModAlt;
                break;
            case 2:
                mods = kKeyModShift;
                break;
            case 3:
                mods = kKeyModAlt;
                break;
            case 4:
                mods = kKeyModCtrl;
                break;
            default:
                mods = 0;
                break;
            }
            InjectKey(code, mods);
        }

        ++iters;

        // Yield every few events so the kbd/mouse readers actually
        // drain (the injection rings are intentionally tiny — a
        // tight unbroken loop just overflows them and starves the
        // dispatch we want to exercise).
        if ((iters & 0x7) == 0)
        {
            duetos::sched::SchedSleepTicks(1);
        }

        // If a hotkey flipped us into TTY, flip back: TTY mode logs
        // every mouse packet to serial (boot_tasks.cpp:1882), which
        // would bury the log, and desktop is the surface under
        // test. The toggle path itself still got exercised.
        if (duetos::drivers::video::GetDisplayMode() == DisplayMode::Tty)
        {
            InjectKey('t', kKeyModCtrl | kKeyModAlt);
            duetos::sched::SchedSleepTicks(2);
        }

        // Re-entered the login gate (a Ctrl+Alt path or screensaver
        // armed it)? Type the seeded default creds to climb back to
        // the desktop instead of fuzzing the gate for the remainder.
        if (LoginIsActive())
        {
            const char* u = "admin";
            for (duetos::u32 i = 0; u[i] != '\0'; ++i)
            {
                InjectKey(static_cast<duetos::u16>(u[i]), 0);
            }
            InjectKey(duetos::drivers::input::kKeyTab, 0);
            for (duetos::u32 i = 0; u[i] != '\0'; ++i)
            {
                InjectKey(static_cast<duetos::u16>(u[i]), 0);
            }
            InjectKey(duetos::drivers::input::kKeyEnter, 0);
            duetos::sched::SchedSleepTicks(20);
        }

        if (duetos::arch::TimerTicks() >= next_progress)
        {
            duetos::u32 cx = 0, cy = 0;
            duetos::drivers::video::CursorPosition(&cx, &cy);
            const auto heap = duetos::mm::KernelHeapStatsRead();
            SerialWrite("[gui-fuzz] t=");
            SerialU64((duetos::arch::TimerTicks() - start) / 100);
            SerialWrite("s iters=");
            SerialU64(iters);
            SerialWrite(" cursor=");
            SerialU64(cx);
            SerialWrite(",");
            SerialU64(cy);
            SerialWrite(" heap_KiB=");
            SerialU64(heap.used_bytes / 1024);
            SerialWrite("\n");
            next_progress += 200;
        }
    }

    const auto heap = duetos::mm::KernelHeapStatsRead();
    SerialWrite("[gui-fuzz] complete iters=");
    SerialU64(iters);
    SerialWrite(" heap_KiB=");
    SerialU64(heap.used_bytes / 1024);
    SerialWrite("\n");

    // Deterministic teardown so a headless run terminates instead
    // of idling to the outer wallclock cap. 0x10 = the CI "sentinel
    // reached cleanly" status (QEMU exit 0x21).
    duetos::arch::TestExit(0x10);
}

} // namespace

void GuiFuzzArm(const char* cmdline)
{
    if (g_cfg.armed)
    {
        return;
    }

    char value[24] = {};
    if (!CmdlineGet(cmdline, "gui-fuzz", value, sizeof(value)))
    {
        return;
    }
    if (value[0] != '\0')
    {
        duetos::u32 secs = g_cfg.secs;
        if (ParseU32Dec(value, &secs) && secs != 0)
        {
            g_cfg.secs = secs;
        }
    }

    char seed[24] = {};
    if (CmdlineGet(cmdline, "gui-fuzz-seed", seed, sizeof(seed)))
    {
        duetos::u64 s = g_cfg.seed;
        if (ParseU64(seed, &s) && s != 0)
        {
            g_cfg.seed = s;
        }
    }

    g_cfg.armed = true;
    SerialWrite("[gui-fuzz] arming runner\n");
    auto* t = duetos::sched::SchedCreate(&Runner, nullptr, "gui-fuzz");
    if (t == nullptr)
    {
        KLOG_ERROR("security/gui-fuzz", "SchedCreate failed — fuzzer not started");
        g_cfg.armed = false;
    }
}

} // namespace duetos::security
