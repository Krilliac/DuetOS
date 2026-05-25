/*
 * DuetOS boot splash — implementation.
 *
 * State machine: kUninitialised → kActive → kDismissed.
 * - SplashInit:          paints the wallpaper backdrop + initial ticker rect.
 * - SplashAdvancePhase:  re-renders the bottom-left ticker with the new name.
 * - SplashTick:          forwards to WallpaperTick for ambient motion.
 * - SplashDismiss:       clears the ticker rect; backdrop pixels survive so
 *                        the login screen paints over them without a flash.
 *
 * None of these are thread-safe on their own — callers hold the compositor
 * lock, matching the contract in splash.h.
 *
 * Self-test (SplashSelfTest) walks the full state machine without emitting
 * any visible output, then logs a single PASS/FAIL sentinel on serial.
 *
 * Boot wiring (SplashInit in boot_bringup, self-test in boot umbrella) is
 * Task 11 — this TU is pure implementation only.
 */

#include "drivers/video/splash.h"

#include "arch/x86_64/serial.h"
#include "debug/probes.h"
#include "drivers/video/chrome_text.h"
#include "drivers/video/framebuffer.h"
#include "drivers/video/theme.h"
#include "drivers/video/wallpaper.h"
#include "util/types.h"

namespace duetos::drivers::video
{

namespace
{

// ── State ────────────────────────────────────────────────────────────────────

enum class State : u8
{
    kUninitialised,
    kActive,
    kDismissed,
};

static State g_state = State::kUninitialised;

// Current phase name displayed in the ticker. Bounded by kPhaseMax including
// the NUL terminator so DrawTickerLine never reads past the buffer end.
static constexpr u32 kPhaseMax = 64;
static char g_phase[kPhaseMax] = {};

// Set to true by SplashSelfTest on PASS; read by SplashSelfTestPassed().
static bool g_selftest_passed = false;

// ── Ticker geometry ───────────────────────────────────────────────────────────

// Left margin for the ticker text in pixels.
static constexpr u32 kTickerX = 40;

// Ticker rect height in pixels (one 8-px glyph + 4 px padding each side).
static constexpr u32 kTickerH = 16;

// Ticker baseline offset within the rect (top of glyph row).
static constexpr u32 kTickerTextDY = 4;

// Ticker Y position: 730/768 of the framebuffer height, scaled to the actual
// framebuffer. On a 1024×768 baseline this places the ticker at y = 730.
// On taller resolutions it scales proportionally into the lower-left corner.
static constexpr u32 kTickerYFrac = 730;
static constexpr u32 kTickerYBase = 768;

// Foreground and background for the ticker line.
// Soft-grey on desktop background — visible on any theme, unobtrusive.
static constexpr u32 kTickerFg = 0x00B0B8C0; // light slate
// Background is filled from ThemeCurrent().desktop_bg at draw time.

// Prefix rendered before the phase name ("duetos . ").
static constexpr const char* kTickerPrefix = "duetos . ";

// ── DrawTickerLine ───────────────────────────────────────────────────────────

/// Clear the ticker rect to the desktop colour and render the current phase
/// name. Returns immediately if the framebuffer is not available.
void DrawTickerLine()
{
    if (!FramebufferAvailable())
    {
        return;
    }

    const auto info = FramebufferGet();
    const u32 fb_w = info.width;
    const u32 fb_h = info.height;
    const u32 ticker_y = (kTickerYFrac * fb_h) / kTickerYBase;
    const u32 bg_rgb = ThemeCurrent().desktop_bg;

    // Clear the ticker rect.
    FramebufferFillRect(kTickerX, ticker_y, fb_w - kTickerX, kTickerH, bg_rgb);

    // Build the label: "duetos . <phase>".  We concatenate into a small stack
    // buffer so ChromeTextDraw gets one contiguous string.
    char label[kPhaseMax + 16]; // prefix (≤15) + phase (≤63) + NUL
    u32 lp = 0;
    for (const char* s = kTickerPrefix; *s != '\0' && lp < sizeof(label) - 1; ++s)
    {
        label[lp++] = *s;
    }
    for (u32 pi = 0; g_phase[pi] != '\0' && lp < sizeof(label) - 1; ++pi)
    {
        label[lp++] = g_phase[pi];
    }
    label[lp] = '\0';

    ChromeTextDraw(ChromeTextRole::Caption, kTickerX, ticker_y + kTickerTextDY, label, kTickerFg, bg_rgb);
}

} // anonymous namespace

// ── Public API ───────────────────────────────────────────────────────────────

void SplashInit()
{
    if (g_state != State::kUninitialised)
    {
        return;
    }

    if (!FramebufferAvailable())
    {
        // TTY path: skip the splash entirely.
        g_state = State::kDismissed;
        return;
    }

    // Paint the initial backdrop using the active theme's desktop colour.
    WallpaperPaint(ThemeCurrent().desktop_bg);

    // Clear g_phase and render the empty ticker rect so the background slot
    // is pre-cleared before the first AdvancePhase call arrives.
    g_phase[0] = '\0';
    DrawTickerLine();

    g_state = State::kActive;
}

void SplashAdvancePhase(const char* name)
{
    if (g_state != State::kActive)
    {
        return;
    }

    // Copy into g_phase, always NUL-terminating within kPhaseMax.
    u32 i = 0;
    if (name != nullptr)
    {
        for (; name[i] != '\0' && i < kPhaseMax - 1U; ++i)
        {
            g_phase[i] = name[i];
        }
    }
    g_phase[i] = '\0';

    // Re-paint the wallpaper backdrop on every phase advance. Subsystem
    // init that runs between phases (console buffer paint, taskbar
    // placeholder, kernel banner write, etc.) can poke through the
    // splash backdrop because it paints directly to the framebuffer.
    // Re-running WallpaperPaint wipes those artifacts and leaves the
    // splash visually clean. Cost: ~6 wallpaper paints across boot,
    // ~10 ms total — invisible against subsystem-bringup wall time.
    WallpaperPaint(ThemeCurrent().desktop_bg);
    DrawTickerLine();
}

void SplashTick()
{
    if (g_state != State::kActive)
    {
        return;
    }

    WallpaperTick();
}

void SplashDismiss()
{
    if (g_state != State::kActive)
    {
        return; // Already dismissed or never initialised — idempotent.
    }

    // Clear only the ticker rect; the wallpaper backdrop survives so the
    // login screen can paint on top without a visible flash.
    if (FramebufferAvailable())
    {
        const auto info = FramebufferGet();
        const u32 fb_w = info.width;
        const u32 fb_h = info.height;
        const u32 ticker_y = (kTickerYFrac * fb_h) / kTickerYBase;
        const u32 bg_rgb = ThemeCurrent().desktop_bg;

        FramebufferFillRect(kTickerX, ticker_y, fb_w - kTickerX, kTickerH, bg_rgb);
    }

    g_state = State::kDismissed;
}

// ── Self-test ─────────────────────────────────────────────────────────────────

void SplashSelfTest()
{
    using duetos::arch::SerialWrite;

    g_selftest_passed = false;
    bool pass = true;
    u32 failed_step = 0;

    auto mark_fail = [&](u32 step)
    {
        if (pass)
        {
            pass = false;
            failed_step = step;
        }
    };

    // Capture existing state so we can restore it after the test.
    const State saved_state = g_state;
    char saved_phase[kPhaseMax];
    for (u32 i = 0; i < kPhaseMax; ++i)
    {
        saved_phase[i] = g_phase[i];
    }

    // ── Step 1: SplashInit from kUninitialised ────────────────────────────
    g_state = State::kUninitialised;
    g_phase[0] = '\0';

    SplashInit();

    // After Init the state must be either kActive (FB present) or kDismissed
    // (TTY path). It must never stay kUninitialised.
    if (g_state == State::kUninitialised)
    {
        SerialWrite("[splash-selftest] FAIL init left state kUninitialised\n");
        KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB6);
        mark_fail(1);
    }

    // ── Step 2: SplashAdvancePhase (FB path only) ─────────────────────────
    if (pass && g_state == State::kActive)
    {
        SplashAdvancePhase("memory");
        // Phase buffer must contain "memory".
        if (g_phase[0] != 'm')
        {
            SerialWrite("[splash-selftest] FAIL phase not stored after AdvancePhase\n");
            KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB6);
            mark_fail(2);
        }
    }

    // ── Step 3: second AdvancePhase ───────────────────────────────────────
    if (pass && g_state == State::kActive)
    {
        SplashAdvancePhase("scheduler");
        if (g_phase[0] != 's')
        {
            SerialWrite("[splash-selftest] FAIL second phase not stored\n");
            KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB6);
            mark_fail(3);
        }
    }

    // ── Step 4: Dismiss must move state to kDismissed ─────────────────────
    if (pass && g_state == State::kActive)
    {
        SplashDismiss();
        if (g_state != State::kDismissed)
        {
            SerialWrite("[splash-selftest] FAIL dismiss did not set kDismissed\n");
            KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB6);
            mark_fail(4);
        }
    }

    // ── Step 5: Double-dismiss must be a no-op (already kDismissed) ───────
    if (pass)
    {
        const State pre = g_state;
        SplashDismiss();
        if (g_state != pre)
        {
            SerialWrite("[splash-selftest] FAIL double-dismiss changed state\n");
            KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB6);
            mark_fail(5);
        }
    }

    // ── Step 6: Init-again from kDismissed must be a no-op ───────────────
    if (pass)
    {
        SplashInit(); // kDismissed — must stay kDismissed.
        if (g_state != State::kDismissed)
        {
            SerialWrite("[splash-selftest] FAIL reinit from dismissed changed state\n");
            KBP_PROBE_V(debug::ProbeId::kBootSelftestFail, 0xB6);
            mark_fail(6);
        }
    }

    // ── Restore state for the real boot ──────────────────────────────────
    g_state = saved_state;
    for (u32 i = 0; i < kPhaseMax; ++i)
    {
        g_phase[i] = saved_phase[i];
    }

    // ── Report ────────────────────────────────────────────────────────────
    if (pass)
    {
        SerialWrite("[splash-selftest] PASS\n");
        g_selftest_passed = true;
    }
    else
    {
        char msg[64] = "[splash-selftest] FAIL at step ";
        u32 o = 31;
        msg[o++] = static_cast<char>('0' + (failed_step % 10));
        msg[o++] = '\n';
        msg[o] = '\0';
        SerialWrite(msg);
    }
}

bool SplashSelfTestPassed()
{
    return g_selftest_passed;
}

} // namespace duetos::drivers::video
