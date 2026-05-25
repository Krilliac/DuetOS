#pragma once

#include "util/types.h"

/*
 * DuetOS boot splash — owns the post-FramebufferInit pre-LoginStart
 * screen. Paints the active theme's wallpaper backdrop via
 * WallpaperPaint(), then renders a phase ticker mono-text line at
 * the bottom-left that's mutated by SplashAdvancePhase(). Dismissed
 * cleanly by SplashDismiss() — backdrop pixels survive, only the
 * ticker rect is cleared, so LoginStart(LoginMode::Gui) paints over
 * the same backdrop without a visible scene change.
 *
 * Scope limits:
 *   - GUI-only. LoginMode::Tty skips this entirely.
 *   - Painted under the compositor lock.
 *   - No fade transition; no "splash dismissed" effect — the
 *     wallpaper continuity IS the transition design.
 *
 * See docs/superpowers/specs/2026-05-24-duetos-pass-b-design.md §4.1.
 */

namespace duetos::drivers::video
{

/// Paint the initial backdrop + first phase ticker line. Must be
/// called after FramebufferInit() and before any SplashAdvancePhase().
/// Idempotent — re-call is a no-op. Caller holds compositor lock.
void SplashInit();

/// Update the phase ticker text. Called from boot_bringup.cpp for
/// each completed phase. Re-renders only the phase-ticker rect.
/// No-op if SplashInit was not called or SplashDismiss was already
/// called. Caller holds compositor lock.
void SplashAdvancePhase(const char* name);

/// Per-frame motion tick. Currently just forwards to WallpaperTick()
/// (splash motion = wallpaper motion). Caller holds compositor lock.
void SplashTick();

/// Clear the phase ticker rect; backdrop continues unchanged. The
/// next caller is typically LoginStart(LoginMode::Gui). Idempotent.
/// Caller holds compositor lock.
void SplashDismiss();

/// Boot-time self-test: paint -> advance -> dismiss invariants.
/// Emits `[splash-selftest] PASS` on success or FAIL + ProbeFire.
void SplashSelfTest();

/// Accessor for the boot umbrella aggregator.
bool SplashSelfTestPassed();

} // namespace duetos::drivers::video
