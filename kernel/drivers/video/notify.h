#pragma once

#include "util/types.h"

/*
 * Notification toasts — v0.
 *
 * A single transient banner painted at the bottom-right of the
 * desktop, above the taskbar and below the cursor. Other kernel
 * code calls `NotifyShow(text)` to surface a one-line message;
 * the toast decays after `kDefaultTtlSec` seconds of compose
 * ticks and then disappears. Mirrors the behaviour an end user
 * expects from a system tray ("file saved", "battery low", "no
 * network"), without coupling any caller to a window.
 *
 * Storage: single global slot. A second `NotifyShow` while a
 * toast is live overwrites it and resets the TTL — the user
 * always sees the most recent message. v0 deliberately doesn't
 * queue: a stack of stale notifications is worse than the latest
 * one only.
 *
 * Context: kernel. `NotifyShow` is task-safe (single store under
 * the compositor lock that the caller already holds); `NotifyRedraw`
 * runs on the ui-ticker thread inside DesktopCompose.
 */

namespace duetos::drivers::video
{

inline constexpr u32 kNotifyMaxText = 80;
inline constexpr u32 kNotifyDefaultTtlTicks = 3; // seconds at 1 Hz compose

/// Severity classification for a toast. Drives the panel
/// background colour so an operator can distinguish a passive
/// status update ("file saved") from a warning ("battery 5%")
/// or an error ("write failed") at a glance. Stored in the
/// history ring so the Notification Center can colour rows
/// after the live toast has expired.
enum class NotifyKind : u8
{
    Info = 0,    // theme accent — neutral status update
    Success = 1, // green band — operation completed
    Warning = 2, // amber band — attention requested
    Error = 3,   // red band   — operation failed
};

/// Display `text` (truncated to kNotifyMaxText) for the default
/// TTL. nullptr / empty text dismisses any active toast.
/// Equivalent to `NotifyShowKind(text, NotifyKind::Info)`.
void NotifyShow(const char* text);

/// Display `text` for `ttl_ticks` compose ticks (≈ seconds).
/// `ttl_ticks == 0` dismisses any active toast. Equivalent to
/// `NotifyShowKindFor(text, NotifyKind::Info, ttl_ticks)`.
void NotifyShowFor(const char* text, u32 ttl_ticks);

/// Display `text` with explicit severity. Default TTL.
void NotifyShowKind(const char* text, NotifyKind kind);

/// Full-form: display `text` with explicit severity and TTL.
/// Coalesces against the history ring's front by (text, kind):
/// pushing the same kind+text pair twice in a row leaves the
/// ring unchanged. Different kind with the same text DOES push
/// — operators want to see the transition from Info to Error.
void NotifyShowKindFor(const char* text, NotifyKind kind, u32 ttl_ticks);

/// True iff a toast is currently visible.
bool NotifyIsActive();

/// Paint the active toast at the bottom-right of the desktop.
/// Called by DesktopCompose between NetPanelRedraw and the
/// caret. Decrements the TTL on every call; when TTL reaches
/// 0 the toast self-clears and the next call is a no-op.
void NotifyRedraw();

/// One-shot self-test: shows + dismisses a toast through the
/// public API and asserts state transitions match. Restores
/// idle state before returning. Prints one PASS/FAIL line to
/// COM1.
void NotifySelfTest();

/// History ring — last `kNotifyHistoryCap` displayed toasts,
/// newest first. The Notification Center / "what was that
/// toast that flashed by?" UI reads from this. Empty slots
/// are NUL-only.
inline constexpr u32 kNotifyHistoryCap = 16;

/// Number of populated entries in the history ring (≤
/// `kNotifyHistoryCap`).
u32 NotifyHistoryCount();

/// Read entry `idx` (0 = most-recent). Copies up to
/// `cap - 1` bytes + NUL terminator into `out`. Returns the
/// number of bytes written (excluding NUL); 0 if `idx` is out
/// of range or `out` is null.
u32 NotifyHistoryGet(u32 idx, char* out, u32 cap);

/// Read the severity of entry `idx`. Returns `NotifyKind::Info`
/// for out-of-range indices so callers don't need a second
/// bounds check.
NotifyKind NotifyHistoryGetKind(u32 idx);

/// Drop every entry in the history ring. The live toast (if any)
/// is left alone — operators dismiss that with `NotifyShow(nullptr)`
/// or wait for the TTL. After this call `NotifyHistoryCount()`
/// returns 0.
void NotifyHistoryClear();

} // namespace duetos::drivers::video
