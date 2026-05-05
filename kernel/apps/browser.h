#pragma once

#include "drivers/video/widget.h"
#include "util/types.h"

/*
 * DuetOS Browser — v0.
 *
 * Minimal HTTP browser. Primary purpose: get the user onto the
 * web so they can download a fuller browser. Hard limits keep the
 * implementation tractable:
 *
 *   - HTTP only — no TLS, so HTTPS URLs are rejected with a clear
 *     status message rather than silently failing.
 *   - HTTP/1.0 GET only — POST / PUT / cookies / redirects are not
 *     followed (a 30x response is reported to the user but the
 *     Location header is not auto-fetched).
 *   - Body cap is `kTcpActiveBufBytes` (2048 bytes) — the kernel's
 *     single-slot TCP receive buffer. Pages larger than this show
 *     a `(truncated)` banner. Downloading anything bigger is gated
 *     on growing that buffer or moving to a streaming API.
 *   - No JavaScript, no CSS, no images, no layout. The renderer is
 *     a tag stripper: HTML tags collapse to whitespace, common
 *     entities (`&amp;` `&lt;` `&gt;` `&quot;` `&nbsp;` `&apos;`)
 *     decode, block-level closers (`</p>` `</div>` `</br>` etc.)
 *     emit a newline so the structure stays readable.
 *
 * UI shape (one window, four modes):
 *
 *   View      — content viewport. Keys:
 *                 U / Tab          enter URL-edit mode
 *                 B / Backspace    back in history
 *                 F                forward in history
 *                 R                reload
 *                 H                history list mode
 *                 L                bookmark list mode
 *                 M                bookmark this page
 *                 S                save body to disk (DLNNNN.HTM)
 *                 J / K / Up / Dn  scroll
 *                 Esc              clear status
 *
 *   UrlEdit   — typing into the URL bar. Keys:
 *                 printable        insert
 *                 Backspace        erase
 *                 Enter            fetch
 *                 Esc              cancel
 *
 *   History   — modal list of visited URLs. Keys:
 *                 Up / Dn          select
 *                 Enter            load
 *                 Esc / H          back to view
 *
 *   Bookmarks — modal list of saved URLs. Keys:
 *                 Up / Dn          select
 *                 Enter            load
 *                 X                remove from bookmarks
 *                 Esc / L          back to view
 *
 * Persistence:
 *   - Bookmarks live in `BOOKMARK.TXT` on the FAT32 root, one URL
 *     per line. Loaded on first window-show, saved after every
 *     mutation. Plain ASCII `\n`-terminated so users can hand-edit.
 *   - Downloads land at the next free `DLNNNN.HTM` slot on the
 *     FAT32 root, raw response body (no HTML stripping).
 *   - History is in-memory only — by design, intuitive for a "type
 *     a URL, see if it works" tool.
 *
 * Threading: each fetch spawns a one-shot kernel task via
 * `SchedCreate`. The input thread sets `fetch_in_flight=true` +
 * the URL, the task does DNS + TCP synchronously (with bounded
 * timeouts), writes results into the browser state, clears the
 * flag, and SchedExits. The DrawFn samples the same state under
 * the compositor lock — single-writer single-reader so a torn
 * read just means one frame paints stale text and the next is
 * correct.
 */

namespace duetos::apps::browser
{

/// Install Browser state on `handle`. Loads bookmarks from FAT32,
/// registers the content-draw callback, leaves the URL bar empty.
void BrowserInit(duetos::drivers::video::WindowHandle handle);

/// Handle of the Browser window, or `kWindowInvalid` until Init.
duetos::drivers::video::WindowHandle BrowserWindow();

/// Keyboard handler. Routes by current mode (see header comment).
/// Returns true iff the key was consumed.
bool BrowserFeedChar(char c);

/// Arrow-key handler. Up/Down scroll in View, navigate in
/// History/Bookmarks; Left/Right are unused in v0.
bool BrowserFeedArrow(u16 keycode);

/// Mouse-wheel handler. In View mode, scrolls the body up/down
/// by `dz` rows; in History/Bookmarks mode, steps the list
/// selection. Registered as the Browser window's WindowWheelFn
/// at BrowserInit time.
void BrowserOnWheel(duetos::i32 dz, duetos::u8 modifiers);

/// Mouse double-click handler. In Bookmarks mode, follows the
/// hit row's URL via `StartFetch`. Other modes — no-op (returns
/// false). Hit-test geometry mirrors `DrawFn`.
bool BrowserOnDoubleClick(duetos::u32 cx, duetos::u32 cy);

/// Switch to URL-edit mode and place the caret at end-of-URL —
/// the v0 backing for the conventional "Ctrl+L" focus-URL
/// shortcut. Bound by main.cpp's keyboard reader when Browser
/// is the active window. Same effect as the existing `U` /
/// `Tab` keys but accessible without losing modifier muscle
/// memory.
void BrowserFocusUrl();

/// Back / forward navigation through the in-memory history
/// stack. Bound by main.cpp's keyboard reader to Alt+Left /
/// Alt+Right when Browser is the active window. No-op at the
/// ends of the history.
void BrowserNavBack();
void BrowserNavForward();

/// Boot self-test — pure compute. Validates URL parsing
/// (scheme/host/port/path extraction), HTML tag stripper +
/// entity decoder. No network I/O so it runs unconditionally.
void BrowserSelfTest();

} // namespace duetos::apps::browser
