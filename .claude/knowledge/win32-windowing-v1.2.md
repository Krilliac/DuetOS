# Win32 windowing v1.2 — lifecycle msgs + timers + GDI primitives + input state + capture + clipboard

**Last updated:** 2026-04-24
**Type:** Observation + Decision
**Status:** Landed — verified end-to-end: windowed_hello paints
with GDI primitives, pumps 3 WM_TIMERs via SetTimer +
GetMessage, exits cleanly.

## What shipped

Third pass on the windowing subsystem adds 13 syscalls
(`SYS_WIN_TIMER_SET..SYS_WIN_CLIP_GET_TEXT`, 72..84) plus a
stack of implicit wins: every CreateWindow / DestroyWindow /
ShowWindow / MoveWindow path now emits Win32-standard
lifecycle messages, a new `win-timer` kernel thread ticks
registered timers every 10 ms, the keyboard reader maintains
an async VK-state bitmap, and mouse capture + text clipboard
come online.

### Lifecycle messages (no new syscall numbers)

Existing handlers now post:

| Origin | Messages (in queue order) |
|--------|---------------------------|
| `DoWinCreate` | WM_CREATE, WM_SIZE, WM_SHOWWINDOW, WM_ACTIVATE, WM_SETFOCUS |
| `DoWinDestroy` | WM_DESTROY |
| `DoWinShow(SW_HIDE)` | WM_SHOWWINDOW(0), WM_ACTIVATE(WA_INACTIVE), WM_KILLFOCUS |
| `DoWinShow(SW_SHOW)` | WM_SHOWWINDOW(1), WM_ACTIVATE(WA_ACTIVE), WM_SETFOCUS |
| `DoWinMove` | WM_MOVE and/or WM_SIZE (per flags) |

wParam / lParam follow Win32 conventions (WM_SIZE's lParam
packs w/h, WM_MOVE's lParam packs x/y, WM_ACTIVATE's wParam =
WA_ACTIVE/WA_INACTIVE).

### Timers — SYS_WIN_TIMER_SET / KILL (72 / 73)

Per-window timer table holds 32 slots (`WindowTimerSlot`).
`SetTimer(hwnd, id, ms, cb)` rounds `ms` up to scheduler ticks
(10 ms grain) and stores it; `KillTimer` drops the slot. A new
kernel thread `win-timer` wakes every tick, decrements every
timer's `remaining_ticks`, and on zero posts `WM_TIMER`
(`wParam = timer_id`) to the target HWND. Timer callbacks (the
`TIMERPROC` argument) are not invoked — v1 always delivers via
the message queue.

`WindowTimerReap(pid, hwnd)` runs when a window dies so timers
don't post into reaped slots; `WindowReapByOwner` calls it for
every window it closes.

### GDI extensions — SYS_GDI_LINE / ELLIPSE / SET_PIXEL (74 / 75 / 76)

Three new primitive kinds land in the per-window display list
(`WinGdiPrimKind::Line`, `Ellipse`, `Pixel`). The compositor
replay path gained:
- **Bresenham line** with 4096-pixel iteration cap (guards
  against huge-coord DoS).
- **Midpoint ellipse** — two-region algorithm with
  per-quadrant plot clipped to the client rect.
- **Single pixel** — direct FramebufferPutPixel.

gdi32 stubs that were no-ops now route through the new
syscalls:

| gdi32 export | Backs |
|--------------|-------|
| `LineTo` + `MoveToEx` | Module-global current point → SYS_GDI_LINE |
| `Polyline` | N-1 SYS_GDI_LINEs |
| `Polygon` | Polyline + closing segment |
| `Ellipse` | SYS_GDI_ELLIPSE |
| `SetPixel` / `SetPixelV` | SYS_GDI_SET_PIXEL |

`GetPixel` returns `CLR_INVALID` — no framebuffer read-back
syscall in v1.

### Async keyboard state — SYS_WIN_GET_KEYSTATE (77)

`g_vk_state[256/8]` bitmap, maintained by the keyboard reader
via `WindowInputTrackKey(code, down)` on every press/release
edge (set BEFORE the modifier / routing logic so even filtered
events update the cache). `GetKeyState` / `GetAsyncKeyState`
return the Win32 layout (high bit set = currently down; low
bit = toggled, not tracked in v1 — always 0).

### Cursor position — SYS_WIN_GET_CURSOR / SET_CURSOR (78 / 79)

`GetCursorPos` copies the compositor cursor into a POINT;
`SetCursorPos` moves the cursor via `CursorMove` with clamped
`dx/dy` deltas. Real end-to-end: a Win32 program that reads
the cursor sees the same value as the shell's hit-tester.

### Mouse capture — SYS_WIN_SET/RELEASE/GET_CAPTURE (80 / 81 / 82)

`g_mouse_capture` stores the captured HWND. When non-invalid,
the mouse reader's PE routing block targets the captured
window regardless of cursor position (overriding topmost
hit-test). The process-exit reaper releases capture if the
dying process held it. Mouse-capture handle is a global
singleton — matches Win32.

### Text clipboard — SYS_WIN_CLIP_SET/GET_TEXT (83 / 84)

Single 1024-byte ASCII buffer in `g_clipboard` plus
`g_clipboard_len`. `OpenClipboard` / `CloseClipboard` /
`EmptyClipboard` are stateless passes; `SetClipboardData(CF_TEXT)`
copies from user into `g_clipboard`; `GetClipboardData(CF_TEXT)`
returns a per-process 1-KiB shadow buffer the kernel fills.
Non-ASCII bytes stored as `?`. Clipboard survives process
exits — matches Win32's desktop-wide scope.

### Alt+key → WM_SYSKEYDOWN / WM_SYSCHAR

Keyboard reader now checks `modifiers & kKeyModAlt` before
building messages for PE windows. Alt-held: WM_SYSKEYDOWN
(0x0104) / WM_SYSCHAR (0x0106) with lParam bit 29 set
(Win32 context-code convention). Plain: WM_KEYDOWN (0x0100)
/ WM_CHAR (0x0102).

## New exports (user32.dll + gdi32.dll)

user32: `GetAsyncKeyState`, `GetCapture`, `GetKeyState`,
`KillTimer`, `ReleaseCapture`, `SetCapture`, `SetTimer`,
functional upgrades to `GetCursorPos`, `SetCursorPos`,
`OpenClipboard`, `CloseClipboard`, `EmptyClipboard`,
`GetClipboardData`, `SetClipboardData`.

gdi32: `GetPixel`, `SetPixel`, `SetPixelV`, functional
upgrades to `Ellipse`, `LineTo`, `MoveToEx`, `Polygon`,
`Polyline`.

## Files touched

| File | Change |
|------|--------|
| `kernel/drivers/video/widget.{h,cpp}` | Display-list prims (Line/Ellipse/Pixel) + Bresenham + midpoint ellipse; VK state bitmap; mouse capture; clipboard; timer table + tick; WindowMsgWaitBlockTimeout |
| `kernel/subsystems/win32/window_syscall.{h,cpp}` | 13 new handlers (+ lifecycle posts in existing CREATE/DESTROY/SHOW/MOVE) |
| `kernel/core/syscall.{h,cpp}` | Enum 72..84 + dispatch cases |
| `kernel/core/main.cpp` | Async VK state tracked by kbd reader; Alt+key → WM_SYSKEYDOWN; mouse reader routes to captured HWND; `win-timer` thread |
| `userland/libs/user32/user32.c` | Real timer + key state + cursor + capture + clipboard stubs |
| `userland/libs/gdi32/gdi32.c` | Real Line/Polyline/Polygon/Ellipse/SetPixel |
| `userland/libs/kernel32/kernel32.c` | (unchanged; OutputDebugStringA already present) |
| `userland/apps/windowed_hello/*` | Fixture upgraded to exercise GDI + timer + pump end-to-end |

## Verification

```
[msgbox] pid=0x16 caption="Windowed Hello" text="Running on DuetOS!"
[win] create pid=0x16 hwnd=7 rect=(500,400 420x220) title="WINDOWED HELLO"
[odbg] windowed_hello: paint done
[odbg] windowed_hello: drained 8         ← 8 lifecycle msgs at startup
[odbg] windowed_hello: pumped 3
[odbg] windowed_hello: timers 3           ← 3 WM_TIMERs in the pump
[I] sys : exit rc val=0x57
[proc] reap-windows pid=0x16 count=0x1
```

## Still NOT done yet

- **WndProc dispatch.** `DispatchMessage` is a no-op. No
  user-mode callback trampoline; `TIMERPROC` is ignored, all
  timers use the queue.
- **WM_PAINT** isn't synthesized — programs must paint
  eagerly (imperatively after ShowWindow) instead of on
  invalidation.
- **Cross-process PostMessage** still refused at the
  syscall.
- **Double-click detection** — no WM_LBUTTONDBLCLK.
- **Mouse wheel** — no WM_MOUSEWHEEL.
- **Raw-input / device-arrival notifications** — not
  planned for v1.x.
- **Caret** (GetCaretBlinkTime, CreateCaret, ...) — text
  editors will need this eventually.
