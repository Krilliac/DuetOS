# Win32 windowing v1.3 — WndProc dispatch + WM_PAINT + user-data + metrics + cross-proc post + find/enum

**Last updated:** 2026-04-24
**Type:** Observation + Decision
**Status:** Landed — `windowed_hello` fixture now dispatches
WM_TIMER through a user-registered WndProc, counts the
invocations via SetWindowLongPtr(GWLP_USERDATA), and
round-trips InvalidateRect → WM_PAINT.

## What shipped

Fourth pass adds 9 syscalls (85..93), WndProc dispatch via
the existing GWLP_WNDPROC slot, a minimal WM_PAINT pipeline,
double-click detection in the mouse reader, and removes the
"same-pid only" restriction on PostMessage.

### Window longs — SYS_WIN_GET_LONG / SET_LONG (85 / 86)

`RegisteredWindow.longs[4]` holds four 64-bit slots per window:
GWLP_WNDPROC (0), GWLP_USERDATA (1), plus two extras. Backs
`GetWindowLongPtrA/W` + `SetWindowLongPtrA/W` + the 32-bit
`GetWindowLongA/W` / `SetWindowLongA/W` (which truncate). The
slot for GWLP_WNDPROC is CRUCIAL — it's how DispatchMessage
recovers the user-mode WndProc pointer.

### WndProc dispatch (no kernel change beyond the long slot)

user32's `RegisterClassA/W/ExA/ExW` stores the class name +
`lpfnWndProc` in a 32-slot in-process class table.
`CreateWindowExA/W` looks up the class by name after creating
the HWND and writes the WndProc into GWLP_WNDPROC via
SYS_WIN_SET_LONG. `DispatchMessageA/W` reads GWLP_WNDPROC back
and invokes the proc with the `__stdcall` ABI:

```c
proc(hwnd, msg, wParam, lParam)
```

Missing WndProc → return 0 (DefWindowProc equivalent).
Effectively: **the entire WndProc call chain is user-mode
only**; the kernel only stores an 8-byte pointer. Cross-
process invocations aren't possible (each process has its
own class table + its own WndProc VAs in its own AS — same
as Win32).

### WM_PAINT / InvalidateRect / ValidateRect / BeginPaint / EndPaint

SYS_WIN_INVALIDATE (87) and SYS_WIN_VALIDATE (88) flip a
per-window `dirty` bit. Invalidate also synchronously calls
`WindowDrainPaints` which walks every alive window, posts
WM_PAINT (wParam=0, lParam=0) to each dirty one, and clears
the bits. Kernel-owned boot windows (pid=0) get their bit
cleared without posting (they paint via content_fn anyway).

user32's `BeginPaint` returns an HDC (same HWND|GDI_TAG
encoding gdi32 uses), fills a PAINTSTRUCT with the client
rect, and ValidateRects the window. `EndPaint` is a no-op
beyond that — the display list is the canonical paint state.

### Active / foreground window — SYS_WIN_GET/SET_ACTIVE (89 / 90)

`GetActiveWindow` / `GetForegroundWindow` → existing
`WindowActive()`. `SetActiveWindow` / `SetForegroundWindow`
→ `WindowRaise()` (which already sets active).

### GetSystemMetrics — SYS_WIN_GET_METRIC (91)

Real values for the common selectors: SM_CXSCREEN / SM_CYSCREEN
from the framebuffer, SM_CYCAPTION = 22, SM_CXFRAME / SM_CYFRAME
= 2, SM_CMOUSEBUTTONS = 3, SM_CMONITORS = 1, SM_CXMINTRACK /
SM_CYMINTRACK = 100 / 50. Unknown selectors return 0 (Win32
convention — callers tolerate this).

### EnumWindows + FindWindow — SYS_WIN_ENUM / FIND (92 / 93)

`EnumWindows(proc, lparam)` asks the kernel for an array of
alive+visible HWNDs, then iterates client-side calling `proc`
per-HWND (stops when proc returns FALSE). `FindWindowA/W`
case-insensitive matches the class name argument is ignored
in v1 — only the window title is used.

### Double-click — WM_LBUTTONDBLCLK

Mouse reader tracks `(last_click_tick, hwnd, x, y)` in static
locals. A press edge within 50 ticks (500 ms) on the same HWND
at the same pixel fires WM_LBUTTONDBLCLK (0x0203) instead of a
second WM_LBUTTONDOWN; the double-click state is then reset so
a third click would start a fresh pair.

### Cross-process PostMessage

`DoWinPostMsg` used to refuse posts targeting another
process's windows. v1.3 drops that check — any PostMessage to
an alive HWND lands in its queue. GetMessage still filters by
`owner_pid == CurrentProcess().pid`, so the receiver is the
only consumer.

### ScreenToClient / ClientToScreen

Pure-client translation via `SYS_WIN_GET_RECT(0)` + the 2-px
border + 22-px title offset. No new syscall.

## New exports (user32.dll)

`BeginPaint`, `ClientToScreen`, `EndPaint`, `EnumWindows`,
`FindWindowA`, `FindWindowExA`, `FindWindowExW`, `FindWindowW`,
`GetWindowLongA/W`, `GetWindowLongPtrA/W`, `ScreenToClient`,
`SetActiveWindow`, `SetForegroundWindow`, `SetWindowLongA/W`,
`SetWindowLongPtrA/W`, `ValidateRect`, plus functional upgrades
to `GetActiveWindow`, `GetForegroundWindow`, `GetSystemMetrics`,
`InvalidateRect`, `UpdateWindow`, `RegisterClassA/W/ExA/ExW`,
`UnregisterClassA`, `CreateWindowExA/W`, `DispatchMessageA/W`.

## Verification

windowed_hello fixture now registers a WNDCLASSA with a
`duet_wndproc` that counts WM_TIMERs in GWLP_USERDATA.
Everything end-to-end in QEMU:

```
[odbg] windowed_hello: screen w=1280     ← SM_CXSCREEN
[odbg] windowed_hello: screen h=800      ← SM_CYSCREEN
[odbg] windowed_hello: paint done
[odbg] windowed_hello: drained 8         ← lifecycle msgs
[odbg] windowed_hello: pumped 3
[odbg] windowed_hello: timers 3
[odbg] windowed_hello: wndproc 3         ← WM_TIMERs hit the WndProc
[odbg] windowed_hello: painted 1         ← WM_PAINT posted+dispatched
[I] sys : exit rc val=0x57
[proc] reap-windows pid=0x16 count=0x1
```

## Still NOT done yet

- **Synchronous SendMessage** — `SendMessageA/W` returns 0
  (no cross-thread or within-thread invoke path).
- **WM_NCCREATE / WM_NCDESTROY / WM_NCPAINT** — only the client
  half fires.
- **Mouse wheel / horizontal scroll** — PS/2 packet format
  doesn't carry wheel deltas.
- **IME / text-service messages** (WM_IME_*, WM_CHAR scan-
  codes > 0x7F) — not planned.
- **Modal dialog loops** (DialogBox*, EndDialog) — require
  DialogProc dispatch on top of the message pump.
- **Common controls / menu bars** — no GDI-side widget
  kits yet.
