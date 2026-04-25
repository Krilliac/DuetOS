# Win32 windowing — current state (through v1.4)

**Last updated:** 2026-04-25
**Type:** Observation + Decision
**Status:** Active — `windowed_hello` exercises the full surface
end-to-end on every headless QEMU boot.

## Scope

Cumulative snapshot of every Win32 windowing slice that has
landed: lifecycle, message queue, GDI, input, focus, parent/child,
styles, caret, MessageBox returns, SendMessage. Replaces the
per-slice notes (`win32-windowing-v0/v1/v1.2/v1.3`) — git history
preserves them; this doc captures the system as it stands today.

## Architecture

```
PE (user32 IAT) ──► user32 stub bytecode ──► int 0x80
                                              │
                                              ▼
                                         SYS_WIN_*
                                              │
                                              ▼
   kernel/subsystems/win32/window_syscall.cpp ──►
   kernel/drivers/video/widget.cpp (compositor + per-window state)
                                              │
                                              ▼
                                  framebuffer present hook
```

`HwndToCompositorHandleForCaller(hwnd, pid)` is the per-process
HWND → compositor handle gate at every entry. Cross-process HWND
reads return `kWindowInvalid`, which prevents accidental cross-pid
GWLP reads (and forces SendMessage cross-process to return 0).

## What is wired

### Lifecycle / message pump
- `CreateWindowExA/W` (captures dwStyle / dwExStyle / parent into
  the per-window 4-slot `longs[]` array).
- `DestroyWindow`, `ShowWindow`, `MoveWindow`, `UpdateWindow`,
  `InvalidateRect` → WM_PAINT.
- `GetMessageA/W` (blocking, 10 ms granularity) and
  `PeekMessageA/W` (non-blocking) on the per-window message ring.
- `TranslateMessage`, `DispatchMessageA/W` (60-byte stub that
  looks up the WndProc and invokes via `__stdcall`).
- `DefWindowProcA/W` returns 0 / WM_PAINT-end semantics.
- Process-exit reaper destroys windows + frees `longs[]` slots.

### GDI
- Window HDC + memDC paths share one object table (HBRUSH, HPEN,
  HBITMAP). Stock objects (`GetStockObject`) return real handles.
- `CreateCompatibleDC` + `CreateCompatibleBitmap` + `SelectObject`
  + `BitBlt` / `StretchBlt` work as the canonical double-buffered
  paint idiom. memDC paint helpers in `gdi_objects.cpp` write
  raw BGRA into the selected bitmap.
- Outline + fill primitives: `Rectangle`, `FillRect`,
  `Ellipse` (fill+outline), `MoveToEx` + `LineTo`, `SetPixel`.
  Pen / brush / bk_color / bk_mode / text_color are stored per-DC
  (memDC and window DC); `text_color_set` flag distinguishes
  "explicit black" from "never set" so SetTextColor(BLACK) takes
  effect on a window DC.
- `TextOutA`, `TextOutW`, `DrawTextA` (8×8 font, ASCII +
  punctuation; `Font8x8Lookup` falls back to a filled-box glyph
  for unmapped codes).
- `GetSysColor` + `GetSysColorBrush` return Classic-theme values.

### Input
- WM_LBUTTONDOWN / WM_LBUTTONUP / WM_MOUSEMOVE / WM_KEYDOWN /
  WM_KEYUP / WM_CHAR routed by the compositor to the per-window
  ring of the focused window.
- `SetCapture` / `ReleaseCapture` redirect mouse messages to a
  capturing window regardless of cursor position.
- Async input state: `GetKeyState`, `GetAsyncKeyState`,
  `GetCursorPos`, `SetCursorPos`.

### Focus / parent / styles
- `g_focus_hwnd` is distinct from `g_active_window` (topmost
  z-order). `SetFocus` fires WM_KILLFOCUS / WM_SETFOCUS pairs.
- `SetParent`, `GetParent`, `GetWindow(GW_*)` walk z-order for
  Next / Prev / First / Last; Child scans descendants.
- `GetWindowLongPtr[A/W]` / `SetWindowLongPtr[A/W]` recognise
  Win32 negative constants: GWLP_WNDPROC=−4, GWLP_USERDATA=−21,
  GWL_STYLE=−16, GWL_EXSTYLE=−20 — remapped to slots 0/1/2/3 of
  the per-window `longs[]` array.

### Caret / beep
- `CreateCaret` / `DestroyCaret` / `SetCaretPos` / `ShowCaret` /
  `HideCaret` route through one syscall (op + args). Compositor's
  1 Hz ui-ticker toggles `g_caret_on`; DesktopCompose paints a
  solid rectangle when `on && shown && visible`.
- `MessageBeep` / `Beep` forward to `PcSpeakerBeep(freq, ms)`;
  defaults 800 Hz / 100 ms for `MessageBeep(0)`. Blocking but
  brief.

### SendMessage
- `SendMessageA/W` + `SendNotifyMessageA/W` fetch the target's
  GWLP_WNDPROC via SYS_WIN_GET_LONG and invoke it directly
  (__stdcall). Cross-process SendMessage returns 0 because the
  HWND→compositor lookup denies cross-pid reads.

### MessageBox
- Real return codes per `uType & 0xF`: IDOK (1), IDRETRY (4),
  IDYES (6) for the common shapes. Simulates "user clicked the
  default button". The text still goes only to the serial log —
  no modal UI.

## Verification (`windowed_hello` end-to-end)

```
[odbg] windowed_hello: screen w=1280
[odbg] windowed_hello: screen h=800
[odbg] windowed_hello: paint done
[odbg] windowed_hello: drained 8
[odbg] windowed_hello: pumped 3
[odbg] windowed_hello: timers 3
[odbg] windowed_hello: wndproc 3
[odbg] windowed_hello: painted 1
[odbg] windowed_hello: send_rv 0          (SendMessage → DefWindowProc=0)
[odbg] windowed_hello: send_ud 1          (WndProc incremented USERDATA)
[odbg] windowed_hello: style 3735928559   (0xDEADBEEF round-trip)
[odbg] windowed_hello: focus 7            (GetFocus = biased HWND)
[odbg] windowed_hello: caret+beep done
[I] sys : exit rc val=0x57
```

## Not yet wired

- **Modal dialogs** — DialogBox / EndDialog. Needs a nested
  pump + DialogProc dispatch.
- **Menus** — CreateMenu / AppendMenu / TrackPopupMenu return 0.
- **Common controls** — no edit / button / list / treeview.
- **Scroll bars** — no SB_* API, no WM_HSCROLL / WM_VSCROLL.
- **Icon / bitmap loading** — `LoadBitmap` etc. return 0.
- **Outline fonts** — only the 8×8 built-in font.
- **Multi-threaded message queues** — the per-pid filter handles
  one thread per process; a multi-threaded PE would see its
  threads' queues merged.

## Notes

- See also: [render-drivers-v6.md](render-drivers-v6.md) for the
  paint stack underneath the GDI surface.
- See also: [win32-stubs-rdi-rsi-abi.md](win32-stubs-rdi-rsi-abi.md)
  for the rdi/rsi callee-saved bug pattern that hit several of
  these stubs during bring-up.
