# Win32 windowing v1 — per-window message queues + GDI + input + reaper

**Last updated:** 2026-04-24
**Type:** Observation + Decision
**Status:** Landed — windowed_hello.exe creates a window, gets
reaped on exit end-to-end in a headless QEMU boot

## What shipped on top of v0

Windowing v0 (`win32-windowing-v0.md`) bridged
`CreateWindowExA/W` / `DestroyWindow` / `ShowWindow` /
`MessageBoxA` to the kernel compositor via SYS_WIN_* 58..61 but
left every follow-up slice listed in its knowledge entry as
TODO. v1 lands all four of them:

### 1. Per-window message queues — SYS 62 / 63 / 64

`RegisteredWindow` in `kernel/drivers/video/widget.cpp` gains a
bounded ring of `WindowMsg { hwnd_biased, message, wparam,
lparam }` — depth 32, oldest-dropped on overflow. Three new
syscalls wrap it:

| Syscall | # | Backs |
|---------|---|-------|
| `SYS_WIN_PEEK_MSG` | 62 | `user32!PeekMessageA/W` |
| `SYS_WIN_GET_MSG`  | 63 | `user32!GetMessageA/W` |
| `SYS_WIN_POST_MSG` | 64 | `user32!PostMessageA/W` |

`GetMessage` blocks inside the kernel via
`sched::SchedSleepTicks(1)` (10 ms grain at 100 Hz) — cheaper
than a full wait-queue and good enough for the first message-
pump workload. WM_QUIT is `0x0012` per Win32; dequeuing it makes
`GetMessage` return 0 so the caller's `while (GetMessage)` loop
exits cleanly. `PostQuitMessage` fans WM_QUIT out to every
window owned by the calling process (the kernel rejects cross-
pid posts, so stray targets become documented no-ops).

The user-space MSG struct is 48 bytes on x64 (HWND, UINT, u32
pad, WPARAM, LPARAM, DWORD time, POINT pt, DWORD lPrivate); the
kernel copies the first 32 bytes and `user32_zero_msg_tail`
zeroes the remaining 16 so callers see deterministic fields.

### 2. GDI client-area painting — SYS 65 / 66 / 67 / 68

Each window carries a **display list** of up to 32 recorded
primitives (`WinGdiPrim`). The compositor replays the list
inside the window's client rect on every `DesktopCompose` pass,
clipping to the rect. Oldest-dropped on overflow.

| Syscall | # | Backs |
|---------|---|-------|
| `SYS_GDI_FILL_RECT` | 65 | `gdi32!FillRect`, solid fill path |
| `SYS_GDI_TEXT_OUT`  | 66 | `gdi32!TextOutA/W`, `ExtTextOut*`, `DrawTextA` |
| `SYS_GDI_RECTANGLE` | 67 | `gdi32!Rectangle`, `FrameRect` |
| `SYS_GDI_CLEAR`     | 68 | `WM_PAINT` / `InvalidateRect` reset |

`GetDC(hWnd)` packs the HWND into the returned HDC sentinel
(`(HWND | 0xDC00000000)`), so subsequent GDI calls recover the
target window without a DC table. Brushes returned by
`CreateSolidBrush` / `CreateBrushIndirect` carry their COLORREF
in the bottom 24 bits tagged with `0xB0000000` — `FillRect` reads
it back. `CreateCompatibleDC` still returns a DC-only sentinel
(no backing bitmap); draws on it fall through to an HWND=0 miss.

**Colour conversion** happens at the syscall boundary:
`ColorRefToRgb` swaps `0x00BBGGRR` (Win32 COLORREF) to
`0x00RRGGBB` (framebuffer).

### 3. Input routing — keyboard reader in `core/main.cpp`

The kbd-reader task checks the active window's `owner_pid`
before falling through to kernel-app routing or the shell. When
the active window is a ring-3 PE (pid > 0):

- `WM_KEYDOWN` (0x0100) is posted with the raw scan/key code as
  wParam.
- Printable ASCII (0x20..0x7E), Enter ('\r' 0x0D), and Backspace
  (0x08) additionally post `WM_CHAR` (0x0102).

System shortcuts (Alt+Tab, Alt+F4, Ctrl+Alt+F1/F2/T/Y, ^C, the
login gate) still fire first and `continue` past this block —
PE windows can't hijack them. Mouse input still goes to the
native compositor (widgets, chrome close buttons, drag). A
follow-up slice adds `WM_LBUTTONDOWN` / `WM_MOUSEMOVE` routing.

### 4. Process-exit window reaper — `ProcessRelease`

`WindowReapByOwner(pid)` walks the compositor registry and
`WindowClose()`s every alive window with matching `owner_pid`.
`ProcessRelease` calls it under the compositor lock right before
freeing the AS reference. pid == 0 is refused so kernel-owned
boot windows (Calculator, Notepad, ...) are never collateral.

Verified end-to-end in QEMU:

```
[t=21237.985ms] [I] sys : exit rc   val=0x57
[proc] reap-windows pid=0x16 count=0x1
[proc] destroy pid=0x16 name="ring3-windowed-hello"
```

## Files touched

| File | Change |
|------|--------|
| `kernel/drivers/video/widget.{h,cpp}` | `RegisteredWindow` + owner_pid + msg ring + display list + reap helper |
| `kernel/subsystems/win32/window_syscall.{h,cpp}` | 7 new syscall handlers |
| `kernel/core/syscall.{h,cpp}` | Enum numbers 62..68 + dispatch cases |
| `kernel/core/process.cpp` | `ProcessRelease` calls `WindowReapByOwner` |
| `kernel/core/main.cpp` | kbd reader posts `WM_KEYDOWN` / `WM_CHAR` to active PE |
| `userland/libs/user32/user32.c` | Real `GetMessage` / `PeekMessage` / `PostMessage` / `PostQuitMessage` |
| `userland/libs/gdi32/gdi32.c` | Real `FillRect` / `TextOut*` / `Rectangle` / `FrameRect` / `DrawTextA` |

## v1.1 follow-up — mouse routing + blocking GetMessage + SW_HIDE + real geometry

A second pass on the same branch landed:

### Mouse message routing

The mouse reader in `core/main.cpp` now posts
`WM_MOUSEMOVE` / `WM_LBUTTONDOWN` / `WM_LBUTTONUP` /
`WM_RBUTTONDOWN` / `WM_RBUTTONUP` to the topmost PE window
under the cursor. Coordinates are client-local; `lParam` packs
`MAKELONG(x, y)`; `wParam` carries `MK_LBUTTON` /
`MK_RBUTTON`. Skipped in the obvious shell-owned states (menu
open, drag active, over taskbar / calendar). Close-box clicks
on a PE-owned window now post `WM_CLOSE` instead of firing
`WindowClose` directly — the PE decides whether to call
`DestroyWindow`. Kernel-owned boot windows (Calculator,
Notepad, ...) still close immediately (no PE to delegate to).

### Blocking GetMessage with WaitQueue + timeout

`SYS_WIN_GET_MSG` now blocks on a global `sched::WaitQueue`
(`g_msg_wq`) via `WindowMsgWaitBlockTimeout(1)` instead of
polling `SchedSleepTicks(1)`. The keyboard reader, mouse
reader, and `SYS_WIN_POST_MSG` all broadcast
`WindowMsgWakeAll()` after appending a message. The 1-tick
(10 ms) timeout on the block is a safety net against a lost
wake in the narrow window between "check queue empty" and
"enter wait queue" — a proper condvar fix would require holding
the wait-queue lock while dropping the compositor lock (larger
refactor). In practice wakes are near-immediate; the poll is
only the safety backstop.

### SW_HIDE is now re-showable

`RegisteredWindow` gains a `visible` bit; `WindowDrawAllOrdered`
and `WindowTopmostAt` skip invisible windows; `SW_HIDE`
(cmd == 0) now calls `WindowSetVisible(h, false)` instead of
closing the slot. A follow-up `ShowWindow(h, SW_SHOW)` sets
visible again and raises the window. `ShowWindow` also now
returns the previous visibility state as its `BOOL` per Win32.

### Real window geometry + title — SYS 69 / 70 / 71

| Syscall | # | Backs |
|---------|---|-------|
| `SYS_WIN_MOVE`     | 69 | `user32!MoveWindow` + `SetWindowPos` (x/y/w/h + flags) |
| `SYS_WIN_GET_RECT` | 70 | `user32!GetWindowRect` / `GetClientRect` / `IsWindow` |
| `SYS_WIN_SET_TEXT` | 71 | `user32!SetWindowTextA` / `SetWindowTextW` |

Windows now copy their title into a per-window `mut_title[64]`
buffer at register time (replaces the by-reference v0 contract
+ external `g_title_arena`); `SetWindowText` overwrites the
same buffer so the pointer stays stable. `IsWindow` piggybacks
on `SYS_WIN_GET_RECT` — the syscall returns 0 iff the handle
is either unknown or owned by a different process, which is
exactly the Win32 IsWindow contract.

## What this does NOT do yet

- **WndProc dispatch.** `DispatchMessageA/W` still returns 0 —
  we don't have a per-window WndProc table and the stubbed
  `RegisterClass*` drops the class metadata. A program that
  handles `WM_PAINT` in its WndProc gets no call; it must paint
  imperatively in its main loop instead. Wiring this requires a
  per-class `lpfnWndProc` table + a ring-3 trampoline so the
  kernel can invoke user code from `DispatchMessage`.
- **WM_PAINT.** The compositor doesn't send it; programs that
  key redraws off WM_PAINT see nothing. `TextOut` calls made
  from the main loop directly do work.
- **Cross-process PostMessage.** Refused at the kernel — the
  HWND must be owned by the caller. Win32 allows cross-process
  in limited circumstances; a future IPC gate can enable it.
- **Clipping between overlapping windows.** A windowed PE's
  display-list primitives still paint over the window
  underneath; clipping respects the window's client rect but
  not the z-order occluders above. Fine for topmost windows
  (the common case); a future slice redraws windows' primitives
  only inside their visible region.
- **Mouse capture (SetCapture / ReleaseCapture).** Not
  implemented — mouse messages always route to the topmost
  window under the cursor even if a PE wanted to track drags
  outside its bounds.

## Storage shape

- `kMaxWindows == 16` (unchanged). Per window: 32 messages × 24
  bytes + 32 primitives × 72 bytes ≈ 3 KiB. Total ≈ 48 KiB in
  `.bss` for the whole registry — comfortable.
- Display list is an append-with-eviction ring (circular shift
  on overflow). Could be upgraded to a dynamic buffer when a
  workload demands it.

## Follow-ups next in rough size order

1. `WM_LBUTTONDOWN` / mouse routing to active PE window (one
   block in the ps2mouse reader, mirroring the keyboard one).
2. Real `sched::WaitQueue` wake in `DoWinGetMsg` (replace the
   10 ms poll). Per-process queue head in `Process` struct;
   `PostMessage` wakes the queue.
3. WndProc dispatch — per-class lpfnWndProc + ring-3 callback
   trampoline so `DispatchMessage` reaches user code.
4. Per-window backing bitmap + `WM_PAINT` on
   compose-invalidation — replaces the display-list replay with
   blit-from-surface.
5. SW_HIDE that's re-showable (add `visible` bit to the widget
   registry slot; current implementation collapses to Destroy).
