# Win32 windowing v0 — user32 → SYS_WIN_* → compositor bridge

**Last updated:** 2026-04-24
**Type:** Observation + Decision
**Status:** Landed — first PE-created window painting end-to-end

## What shipped

Four new syscalls in the 58..61 range bridge `user32.dll`'s
window-lifecycle + message-box stubs into the kernel compositor in
`kernel/drivers/video/widget.{h,cpp}`:

| Syscall | # | Backs |
|---------|---|-------|
| `SYS_WIN_CREATE` | 58 | `user32!CreateWindowExA` / `CreateWindowExW` |
| `SYS_WIN_DESTROY` | 59 | `user32!DestroyWindow` |
| `SYS_WIN_SHOW` | 60 | `user32!ShowWindow` (SW_HIDE == close; anything else == raise) |
| `SYS_WIN_MSGBOX` | 61 | `user32!MessageBoxA` / `MessageBoxW` / `MessageBoxExA/W` (serial-logged surrogate; returns IDOK) |

Handlers live in `kernel/subsystems/win32/window_syscall.{h,cpp}`. The
W variants in `userland/libs/user32/user32.c` translate UTF-16 to
ASCII (`'?'` for non-ASCII code units) then call the same kernel
entry as the A variants.

## Geometry of the change

```
Ring-3 PE (windowed_hello.exe)
    │  CALL [IAT:CreateWindowExA]
    ▼
user32.dll (userland/libs/user32/user32.c)
    │  int $0x80, rax=58, rdi=x, rsi=y, rdx=w, r10=h, r8=title
    ▼
SyscallDispatch (kernel/core/syscall.cpp)
    │
    ▼
DoWinCreate (kernel/subsystems/win32/window_syscall.cpp)
    │  CompositorLock → CopyUserString(title) → WindowRegister → DesktopCompose → CompositorUnlock
    ▼
Compositor (kernel/drivers/video/widget.cpp)
    │  paints on next compose tick
    ▼
Framebuffer
```

## HWND bias

Compositor handles are 0-based indices. Win32 callers check
`hwnd != NULL`, so we return `(compositor_handle + 1)` as the HWND.
The kernel unbiases on DESTROY / SHOW. `kHwndBias = 1` in
`window_syscall.cpp`.

## Title-string lifetime

`WindowRegister(chrome, title)` stores the title pointer by reference
— the kernel never copies the string. Ring-3 memory can't be held
across scheduler switches, so `DoWinCreate` copies the user's title
into a per-slot arena `g_title_arena[kMaxWindows][kWinTitleMax+1]`
and hands `WindowRegister` the arena slot's address. The arena is
deliberately not freed on DESTROY for v0 (the widget-layer registry
itself is append-only).

## Other changes

1. **`kMaxWindows` bumped 6 → 16** (`kernel/drivers/video/widget.h`)
   — boot apps (Calculator, Notepad, Task Manager, Kernel Log, Files,
   Clock) already consumed all 6 slots; ring-3 PEs had no room.
   Static arrays in widget.cpp / taskbar.cpp (`kMaxTabs = 8`) still
   fit fine in .bss. The taskbar doesn't show PE windows past the
   8th slot — acceptable for v0.
2. **Framebuffer-absent fallback** — if `FramebufferGet()` reports
   zero dimensions (serial-only boot), the geometry clamp uses a
   notional 1024×768 canvas so the syscall round-trip is still
   testable from the serial log even without a display.

## Verification

`/bin/windowed_hello.exe` (new fixture — see
`userland/apps/windowed_hello/`) imports `CreateWindowExA` +
`ShowWindow` + `MessageBoxA` from `user32.dll` and `Sleep` +
`ExitProcess` from `kernel32.dll`. On boot:

```
[msgbox] pid=0x16 caption="Windowed Hello" text="Running on DuetOS!"
[win] create pid=0x16 hwnd=7 rect=(500,400 420x220) title="WINDOWED HELLO"
[I] sys : exit rc val=0x57                    # 0x57 = distinctive exit
```

The window is visible in `docs/screenshots/07-windowed-hello.png`
(captured via `screenshot-theme.sh 5` — entry 5 is
"Desktop Classic (autologin)", which skips the login gate and drops
straight into the desktop compose).

## What this does NOT do

- No per-window message queue yet. `GetMessage` / `PeekMessage` still
  return WM_QUIT (0 for GetMessage, FALSE for PeekMessage) so
  event-pump programs exit immediately. Per-window input queues
  + `PostMessage` dispatch are a separate slice.
- No GDI painting into the client area yet. `gdi32!BitBlt` /
  `TextOut` / `Rectangle` / `FillRect` are still silent no-ops.
  A real implementation needs the compositor to expose a per-window
  backing surface and the `HDC` to mint a handle into it.
- No keyboard/mouse routing to the target window. PS/2 + xHCI
  keyboard input still goes to the native console.
- No SW_SHOWNORMAL-as-reshow path. `SW_HIDE` is implemented as
  destroy (window visually leaves, can't be re-shown). Proper hide
  requires a `visible` flag on the widget-layer slot.
- No process-exit reaping of leaked windows. If a PE creates a
  window and exits without DestroyWindow, the slot is leaked until
  reboot (kMaxWindows=16 gives budget for many exits before the
  compositor fills up).

## Follow-up slices in rough size order

1. Process-exit window reaper (bounded — walk per-process window
   list, call WindowClose on each).
2. SW_HIDE re-showable — add `visible` bit to RegisteredWindow,
   branch DesktopCompose / hit-testing on it.
3. Per-window message queue — finite-depth ring per HWND, kernel
   side of `PostMessage` enqueues, `GetMessage` dequeues or blocks.
4. Keyboard focus routing — on Alt+Tab / click, record which HWND
   owns focus; keyboard reader posts WM_KEYDOWN / WM_CHAR to that
   queue instead of the native console.
5. GDI v0 — per-window backing surface allocated in the kernel
   heap; `GetDC` returns an HDC that indexes into a per-process DC
   table; `TextOutA` paints into the surface; `InvalidateRect` +
   next compose blits the surface.
