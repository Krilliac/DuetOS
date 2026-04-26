# Native DuetOS apps v0 — pattern for in-kernel applications

**Last updated:** 2026-04-21
**Type:** Pattern
**Status:** Active

## Description

DuetOS has an in-kernel widget system (windows, buttons,
taskbar, content-draw callbacks, 1 Hz compositor tick). This
entry documents the **pattern** an in-kernel "app" follows so
new apps slot in cleanly without bespoke wiring each time.

Applies to kernel-resident apps only. Once a tier-2 syscall ABI
for ring-3 apps lands, a second entry supersedes this one for
user-mode apps.

## Context

Lives under `kernel/apps/`. Current occupants:

- `notes.{h,cpp}`           — linear text buffer, keyboard-only.
- `calculator.{h,cpp}`      — 4x4 keypad, keyboard + mouse.

Build-system plumbing: each app adds one line to the
`DUETOS_KERNEL_SHARED_SOURCES` list in `kernel/CMakeLists.txt`
(alphabetised within the `apps/` section).

## Approach

### 1. Each app is a leaf module

```
kernel/apps/<appname>.h    — public entry points.
kernel/apps/<appname>.cpp  — state + logic + draw callback.
```

No cross-app dependencies. An app may call into
`drivers/video/` (framebuffer, widget), `arch/x86_64/serial`
(boot log), and pure utilities. It must **not** reach into
another app's translation unit — if two apps need shared code,
promote it into a neutral helper header first.

### 2. Public API shape

```cpp
namespace duetos::apps::<appname>
{

/// One-shot init: bind to a window handle, install content-
/// draw callback, register any widgets, seed initial state.
void <App>Init(drivers::video::WindowHandle handle);

/// Handle accessor, used by input routers to decide when a
/// key / click is for this app.
drivers::video::WindowHandle <App>Window();

/// Keyboard handler. Returns true iff the char was consumed.
bool <App>FeedChar(char c);

/// (Optional) Widget event handler for apps that register
/// buttons. Returns true iff the id is claimed.
bool <App>OnWidgetEvent(u32 id);

/// (Optional) Boot-time self-test that prints one PASS/FAIL
/// line to COM1, exercising the logic along a known path.
void <App>SelfTest();

} // namespace
```

### 3. Wiring in `kernel/core/main.cpp`

Three integration points:

**Window registration + Init** — inside the GUI bring-up block:

```cpp
WindowChrome chrome{ ... };
const auto handle = WindowRegister(chrome, "APPNAME");
apps::<appname>::<App>Init(handle);
apps::<appname>::<App>SelfTest();   // optional
```

**Keyboard routing** — inside `kbd_reader`'s app-routing block
(before the shell-feed branches):

```cpp
if (active == apps::<appname>::<App>Window()) {
    if (char c = translate(ev); c != 0) {
        app_consumed = apps::<appname>::<App>FeedChar(c);
    }
}
```

All feeds happen under `CompositorLock()`.

**Mouse routing** — inside the `mouse_reader` widget-hit block:

```cpp
if (hit != kWidgetInvalid) {
    apps::<appname>::<App>OnWidgetEvent(hit);
}
```

### 4. Widget ID ranges

Each app that registers widgets picks a private 16-bit ID base
inside the u32 space. Conventions so far:

| App | `kIdBase` | `kIdCount` |
|---|---|---|
| Calculator | `0x1000` | `16` |

Pick the next free 0x1000-aligned slot for the next app. The
widget layer is oblivious to the partitioning — apps only use
the base to reject hits that aren't theirs.

### 5. Thread-safety contract

- State mutation happens under the compositor lock. The
  kbd-reader and mouse-reader threads lock before calling the
  app; the ui-ticker holds the lock while invoking the
  content-draw callback.
- App functions may read their own `g_state` without additional
  locking — the caller holds it.
- App functions **must not** call `DesktopCompose` themselves.
  The input-router thread does that after the feed returns.

### 6. Content-draw callback shape

```cpp
void DrawFn(u32 cx, u32 cy, u32 cw, u32 ch, void* cookie)
{
    // cx/cy is the top-left of the client area (post-chrome).
    // cw/ch is the client-area size.
    // Draw inside [cx, cx+cw) × [cy, cy+ch) only.
    // Caller holds the compositor lock.
    // Widgets owned by this window paint AFTER this callback,
    // so widgets visually overlay content.
}
```

Typical apps:
- Paint a background fill over the client area with the window's
  `colour_client`.
- Draw content using `FramebufferDrawChar` / `FramebufferDrawString`
  (8x8 font, 10 px row stride is the house standard).

### 7. Boot-time self-test pattern

Every app with non-trivial logic (calculator's arithmetic,
notes' buffer cap, future file-list filtering) runs a
self-test at boot that prints `[<app>] self-test OK (...)` or
`[<app>] self-test FAILED`. The ctest smoke harness asserts
the OK line as an expected signature, catching regressions
without needing any user interaction.

See `tools/test/ctest-boot-smoke.sh` — each app adds one line to
the `expected` array once its self-test runs.

## Notes

- **kMaxWidgets** in `drivers/video/widget.cpp` caps the total
  button count across all apps at 32 today. If a future app
  needs more, bump there (comment at the array declaration
  tracks current consumers).
- **kMaxWindows** is 4 today. Notepad, Calculator, Task Manager,
  Kernel Log fill all four slots — the next app must either
  close one or bump `kMaxWindows`. Bumping is cheap (flat
  arrays in `widget.cpp`).
- **Keyboard routing precedence**: app > shell. When the
  active window is an app with a keyboard handler, Backspace
  / Enter / printable ASCII all go to the app; the shell sees
  nothing. Alt+Tab / Alt+F4 / Ctrl+Alt+F1-F2 / Ctrl+Alt+T
  intercept first and are not app-routable.
- **Migrating to ring 3**: once a tier-2 syscall ABI exists,
  the `<App>FeedChar` / `<App>OnWidgetEvent` callback shape
  becomes "post event to process, wait for paint buffer back."
  Apps designed against this in-kernel pattern should migrate
  with mechanical changes only — the logic stays put, the
  thread-safety boundary moves from `CompositorLock()` to an
  event-queue syscall.
- **See also:**
  - `win32-subsystem-v0.md` — different kind of "app" (real
    Windows PE) with its own subsystem. Not the same track.
  - `rust-bringup-plan.md` — apps will stay C++ for now;
    Rust is reserved for parsing-heavy subsystems.
