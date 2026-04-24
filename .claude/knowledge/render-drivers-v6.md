# render/drivers v6 — message loop + filled primitives + UTF-16 text + sys palette

**Last updated:** 2026-04-24
**Type:** Observation + Decision
**Status:** Active — a functional Win32 GUI app runs on the
desktop. Mouse + keyboard events reach the PE's WndProc;
Rectangle / Ellipse / DrawText / TextOutW produce expected
pixels; GetSysColor returns Classic-theme values.

## The headline: PE message loops now work

Every Win32 GUI tutorial ever written centers on this boilerplate:

```c
MSG msg;
while (GetMessage(&msg, NULL, 0, 0)) {
    TranslateMessage(&msg);
    DispatchMessage(&msg);
}
```

Before v6: `GetMessageA` returned 0 on the first call (dummy
`kOffReturnZero` stub), so every PE exited its message loop
immediately — no input, no paint, no interaction.

After v6:
- `GetMessageA/W` → `SYS_WIN_GET_MSG` (63). Blocks (10 ms granularity)
  until the window's message ring has something.
- `PeekMessageA/W` → `SYS_WIN_PEEK_MSG` (62). Non-blocking.
- `DispatchMessageA/W` → custom 60-byte stub that looks up the
  window's registered WndProc via `SYS_WIN_GET_LONG(hwnd, 0)` and
  calls it directly: `wndproc(hwnd, msg, wparam, lparam)`. The
  call happens entirely in user mode — no kernel bounce.
- `TranslateMessage` stays at `kOffReturnZero` because our PS/2
  keyboard reader already posts `WM_CHAR` directly after
  `WM_KEYDOWN`.

Input routing was already fully wired in v1.2–v1.4 (mouse clicks
→ WM_LBUTTONDOWN with client coords, key events → WM_KEYDOWN +
WM_CHAR, focus tracking, capture). The syscall bridge being absent
made it all invisible to PEs.

## Filled primitives + DC brush state

Win32 `Rectangle` / `Ellipse` / `PatBlt` fill with the DC's
currently-selected brush and outline with the selected pen. The v5
outline-only stubs were visually wrong for most apps.

- `MemDC` + `WindowDcState` grew a `selected_brush` field;
  `SelectObject(hdc, hbrush)` now stores it for both kinds of DC.
- `ResolveBrushColor(hdc)` is the sibling of `ResolvePenColor` —
  returns `WHITE_BRUSH` (0xFFFFFF) when no selection.
- `SYS_GDI_RECTANGLE_FILLED` (122): fills rect body with brush,
  draws outline with pen. Window path records FillRect + Rectangle
  display-list prims; memDC path paints the bitmap + 4 Bresenham
  edges.
- `SYS_GDI_ELLIPSE_FILLED` (123): bounding-box scan with the
  integer-ellipse test `(x-cx)² * b² + (y-cy)² * a² ≤ a²·b²`. No
  sqrt. memDC fill is real; window path still outline-only
  because the compositor lacks a FilledEllipse prim (documented
  gap, not a blocker for most apps since most fills happen on
  memDCs anyway via the double-buffered paint pattern).
- `SYS_GDI_PAT_BLT` (124): rect fill with DC brush. ROP ignored —
  always `PATCOPY` semantics.

## UTF-16 text — TextOutW + DrawTextW

Many modern PEs (especially anything MSVC-compiled with
`UNICODE`) import `gdi32.TextOutW` / `DrawTextW` instead of the A
variants. Before v6 these returned dummy 1 and drew nothing.

Implementation:
- `SYS_GDI_TEXT_OUT_W` (125) + `SYS_GDI_DRAW_TEXT_W` (126).
- Kernel reads the UTF-16 source into an on-stack buffer, walks
  it u16-by-u16, and produces an ASCII string where each wchar_t
  is either `(char)wc` if `wc < 0x80` or `'?'` for non-ASCII.
  We don't implement real Unicode rendering yet; the `?`
  placeholder means a Unicode-heavy PE gets question marks
  instead of the correct glyphs, but ASCII-heavy PEs (including
  all English UI strings from Windows apps) render correctly.
- `DrawTextAsciiOnDc` helper — the alignment + dispatch core
  from `DoGdiDrawText` was extracted so both A and W variants
  share it after their respective copy-ins.

## Stub page outgrew one page — now 2 × 4 KiB

TextOutW at 31 bytes would have pushed us past 4096. Two choices:
compact existing stubs (painful, offset churn) or expand. We
expanded:

- `pe_loader.cpp:PeLoad` now calls `AllocateContiguousFrames(2)`
  and maps both pages R-X at `kWin32StubsVa + 0` and
  `kWin32StubsVa + 0x1000`.
- The `static_assert` bumped from `<= 4096` to `<= 8192`. Current
  end: `0x1048` = 4168 bytes; ~50 % of the second page free.
- `Win32StubsPopulate(dst)` already uses `sizeof(kStubsBytes)` so
  the copy loop doesn't need changes.

## System palette — GetSysColor + GetSysColorBrush

Win32 apps query the system palette to avoid hard-coding colours
(`GetSysColor(COLOR_WINDOW)` vs. `RGB(255,255,255)` directly).
Returning 0 made every UI element look broken.

- 31-entry Classic-theme palette table covers
  `COLOR_SCROLLBAR` (0) through `COLOR_MENUBAR` (30).
- `GdiSysColorBrush(idx)` lazily allocates a real HBRUSH the
  first time each palette slot is queried, caches the handle,
  and sets `.stock = true` so `DeleteObject` is a safe no-op.

A PE calling `GetSysColor(COLOR_BTNFACE)` now gets `0x00F0F0F0`
(Classic grey); `GetSysColorBrush(COLOR_HIGHLIGHT)` returns a
reusable HBRUSH with the Classic selection blue.

## End-to-end: what a real PE now does

Consider a typical "Notepad-style" skeleton:

```c
LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(h, &ps);
        FillRect(hdc, &ps.rcPaint, GetSysColorBrush(COLOR_WINDOW));
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));
        RECT r = {10, 10, 300, 40};
        DrawTextW(hdc, L"Hello, DuetOS!", -1, &r,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        Rectangle(hdc, 10, 60, 290, 120);   // filled + outlined
        EndPaint(h, &ps);
        return 0;
    }
    case WM_LBUTTONDOWN:
        MessageBoxA(h, "You clicked!", "Hi", MB_OK);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(h, m, w, l);
}

int WINAPI WinMain(...) {
    WNDCLASSEX wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hbrBackground = GetSysColorBrush(COLOR_WINDOW);
    wc.lpszClassName = "MyApp";
    RegisterClassExA(&wc);
    HWND h = CreateWindowExA(0, "MyApp", "Title", WS_OVERLAPPEDWINDOW,
                             CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
                             NULL, NULL, hInst, NULL);
    ShowWindow(h, SW_SHOWNORMAL);
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return 0;
}
```

Every call above now has a real backing:

- `RegisterClassExA` / `CreateWindowExA` / `ShowWindow` — v1.x
- `GetMessage` → real (v6)
- `DispatchMessage` → WndProc is called (v6)
- `BeginPaint` / `EndPaint` → v3
- `FillRect` (with HBRUSH from GetSysColorBrush) → v3+v6
- `SetBkMode` / `SetTextColor` → v4
- `DrawTextW` with alignment → v5+v6
- `Rectangle` filled → v6
- `MessageBoxA` / `PostQuitMessage` → v1.x
- The click fires `WM_LBUTTONDOWN` that the WndProc sees → v1.2+v6

## Still ahead

- Window-DC filled-ellipse prim (needs FilledEllipse display-list entry)
- Real Unicode rendering (non-ASCII `?` placeholder for now)
- Pen width > 1 (thick lines)
- DT_WORDBREAK + multi-line DrawText
- SetDIBits / StretchDIBits for raw pixel upload
- GetSystemMetrics returning sensible per-index values
  (currently all 0)

## References

- `kernel/subsystems/win32/stubs.cpp` — offsets 0xF41..0x1047
  covering message loop, filled primitives, UTF-16 text, palette.
- `kernel/subsystems/win32/gdi_objects.{h,cpp}` — brush tracking,
  filled primitive handlers, sys-palette table + brush pool.
- `kernel/subsystems/win32/window_syscall.cpp` — DoGdiTextOutW,
  DoGdiDrawTextW, DrawTextAsciiOnDc helper.
- `kernel/core/syscall.h` — SYS_GDI_RECTANGLE_FILLED (122) through
  SYS_GDI_GET_SYS_COLOR_BRUSH (128).
- `kernel/core/pe_loader.cpp:1247` — stubs page expanded to two
  contiguous 4 KiB frames.
