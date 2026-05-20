#include "display/window.h"
#include <windows.h>
#include <windowsx.h>
#include <chrono>
#include <cstring>

namespace duetos::vmm
{
static FbWindow* g_self = nullptr; // one VMM window per process

// PS/2 mouse motion coalescing window. Real PS/2 hardware delivers
// packets at ~40 Hz; modern hosts emit WM_MOUSEMOVE at 60-240 Hz
// matching their pointer polling rate. Pushing a 3-byte packet per
// Win32 event saturates the kernel's mouse-reader on a debug build
// (see the runaway-cpu / ring-full / soft-lockup chain we saw on
// 2026-05-19). Coalesce by accumulating dx/dy and only emitting on
// a button/wheel transition or once this many milliseconds have
// elapsed since the last emit.
//
// We deliberately throttle BELOW the PS/2 hardware rate (40 Hz) on
// debug builds — the kernel's per-packet dispatch + cursor update
// path on a software-FB Clang/UBSan/KASAN build costs ~25 ms per
// packet, so at 40 Hz mouse-reader saturates (98% of scheduler
// budget) and the compositor is left with no cycles to redraw
// (the "1 frame per 30 s" symptom from 2026-05-19 testing). 100 ms
// (10 Hz) leaves the compositor and other tasks comfortable headroom.
// Cursor lag is ~100 ms behind physical motion — fine for dev use.
constexpr int kMouseCoalesceMs = 100; // 10 Hz — sub-PS/2 cadence
                                      // matched to the debug
                                      // build's per-packet cost

static uint32_t MouseButtons(WPARAM w)
{
    uint32_t b = 0;
    if (w & MK_LBUTTON) b |= 1;
    if (w & MK_RBUTTON) b |= 2;
    if (w & MK_MBUTTON) b |= 4;
    return b;
}

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    FbWindow* s = g_self;
    static int lastX = -1, lastY = -1;
    // Coalesced PS/2 motion state — accumulates dx/dy across
    // WM_MOUSEMOVE events, flushes at kMouseCoalesceMs cadence OR
    // immediately on a button transition (so click position
    // matches release timing). See note at file scope.
    static int      accumDx     = 0;
    static int      accumDy     = 0;
    static uint32_t lastButtons = 0;
    using mouseClock = std::chrono::steady_clock;
    static auto     lastEmit    = mouseClock::now();
    switch (m)
    {
    case WM_TIMER:
        if (s && !IsIconic(h))
        {
            BITMAPINFO bi{};
            bi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
            bi.bmiHeader.biWidth       = (LONG)s->W();
            bi.bmiHeader.biHeight      = -(LONG)s->H(); // top-down
            bi.bmiHeader.biPlanes      = 1;
            bi.bmiHeader.biBitCount    = 32;
            bi.bmiHeader.biCompression = BI_RGB;
            RECT cr;
            GetClientRect(h, &cr);
            HDC dc = GetDC(h);
            StretchDIBits(dc, 0, 0, cr.right, cr.bottom, 0, 0,
                          s->W(), s->H(), s->Fb(), &bi,
                          DIB_RGB_COLORS, SRCCOPY);
            ReleaseDC(h, dc);
        }
        return 0;
    case WM_KEYDOWN:
    case WM_SYSKEYDOWN:
        if (s) s->Sink().onKey((uint32_t)w, true,  (l >> 24) & 1);
        return 0;
    case WM_KEYUP:
    case WM_SYSKEYUP:
        if (s) s->Sink().onKey((uint32_t)w, false, (l >> 24) & 1);
        return 0;
    case WM_MOUSEMOVE:
    {
        int x = GET_X_LPARAM(l), y = GET_Y_LPARAM(l);
        if (lastX < 0) { lastX = x; lastY = y; }
        accumDx += x - lastX;
        accumDy += y - lastY;
        lastX = x; lastY = y;

        const uint32_t btns = MouseButtons(w);
        const bool     btnChanged = (btns != lastButtons);
        const auto     now = mouseClock::now();
        const auto     elapsedMs = std::chrono::duration_cast<
            std::chrono::milliseconds>(now - lastEmit).count();

        // Flush on either: cadence boundary (and there's motion to
        // emit) OR a button state transition (must emit immediately
        // so click position lines up with the user's intent).
        if (btnChanged ||
            (elapsedMs >= kMouseCoalesceMs && (accumDx || accumDy)))
        {
            if (s) s->Sink().onMouse(accumDx, accumDy, btns, 0);
            accumDx = 0; accumDy = 0;
            lastButtons = btns;
            lastEmit = now;
        }
        return 0;
    }
    case WM_LBUTTONDOWN: case WM_LBUTTONUP:
    case WM_RBUTTONDOWN: case WM_RBUTTONUP:
    case WM_MBUTTONDOWN: case WM_MBUTTONUP:
    {
        // Flush any pending motion so the click delta arrives with
        // the button transition (not in a stale frame after it).
        const uint32_t btns = MouseButtons(w);
        if (s) s->Sink().onMouse(accumDx, accumDy, btns, 0);
        accumDx = 0; accumDy = 0;
        lastButtons = btns;
        lastEmit = mouseClock::now();
        return 0;
    }
    case WM_MOUSEWHEEL:
    {
        const uint32_t btns = MouseButtons(GET_KEYSTATE_WPARAM(w));
        const int      wheel = GET_WHEEL_DELTA_WPARAM(w) / WHEEL_DELTA;
        if (s) s->Sink().onMouse(accumDx, accumDy, btns, wheel);
        accumDx = 0; accumDy = 0;
        lastButtons = btns;
        lastEmit = mouseClock::now();
        return 0;
    }
    case WM_SETCURSOR:
        // Hide the host cursor while it's over the framebuffer
        // client area — the guest draws its own software cursor,
        // and two overlapping arrows is visually confusing. The
        // non-client frame (titlebar, resize edges) keeps the
        // default cursor so the operator can still drag / resize
        // the window normally.
        if (LOWORD(l) == HTCLIENT)
        {
            SetCursor(nullptr);
            return TRUE;
        }
        break; // fall through to DefWindowProcW for non-client
    case WM_CLOSE:
        if (s) s->FireClose();
        DestroyWindow(h);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(h, m, w, l);
}

bool FbWindow::Start(uint8_t* fb, uint32_t pitch, uint32_t wd, uint32_t ht,
                     const char* title, InputSink sink,
                     std::function<void()> onClose)
{
    m_fb = fb; m_pitch = pitch; m_w = wd; m_h = ht;
    m_sink = std::move(sink); m_onClose = std::move(onClose);
    g_self = this; m_run = true;
    m_thread = std::thread(&FbWindow::ThreadMain, this, title);
    return true;
}

void FbWindow::ThreadMain(const char* title)
{
    HINSTANCE inst = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = inst;
    wc.hCursor       = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512)); // IDC_ARROW
    wc.lpszClassName = L"DuetOSVmmWindow";
    RegisterClassW(&wc);

    RECT r{0, 0, (LONG)m_w, (LONG)m_h};
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    wchar_t wt[256];
    MultiByteToWideChar(CP_UTF8, 0, title, -1, wt, 256);
    HWND hwnd = CreateWindowW(wc.lpszClassName, wt, WS_OVERLAPPEDWINDOW,
                              CW_USEDEFAULT, CW_USEDEFAULT,
                              r.right - r.left, r.bottom - r.top,
                              nullptr, nullptr, inst, nullptr);
    m_hwnd = hwnd;
    ShowWindow(hwnd, SW_SHOWMINIMIZED);  // spec: start minimized
    SetTimer(hwnd, 1, 16, nullptr);      // ~60fps blit tick

    MSG msg;
    while (m_run.load() && GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    KillTimer(hwnd, 1);
    UnregisterClassW(wc.lpszClassName, inst);
}

void FbWindow::Stop()
{
    if (!m_run.exchange(false)) return;
    if (m_hwnd) PostMessageW((HWND)m_hwnd, WM_CLOSE, 0, 0);
    if (m_thread.joinable()) m_thread.join();
}

void FbWindow::SetTitle(const char* sIn)
{
    if (!m_hwnd) return;
    wchar_t wt[256];
    MultiByteToWideChar(CP_UTF8, 0, sIn, -1, wt, 256);
    SetWindowTextW((HWND)m_hwnd, wt);
}

FbWindow::~FbWindow() { Stop(); }
} // namespace duetos::vmm
