#include "display/window.h"
#include <windows.h>
#include <windowsx.h>
#include <cstring>

namespace duetos::vmm
{
static FbWindow* g_self = nullptr; // one VMM window per process

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
        if (s) s->Sink().onMouse(x - lastX, y - lastY,
                                 MouseButtons(w), 0);
        lastX = x; lastY = y;
        return 0;
    }
    case WM_LBUTTONDOWN: case WM_LBUTTONUP:
    case WM_RBUTTONDOWN: case WM_RBUTTONUP:
    case WM_MBUTTONDOWN: case WM_MBUTTONUP:
        if (s) s->Sink().onMouse(0, 0, MouseButtons(w), 0);
        return 0;
    case WM_MOUSEWHEEL:
        if (s) s->Sink().onMouse(0, 0, MouseButtons(GET_KEYSTATE_WPARAM(w)),
                                 GET_WHEEL_DELTA_WPARAM(w) / WHEEL_DELTA);
        return 0;
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
