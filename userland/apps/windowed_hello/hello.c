/*
 * userland/apps/windowed_hello/hello.c
 *
 * Exercises the windowing subsystem end-to-end: compositor
 * window, message pump, GDI paint, SetTimer, WM_CLOSE graceful
 * shutdown. Also serves as the screenshot-capture fixture — the
 * final `Sleep(20s)` gives the screenshot script's settle window
 * time to grab the painted client area.
 *
 * Expected serial log signature:
 *   [msgbox] pid=... caption="Windowed Hello" text="Running on DuetOS!"
 *   [win] create pid=... hwnd=N rect=(x,y WxH) title="WINDOWED HELLO"
 *   [odbg] windowed_hello: paint done
 *   [odbg] windowed_hello: pumped N messages
 *   [I] sys : exit rc val=0x57
 */

typedef void* HANDLE;
typedef void* HDC;
typedef void* HBRUSH;
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef unsigned int COLORREF;
typedef int BOOL;
typedef unsigned long long WPARAM;
typedef unsigned long long LPARAM;
typedef unsigned long long LRESULT;

typedef struct
{
    HANDLE hwnd;
    UINT message;
    UINT _pad;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    int pt_x;
    int pt_y;
    DWORD lPrivate;
} MSG;

typedef struct
{
    int left, top, right, bottom;
} RECT;

#define CW_USEDEFAULT ((int)0x80000000)
#define SW_SHOW 5
#define WS_OVERLAPPEDWINDOW 0x00CF0000u
#define WM_QUIT 0x0012
#define WM_CLOSE 0x0010
#define WM_TIMER 0x0113
#define PM_REMOVE 1

#define RGB(r, g, b) ((COLORREF)(((unsigned)(r)) | (((unsigned)(g)) << 8) | (((unsigned)(b)) << 16)))

typedef unsigned short ATOM;
typedef LRESULT(__stdcall* WNDPROC)(HANDLE hwnd, UINT msg, WPARAM w, LPARAM l);

typedef struct
{
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HANDLE hInstance;
    HANDLE hIcon;
    HANDLE hCursor;
    HANDLE hbrBackground;
    const char* lpszMenuName;
    const char* lpszClassName;
} WNDCLASSA;

__declspec(dllimport) ATOM __stdcall RegisterClassA(const WNDCLASSA* wc);
__declspec(dllimport) HANDLE __stdcall CreateWindowExA(DWORD dwExStyle, const char* lpClassName,
                                                       const char* lpWindowName, DWORD dwStyle, int x, int y,
                                                       int nWidth, int nHeight, HANDLE hWndParent, HANDLE hMenu,
                                                       HANDLE hInstance, void* lpParam);
__declspec(dllimport) BOOL __stdcall ShowWindow(HANDLE hWnd, int nCmdShow);
__declspec(dllimport) BOOL __stdcall InvalidateRect(HANDLE h, const void* r, BOOL erase);
__declspec(dllimport) int __stdcall GetSystemMetrics(int index);
__declspec(dllimport) HANDLE __stdcall GetActiveWindow(void);
__declspec(dllimport) BOOL __stdcall ScreenToClient(HANDLE h, void* pt);
__declspec(dllimport) long long __stdcall SetWindowLongPtrA(HANDLE h, int index, long long value);
__declspec(dllimport) long long __stdcall GetWindowLongPtrA(HANDLE h, int index);
#define GWLP_USERDATA 1
__declspec(dllimport) int __stdcall MessageBoxA(HANDLE hWnd, const char* lpText, const char* lpCaption, UINT uType);
__declspec(dllimport) BOOL __stdcall GetMessageA(MSG* msg, HANDLE h, UINT min, UINT max);
__declspec(dllimport) BOOL __stdcall PeekMessageA(MSG* msg, HANDLE h, UINT min, UINT max, UINT flags);
__declspec(dllimport) BOOL __stdcall TranslateMessage(const MSG* msg);
__declspec(dllimport) long long __stdcall DispatchMessageA(const MSG* msg);
__declspec(dllimport) unsigned long long __stdcall SetTimer(HANDLE h, unsigned long long id, UINT elapse, void* cb);
__declspec(dllimport) BOOL __stdcall KillTimer(HANDLE h, unsigned long long id);
__declspec(dllimport) BOOL __stdcall DestroyWindow(HANDLE h);

__declspec(dllimport) HDC __stdcall GetDC(HANDLE hWnd);
__declspec(dllimport) int __stdcall ReleaseDC(HANDLE hWnd, HDC dc);
__declspec(dllimport) HBRUSH __stdcall CreateSolidBrush(COLORREF clr);
__declspec(dllimport) BOOL __stdcall DeleteObject(void* obj);
__declspec(dllimport) int __stdcall FillRect(HDC dc, const RECT* r, HBRUSH br);
__declspec(dllimport) BOOL __stdcall Rectangle(HDC dc, int l, int t, int r, int b);
__declspec(dllimport) BOOL __stdcall Ellipse(HDC dc, int l, int t, int r, int b);
__declspec(dllimport) BOOL __stdcall LineTo(HDC dc, int x, int y);
__declspec(dllimport) BOOL __stdcall MoveToEx(HDC dc, int x, int y, void* prev);
__declspec(dllimport) BOOL __stdcall TextOutA(HDC dc, int x, int y, const char* text, int len);
__declspec(dllimport) COLORREF __stdcall SetPixel(HDC dc, int x, int y, COLORREF col);

__declspec(dllimport) void __stdcall Sleep(DWORD dwMilliseconds);
__declspec(dllimport) void __stdcall ExitProcess(unsigned int uExitCode);
__declspec(dllimport) void __stdcall OutputDebugStringA(const char* s);

static int str_len(const char* s)
{
    int n = 0;
    while (s[n])
        ++n;
    return n;
}

static void dbg_uint(const char* prefix, unsigned v)
{
    /* Tiny printf for [odbg] logging. Max 16 decimal digits. */
    char buf[64];
    int n = 0;
    while (prefix[n] && n < 40)
    {
        buf[n] = prefix[n];
        ++n;
    }
    /* Reverse-print v. */
    char digits[16];
    int d = 0;
    if (v == 0)
    {
        digits[d++] = '0';
    }
    while (v > 0 && d < 16)
    {
        digits[d++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (d > 0 && n < 62)
    {
        buf[n++] = digits[--d];
    }
    buf[n++] = '\n';
    buf[n] = '\0';
    OutputDebugStringA(buf);
}

/* WndProc: routes messages via DispatchMessageA. Counts
 * WM_TIMERs received — the counter is stored in GWLP_USERDATA
 * so both the WndProc and main can read it, proving the
 * SetWindowLongPtr round-trip works. */
static LRESULT __stdcall duet_wndproc(HANDLE hwnd, UINT msg, WPARAM w, LPARAM l)
{
    (void)w;
    (void)l;
    if (msg == WM_TIMER)
    {
        long long prev = GetWindowLongPtrA(hwnd, GWLP_USERDATA);
        SetWindowLongPtrA(hwnd, GWLP_USERDATA, prev + 1);
    }
    return 0;
}

void mainCRTStartup(void)
{
    MessageBoxA(0, "Running on DuetOS!", "Windowed Hello", 0);

    WNDCLASSA wc = {0};
    wc.lpfnWndProc = duet_wndproc;
    wc.lpszClassName = "DuetWindow";
    RegisterClassA(&wc);

    /* Log a GetSystemMetrics call to prove the metric syscall
     * reaches the framebuffer dims (non-zero). */
    int screen_w = GetSystemMetrics(0 /* SM_CXSCREEN */);
    int screen_h = GetSystemMetrics(1 /* SM_CYSCREEN */);
    dbg_uint("[odbg] windowed_hello: screen w=", (unsigned)screen_w);
    dbg_uint("[odbg] windowed_hello: screen h=", (unsigned)screen_h);

    HANDLE hwnd =
        CreateWindowExA(0, "DuetWindow", "WINDOWED HELLO", WS_OVERLAPPEDWINDOW, 500, 400, 420, 220, 0, 0, 0, 0);

    if (hwnd)
    {
        ShowWindow(hwnd, SW_SHOW);

        /* Paint the client area via gdi32 primitives: bridges
         * FillRect + Rectangle + Ellipse + LineTo + TextOut to
         * the kernel's per-window display list. */
        HDC dc = GetDC(hwnd);
        if (dc)
        {
            /* Background wash. Brush tag carries the COLORREF in
             * its low 24 bits so the kernel side can recover. */
            HBRUSH bg = CreateSolidBrush(RGB(0x20, 0x30, 0x50));
            RECT client = {0, 0, 412, 192};
            FillRect(dc, &client, bg);
            DeleteObject(bg);

            /* 1-px outline rectangle + diagonal lines + ellipse
             * — proves Line / Ellipse reach the compositor. */
            Rectangle(dc, 10, 10, 200, 80);
            MoveToEx(dc, 10, 10, 0);
            LineTo(dc, 200, 80);
            MoveToEx(dc, 200, 10, 0);
            LineTo(dc, 10, 80);
            Ellipse(dc, 220, 10, 400, 80);

            /* Pixel stipple. */
            for (int i = 0; i < 50; ++i)
            {
                SetPixel(dc, 220 + i * 3, 110, RGB(0xFF, 0xFF, 0x00));
            }

            TextOutA(dc, 12, 100, "DuetOS windowed_hello", 21);
            TextOutA(dc, 12, 120, "GDI + MsgPump + Timer", 21);
            ReleaseDC(hwnd, dc);
        }
        OutputDebugStringA("[odbg] windowed_hello: paint done\n");

        /* Drain the WM_CREATE / WM_SIZE / WM_ACTIVATE lifecycle
         * messages that land when the window registers. */
        MSG msg;
        unsigned drained = 0;
        while (drained < 32 && PeekMessageA(&msg, 0, 0, 0, PM_REMOVE))
        {
            ++drained;
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        dbg_uint("[odbg] windowed_hello: drained ", drained);

        /* Timer-backed pump: SetTimer fires WM_TIMER every 500ms;
         * GetMessage blocks until one arrives. Pump up to 3 then
         * bail. Bounded iteration so a broken timer can't hang
         * the fixture past the 17s screenshot window. */
        SetTimer(hwnd, 1, 500, 0);
        unsigned got_timer = 0;
        unsigned got_total = 0;
        while (got_timer < 3 && got_total < 50)
        {
            if (!GetMessageA(&msg, 0, 0, 0))
                break;
            ++got_total;
            if (msg.message == WM_TIMER)
                ++got_timer;
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
        KillTimer(hwnd, 1);
        dbg_uint("[odbg] windowed_hello: pumped ", got_total);
        dbg_uint("[odbg] windowed_hello: timers ", got_timer);
        /* WndProc counter should match `got_timer` — that's how
         * we know DispatchMessage actually invoked our proc. */
        const unsigned dispatched_timers = (unsigned)GetWindowLongPtrA(hwnd, GWLP_USERDATA);
        dbg_uint("[odbg] windowed_hello: wndproc ", dispatched_timers);

        /* InvalidateRect → WM_PAINT round-trip. */
        InvalidateRect(hwnd, 0, 1);
        unsigned painted = 0;
        for (unsigned iter = 0; iter < 8; ++iter)
        {
            if (!PeekMessageA(&msg, 0, 0, 0, PM_REMOVE))
                break;
            if (msg.message == 0x000F /* WM_PAINT */)
            {
                ++painted;
            }
            DispatchMessageA(&msg);
        }
        dbg_uint("[odbg] windowed_hello: painted ", painted);
    }

    /* Screenshot settle window. */
    Sleep(17000);
    ExitProcess(0x57);
}
