/*
 * pe32_window — PE32 (i386) GUI test image for the USER32 rung of the
 * PE32 ladder. Registers a window class, creates a window, and drives
 * a full message loop against the kernel window manager: post → peek →
 * dispatch → WndProc → paint → quit.
 *
 * The point of this image is the things a compile cannot prove:
 *
 *   - RegisterClassA actually stores lpfnWndProc (it used to discard
 *     it and return a fake atom), and CreateWindowExA copies it into
 *     the new window so DispatchMessage can find it from the HWND.
 *   - PeekMessage repacks the kernel's 32-byte wire message into the
 *     caller's 28-byte i386 MSG. Step 6 plants a canary immediately
 *     after the MSG and checks it survives — a pass-through
 *     implementation writes 4 bytes past the end of the struct and
 *     trips it.
 *   - DispatchMessage really calls back into this image's WndProc.
 *
 * Built with i686-w64-mingw32-gcc, freestanding, entry mainCRTStartup.
 * Reports the standardized battery verdict line and exits rc=0x42 on
 * success so the boot scraper has a deterministic signature.
 */

typedef void* HANDLE;
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef int INT;
typedef int LRESULT;
typedef unsigned int WPARAM;
typedef unsigned int LPARAM;
typedef unsigned short ATOM;

#define STD_OUTPUT_HANDLE ((DWORD) - 11)

/* kernel32 */
__declspec(dllimport) void __stdcall ExitProcess(unsigned);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE, const void*, DWORD, DWORD*, void*);

/* user32 */
__declspec(dllimport) ATOM __stdcall RegisterClassA(const void*);
__declspec(dllimport) HANDLE __stdcall CreateWindowExA(DWORD, const char*, const char*, DWORD, int, int, int, int,
                                                       HANDLE, HANDLE, HANDLE, void*);
__declspec(dllimport) BOOL __stdcall ShowWindow(HANDLE, int);
__declspec(dllimport) BOOL __stdcall DestroyWindow(HANDLE);
__declspec(dllimport) BOOL __stdcall GetClientRect(HANDLE, void*);
__declspec(dllimport) long __stdcall GetWindowLongA(HANDLE, int);
__declspec(dllimport) BOOL __stdcall PostMessageA(HANDLE, UINT, WPARAM, LPARAM);
__declspec(dllimport) BOOL __stdcall PeekMessageA(void*, HANDLE, UINT, UINT, UINT);
__declspec(dllimport) BOOL __stdcall GetMessageA(void*, HANDLE, UINT, UINT);
__declspec(dllimport) LRESULT __stdcall DispatchMessageA(const void*);
__declspec(dllimport) LRESULT __stdcall SendMessageA(HANDLE, UINT, WPARAM, LPARAM);
__declspec(dllimport) void __stdcall PostQuitMessage(int);
__declspec(dllimport) LRESULT __stdcall DefWindowProcA(HANDLE, UINT, WPARAM, LPARAM);
__declspec(dllimport) HANDLE __stdcall BeginPaint(HANDLE, void*);
__declspec(dllimport) BOOL __stdcall EndPaint(HANDLE, const void*);
__declspec(dllimport) INT __stdcall GetSystemMetrics(int);

/* gdi32 */
__declspec(dllimport) HANDLE __stdcall CreateSolidBrush(unsigned long);
__declspec(dllimport) HANDLE __stdcall SelectObject(HANDLE, HANDLE);
__declspec(dllimport) INT __stdcall FillRect(HANDLE, const void*, HANDLE);
__declspec(dllimport) BOOL __stdcall TextOutA(HANDLE, int, int, const char*, int);
__declspec(dllimport) BOOL __stdcall Rectangle(HANDLE, int, int, int, int);
__declspec(dllimport) BOOL __stdcall DeleteObject(HANDLE);

typedef struct
{
    INT left, top, right, bottom;
} RECT;

/* i386 MSG — 28 bytes. Field order and size matter: the whole point
 * of step 6 is that user32 repacks the kernel's 32-byte wire format
 * into exactly this. */
typedef struct
{
    HANDLE hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    INT pt_x;
    INT pt_y;
} MSG32;

typedef struct
{
    UINT style;
    void* lpfnWndProc;
    INT cbClsExtra;
    INT cbWndExtra;
    HANDLE hInstance;
    HANDLE hIcon;
    HANDLE hCursor;
    HANDLE hbrBackground;
    const char* lpszMenuName;
    const char* lpszClassName;
} WNDCLASS32;

#define WM_PAINT 0x000F
#define WM_QUIT 0x0012
#define WM_APP 0x8000
#define PM_REMOVE 0x0001
#define SW_SHOW 5
#define GWLP_WNDPROC (-4)
#define WS_OVERLAPPEDWINDOW 0x00CF0000

static void say(const char* s)
{
    DWORD n = 0;
    while (s[n])
        ++n;
    DWORD written = 0;
    (void)WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), s, n, &written, 0);
}

/* WndProc call log — DispatchMessage / SendMessage must land here. */
static volatile unsigned g_wndproc_calls = 0;
static volatile UINT g_last_msg = 0;
static volatile WPARAM g_last_wparam = 0;
static volatile LPARAM g_last_lparam = 0;
static HANDLE g_paint_hwnd = 0;

static void paint_window(HANDLE hwnd);

static LRESULT __stdcall TestWndProc(HANDLE hwnd, UINT msg, WPARAM w, LPARAM l)
{
    ++g_wndproc_calls;
    g_last_msg = msg;
    g_last_wparam = w;
    g_last_lparam = l;
    if (msg == WM_PAINT)
    {
        paint_window(hwnd);
        return 0;
    }
    return DefWindowProcA(hwnd, msg, w, l);
}

/* PAINTSTRUCT on i386 is 64 bytes. */
typedef struct
{
    HANDLE hdc;
    BOOL fErase;
    RECT rcPaint;
    BOOL fRestore;
    BOOL fIncUpdate;
    unsigned char rgbReserved[32];
} PAINTSTRUCT32;

static void paint_window(HANDLE hwnd)
{
    PAINTSTRUCT32 ps;
    HANDLE hdc = BeginPaint(hwnd, &ps);
    if (!hdc)
        return;
    HANDLE brush = CreateSolidBrush(0x00404060);
    RECT full = {0, 0, ps.rcPaint.right, ps.rcPaint.bottom};
    (void)FillRect(hdc, &full, brush);
    (void)SelectObject(hdc, brush);
    (void)Rectangle(hdc, 4, 4, ps.rcPaint.right - 4, ps.rcPaint.bottom - 4);
    (void)TextOutA(hdc, 8, 8, "DuetOS PE32 window", 18);
    (void)DeleteObject(brush);
    (void)EndPaint(hwnd, &ps);
    g_paint_hwnd = hwnd;
}

/* The two digit slots sit right after "step=". Deriving the offset
 * from the literal rather than hand-counting it keeps the two in
 * sync — an off-by-one here corrupts the '=' and reports the wrong
 * step number, which is exactly the kind of misdirection a failing
 * boot cannot afford. */
static void fail(int step)
{
    static const char kPrefix[] = "[ring3-pe32-window] FAIL step=";
    char msg[] = "[ring3-pe32-window] FAIL step=NN\r\n";
    const unsigned d = sizeof(kPrefix) - 1;
    msg[d] = (char)('0' + (step / 10));
    msg[d + 1] = (char)('0' + (step % 10));
    say(msg);
    ExitProcess(1);
}

/* Report an unexpected value alongside the step so a failing boot
 * says WHAT arrived, not just that something did. */
static void fail_val(int step, unsigned value)
{
    static const char kPrefix[] = "[pe32-window] step=";
    char msg[] = "[pe32-window] step=NN got=0xXXXXXXXX\r\n";
    const unsigned d = sizeof(kPrefix) - 1;
    msg[d] = (char)('0' + (step / 10));
    msg[d + 1] = (char)('0' + (step % 10));
    for (int i = 0; i < 8; ++i)
    {
        const unsigned nibble = (value >> ((7 - i) * 4)) & 0xF;
        msg[d + 9 + i] = (char)(nibble < 10 ? ('0' + nibble) : ('a' + nibble - 10));
    }
    say(msg);
    fail(step);
}

void mainCRTStartup(void)
{
    say("[pe32-window] start\r\n");

    /* 1. Class registration must store the WNDPROC and hand back a
     *    non-zero atom. */
    WNDCLASS32 wc;
    {
        unsigned char* p = (unsigned char*)&wc;
        for (unsigned i = 0; i < sizeof(wc); ++i)
            p[i] = 0;
    }
    wc.lpfnWndProc = (void*)TestWndProc;
    wc.lpszClassName = "DuetPE32WndClass";
    const ATOM atom = RegisterClassA(&wc);
    if (atom == 0)
        fail(1);
    say("[pe32-window] class registered\r\n");

    /* 2. The window manager must hand back a real HWND. */
    HANDLE hwnd =
        CreateWindowExA(0, "DuetPE32WndClass", "DuetOS PE32", WS_OVERLAPPEDWINDOW, 40, 40, 320, 200, 0, 0, 0, 0);
    if (!hwnd)
        fail(2);
    say("[pe32-window] window created\r\n");

    /* 3. CreateWindowEx must have copied the class WNDPROC into the
     *    window's long slot — this is the link DispatchMessage
     *    depends on, and the stub build never made it. */
    if ((void*)GetWindowLongA(hwnd, GWLP_WNDPROC) != (void*)TestWndProc)
        fail(3);

    /* 4. Geometry must come from the compositor, not a zeroed
     *    buffer. */
    (void)ShowWindow(hwnd, SW_SHOW);
    RECT client = {-1, -1, -1, -1};
    if (!GetClientRect(hwnd, &client))
        fail(4);
    if (client.right <= 0 || client.bottom <= 0)
        fail(5);

    /* 5. GetSystemMetrics must report a real screen, not the stub's
     *    hard-coded 1024x768. Any non-zero size is acceptable — the
     *    check is that the syscall answered. */
    if (GetSystemMetrics(0) <= 0 || GetSystemMetrics(1) <= 0)
        fail(6);

    /* 6. Post → peek round-trip, with a canary immediately after the
     *    MSG. A pump that hands the kernel the caller's 28-byte MSG
     *    directly gets its fields misaligned AND overwrites the four
     *    bytes the canary occupies. */
    struct
    {
        MSG32 msg;
        unsigned canary;
    } probe;
    {
        unsigned char* p = (unsigned char*)&probe;
        for (unsigned i = 0; i < sizeof(probe); ++i)
            p[i] = 0;
    }
    probe.canary = 0xC0FFEE01u;
    if (!PostMessageA(hwnd, WM_APP, 0x1234, 0x5678))
        fail(7);
    /* Creating and showing the window already queued messages
     * (WM_PAINT at least), and the queue is FIFO, so drain until our
     * own message surfaces rather than assuming it is first. The
     * canary is re-checked on EVERY iteration — one overrunning
     * write anywhere in the drain is the bug this is looking for. */
    int found = 0;
    UINT last_seen = 0;
    for (int i = 0; i < 32 && !found; ++i)
    {
        if (!PeekMessageA(&probe.msg, hwnd, 0, 0, PM_REMOVE))
            break;
        if (probe.canary != 0xC0FFEE01u)
            fail(9); /* 32-byte wire write into a 28-byte MSG */
        last_seen = probe.msg.message;
        if (probe.msg.message == WM_APP)
            found = 1;
    }
    if (!found)
        fail_val(10, last_seen);
    if (probe.msg.wParam != 0x1234)
        fail_val(11, probe.msg.wParam);
    if (probe.msg.lParam != 0x5678)
        fail_val(12, probe.msg.lParam);
    if (probe.msg.hwnd != hwnd)
        fail_val(13, (unsigned)(unsigned long)probe.msg.hwnd);
    say("[pe32-window] msg round-trip ok\r\n");

    /* 7. DispatchMessage must reach this image's WndProc. */
    const unsigned before = g_wndproc_calls;
    (void)DispatchMessageA(&probe.msg);
    if (g_wndproc_calls != before + 1)
        fail_val(14, g_wndproc_calls);
    if (g_last_msg != WM_APP)
        fail_val(15, g_last_msg);
    if (g_last_wparam != 0x1234 || g_last_lparam != 0x5678)
        fail(16);
    say("[pe32-window] dispatch ok\r\n");

    /* 8. SendMessage is the synchronous path to the same WNDPROC. */
    (void)SendMessageA(hwnd, WM_APP + 1, 0xAA, 0xBB);
    if (g_last_msg != WM_APP + 1 || g_last_wparam != 0xAA || g_last_lparam != 0xBB)
        fail_val(17, g_last_msg);

    /* 9. Paint through the DC. The draw calls are recorded in the
     *    compositor's display list; the check here is that the paint
     *    path runs to completion and BeginPaint handed back a DC. */
    MSG32 paint_msg = {hwnd, WM_PAINT, 0, 0, 0, 0, 0};
    (void)DispatchMessageA(&paint_msg);
    if (g_paint_hwnd != hwnd)
        fail(18);
    say("[pe32-window] paint ok\r\n");

    /* 10. PostQuitMessage must break the pump: GetMessage returns
     *     FALSE with WM_QUIT and the exit code in wParam. */
    PostQuitMessage(0x42);
    MSG32 quit_msg;
    {
        unsigned char* p = (unsigned char*)&quit_msg;
        for (unsigned i = 0; i < sizeof(quit_msg); ++i)
            p[i] = 0xEE;
    }
    /* Drain whatever the quit fan-out queued until WM_QUIT shows up;
     * a pump that never yields it would spin here, so the loop is
     * bounded and a miss is a failure rather than a hang. */
    int saw_quit = 0;
    for (int i = 0; i < 32 && !saw_quit; ++i)
    {
        const BOOL more = GetMessageA(&quit_msg, 0, 0, 0);
        if (!more)
        {
            if (quit_msg.message != WM_QUIT)
                fail_val(19, quit_msg.message);
            if (quit_msg.wParam != 0x42)
                fail_val(20, quit_msg.wParam);
            saw_quit = 1;
        }
    }
    if (!saw_quit)
        fail(21);
    say("[pe32-window] quit ok\r\n");

    if (!DestroyWindow(hwnd))
        fail(22);

    say("[pe32-window] all checks passed — exit rc=0x42\r\n");
    say("[ring3-pe32-window] PASS\r\n");
    ExitProcess(0x42);
}
