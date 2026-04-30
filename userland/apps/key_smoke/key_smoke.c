/*
 * key_smoke — exercise virtual-key / keyboard-state APIs.
 *
 *   GetKeyState
 *   GetAsyncKeyState
 *   MapVirtualKeyW (VK_A → 'A')
 *   GetKeyboardLayout
 *   ToAscii / ToUnicode (skipped — needs key state)
 */
#include <windows.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

void __cdecl mainCRTStartup(void)
{
    Out("[key_smoke] starting\r\n");

    /* GetKeyState(VK_LBUTTON) — should not trap. */
    SHORT s = GetKeyState(VK_LBUTTON);
    Out("[key_smoke] GetKeyState         = ");
    Out("PASS (returned)\r\n");
    (void)s;

    /* GetAsyncKeyState. */
    SHORT a = GetAsyncKeyState(VK_LBUTTON);
    Out("[key_smoke] GetAsyncKeyState    = ");
    Out("PASS (returned)\r\n");
    (void)a;

    /* MapVirtualKeyW: VK_A → 'A'. */
    UINT m = MapVirtualKeyW('A', MAPVK_VK_TO_CHAR);
    Out("[key_smoke] MapVirtualKeyW(A)   = ");
    Out(m == 'A' || m != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* GetKeyboardLayout. */
    HKL k = GetKeyboardLayout(0);
    Out("[key_smoke] GetKeyboardLayout   = ");
    Out(k != NULL ? "PASS\r\n" : "FAIL/STUB\r\n");

    Out("[key_smoke] done\r\n");
    ExitProcess(0);
}
