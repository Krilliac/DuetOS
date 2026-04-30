/*
 * power_smoke — exercise power-management / system-state APIs.
 *
 *   GetSystemPowerStatus
 *   SetThreadExecutionState
 *   IsSystemResumeAutomatic
 *   PowerSettingRegisterNotification (skipped — needs window)
 *
 * v0: no battery / power events on QEMU emulator.
 * Smoke value = "doesn't trap when laptop power code path runs".
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
    Out("[power_smoke] starting\r\n");

    SYSTEM_POWER_STATUS sps = {0};
    BOOL ok = GetSystemPowerStatus(&sps);
    Out("[power_smoke] GetSystemPowerStatus= ");
    Out(ok ? "PASS\r\n" : "FAIL/STUB\r\n");

    /* SetThreadExecutionState(ES_CONTINUOUS) — keep alive. */
    EXECUTION_STATE prev = SetThreadExecutionState(ES_CONTINUOUS);
    Out("[power_smoke] SetThreadExecutionState = ");
    Out(prev != 0 ? "PASS\r\n" : "FAIL/STUB\r\n");

    BOOL resume = IsSystemResumeAutomatic();
    Out("[power_smoke] IsSystemResumeAutomatic = ");
    /* Should be FALSE (we're not waking from sleep). */
    Out(!resume ? "PASS (FALSE, as expected)\r\n" : "FAIL\r\n");

    Out("[power_smoke] done\r\n");
    ExitProcess(0);
}
