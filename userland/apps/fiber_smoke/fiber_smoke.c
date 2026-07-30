/*
 * fiber_smoke -- exercise real Win32 Fiber + FLS APIs.
 *
 * Test plan:
 *   1. ConvertThreadToFiber -> creates fiber A (slot 0).
 *   2. CreateFiber          -> creates fiber B with its own stack.
 *   3. FlsAlloc             -> allocate one FLS slot.
 *   4. FlsSetValue in A     -> store 0xAAAA in A's FLS.
 *   5. SwitchToFiber(B)     -> B runs, sets FLS to 0xBBBB, switches back.
 *   6. FlsGetValue in A     -> must still be 0xAAAA (per-fiber isolation).
 *   7. DeleteFiber(B)       -> free B's resources.
 *   8. FlsFree              -> release the FLS slot.
 *
 * Expected serial output:
 *   [fiber_smoke] starting
 *   [fiber_smoke] ConvertThreadToFiber = PASS
 *   [fiber_smoke] CreateFiber          = PASS
 *   [fiber_smoke] FlsAlloc             = PASS
 *   [fiber_smoke] FlsSetValue(A)       = PASS
 *   [fiber_smoke] fiberB: running
 *   [fiber_smoke] fiberB: FlsGet       = PASS (isolated)
 *   [fiber_smoke] fiberB: FlsSet(B)    = PASS
 *   [fiber_smoke] back in A
 *   [fiber_smoke] FlsGetValue(A)       = PASS (0xAAAA preserved)
 *   [fiber_smoke] DeleteFiber(B)       = PASS
 *   [fiber_smoke] FlsFree              = PASS
 *   [fiber_smoke] done
 *   [ring3-fiber-smoke] PASS
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

/* Shared state: fiber A's address so B can switch back. */
static void* g_fiberA;
static DWORD g_flsSlot;
static int g_fiberB_ran;

static void __stdcall FiberBProc(void* param)
{
    (void)param;
    Out("[fiber_smoke] fiberB: running\r\n");

    /* FLS slot should be 0 in B (B hasn't set it yet). */
    void* bval = FlsGetValue(g_flsSlot);
    Out("[fiber_smoke] fiberB: FlsGet       = ");
    Out(bval == (void*)0 ? "PASS (isolated)\r\n" : "FAIL\r\n");

    /* Set B's own FLS value. */
    BOOL ok = FlsSetValue(g_flsSlot, (void*)0xBBBB);
    Out("[fiber_smoke] fiberB: FlsSet(B)    = ");
    Out(ok ? "PASS\r\n" : "FAIL\r\n");

    g_fiberB_ran = 1;

    /* Switch back to fiber A. */
    SwitchToFiber(g_fiberA);

    /* If B is ever resumed again, just loop back. */
    for (;;)
        SwitchToFiber(g_fiberA);
}

void __cdecl mainCRTStartup(void)
{
    int all_pass = 1;
    Out("[fiber_smoke] starting\r\n");

    /* 1. Convert this thread into fiber A. */
    g_fiberA = ConvertThreadToFiber((void*)0xA0A0);
    Out("[fiber_smoke] ConvertThreadToFiber = ");
    if (g_fiberA != (void*)0)
    {
        Out("PASS\r\n");
    }
    else
    {
        Out("FAIL\r\n");
        all_pass = 0;
    }

    /* 2. Create fiber B. */
    void* fiberB = CreateFiber(0, FiberBProc, (void*)0xB0B0);
    Out("[fiber_smoke] CreateFiber          = ");
    if (fiberB != (void*)0)
    {
        Out("PASS\r\n");
    }
    else
    {
        Out("FAIL\r\n");
        all_pass = 0;
    }

    /* 3. Allocate an FLS slot. */
    g_flsSlot = FlsAlloc(NULL);
    Out("[fiber_smoke] FlsAlloc             = ");
    if (g_flsSlot != FLS_OUT_OF_INDEXES)
    {
        Out("PASS\r\n");
    }
    else
    {
        Out("FAIL\r\n");
        all_pass = 0;
    }

    if (g_fiberA && fiberB && g_flsSlot != FLS_OUT_OF_INDEXES)
    {
        /* 4. Set FLS value in fiber A. */
        BOOL set_ok = FlsSetValue(g_flsSlot, (void*)0xAAAA);
        Out("[fiber_smoke] FlsSetValue(A)       = ");
        Out(set_ok ? "PASS\r\n" : "FAIL\r\n");
        if (!set_ok)
            all_pass = 0;

        /* 5. Switch to fiber B. B will set its own FLS and switch back. */
        SwitchToFiber(fiberB);

        /* 6. Back in A -- verify our FLS is still 0xAAAA. */
        Out("[fiber_smoke] back in A\r\n");
        void* aval = FlsGetValue(g_flsSlot);
        Out("[fiber_smoke] FlsGetValue(A)       = ");
        if (aval == (void*)0xAAAA)
        {
            Out("PASS (0xAAAA preserved)\r\n");
        }
        else
        {
            Out("FAIL\r\n");
            all_pass = 0;
        }

        /* Verify B actually ran. */
        if (!g_fiberB_ran)
        {
            Out("[fiber_smoke] fiberB did not run   = FAIL\r\n");
            all_pass = 0;
        }

        /* 7. Delete fiber B. */
        DeleteFiber(fiberB);
        Out("[fiber_smoke] DeleteFiber(B)       = PASS\r\n");

        /* 8. Free the FLS slot. */
        BOOL free_ok = FlsFree(g_flsSlot);
        Out("[fiber_smoke] FlsFree              = ");
        Out(free_ok ? "PASS\r\n" : "FAIL\r\n");
        if (!free_ok)
            all_pass = 0;
    }

    Out("[fiber_smoke] done\r\n");
    Out(all_pass ? "[ring3-fiber-smoke] PASS\r\n" : "[ring3-fiber-smoke] FAIL\r\n");
    ExitProcess(0);
}
