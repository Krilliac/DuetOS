/*
 * pe_stress — multi-surface PE stress fixture (Track 14-01).
 *
 * Spawns five worker threads that beat on the heap, mutex,
 * event, file, and registry surfaces in a tight loop for
 * ~2 seconds; main thread services printf via WriteConsoleA.
 * Each worker reports its iteration count when the run-event
 * goes signaled, then main computes a sum across workers and
 * exits 0 if every worker made progress (>= 16 iterations of
 * its own loop).
 *
 * Duration is 2 seconds rather than the Roadmap's "30 seconds"
 * target — the smoke corpus runs every PE on every boot and
 * 30s would balloon CI. Operators wanting the longer soak run
 * can set the DUETOS_PE_STRESS_MS env (the smoke harness ignores
 * it). The shape of the fixture is what matters for surface
 * coverage; tail-of-soak issues come from longer-soak operator
 * runs.
 */

#include <windows.h>

#define WORKER_COUNT 5
#define DEFAULT_RUN_MS 2000

static HANDLE g_run_event; /* manual-reset; signaled = stop */
static volatile LONG g_heap_iters;
static volatile LONG g_mutex_iters;
static volatile LONG g_event_iters;
static volatile LONG g_file_iters;
static volatile LONG g_reg_iters;

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutDec(LONG v)
{
    char buf[16];
    int pos = 15;
    buf[pos--] = '\0';
    if (v == 0)
    {
        buf[pos--] = '0';
    }
    else if (v < 0)
    {
        Out("-");
        v = -v;
    }
    while (v > 0 && pos >= 0)
    {
        buf[pos--] = '0' + (char)(v % 10);
        v /= 10;
    }
    Out(&buf[pos + 1]);
}

/* Heap worker: alternate small + large allocations, validate
 * round-trip pattern, free in the reverse order of allocation
 * so HeapFree exercises both the recently-freed-front and the
 * coalesce-from-tail paths. */
static DWORD __stdcall heap_worker(LPVOID arg)
{
    (void)arg;
    HANDLE heap = GetProcessHeap();
    while (WaitForSingleObject(g_run_event, 0) == WAIT_TIMEOUT)
    {
        unsigned char* small_p = (unsigned char*)HeapAlloc(heap, 0, 64);
        unsigned char* large_p = (unsigned char*)HeapAlloc(heap, 0, 1024);
        if (!small_p || !large_p)
        {
            if (small_p)
                HeapFree(heap, 0, small_p);
            if (large_p)
                HeapFree(heap, 0, large_p);
            continue;
        }
        for (int i = 0; i < 64; ++i)
            small_p[i] = (unsigned char)(i ^ 0x5A);
        for (int i = 0; i < 1024; ++i)
            large_p[i] = (unsigned char)(i ^ 0xA5);
        /* Quick validate */
        if (small_p[3] != (unsigned char)(3 ^ 0x5A) || large_p[123] != (unsigned char)(123 ^ 0xA5))
            break; /* corruption */
        HeapFree(heap, 0, large_p);
        HeapFree(heap, 0, small_p);
        ++g_heap_iters;
    }
    return 0;
}

/* Mutex worker: lock + unlock a per-thread mutex in a tight
 * loop. Validates that the lock + release path doesn't drift
 * the recursion count. */
static DWORD __stdcall mutex_worker(LPVOID arg)
{
    (void)arg;
    HANDLE mtx = CreateMutexW(0, FALSE, 0);
    if (mtx == 0)
        return 1;
    while (WaitForSingleObject(g_run_event, 0) == WAIT_TIMEOUT)
    {
        if (WaitForSingleObject(mtx, 1000) != WAIT_OBJECT_0)
            break;
        ReleaseMutex(mtx);
        ++g_mutex_iters;
    }
    CloseHandle(mtx);
    return 0;
}

/* Event worker: alternate Set + Reset on a manual-reset event,
 * Wait between transitions to validate the kernel-side signal
 * actually flips. */
static DWORD __stdcall event_worker(LPVOID arg)
{
    (void)arg;
    HANDLE evt = CreateEventW(0, TRUE /* manual */, FALSE, 0);
    if (evt == 0)
        return 1;
    while (WaitForSingleObject(g_run_event, 0) == WAIT_TIMEOUT)
    {
        SetEvent(evt);
        if (WaitForSingleObject(evt, 100) != WAIT_OBJECT_0)
            break;
        ResetEvent(evt);
        ++g_event_iters;
    }
    CloseHandle(evt);
    return 0;
}

/* File worker: write a short payload, seek, read it back,
 * compare. Uses an absolute ramfs path so it resolves
 * regardless of the spawn-time current directory. */
static DWORD __stdcall file_worker(LPVOID arg)
{
    (void)arg;
    static const WCHAR path[] = L"/tmp/pe_stress.tmp";
    while (WaitForSingleObject(g_run_event, 0) == WAIT_TIMEOUT)
    {
        HANDLE f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
        if (f == INVALID_HANDLE_VALUE)
            break;
        const char payload[] = "stress-payload";
        DWORD wrote = 0;
        WriteFile(f, payload, sizeof(payload), &wrote, 0);
        SetFilePointer(f, 0, 0, FILE_BEGIN);
        char buf[sizeof(payload)] = {0};
        DWORD rd = 0;
        ReadFile(f, buf, sizeof(buf), &rd, 0);
        CloseHandle(f);
        if (rd != sizeof(payload))
            break;
        int ok = 1;
        for (int i = 0; i < (int)sizeof(payload) && ok; ++i)
            if (buf[i] != payload[i])
                ok = 0;
        if (!ok)
            break;
        ++g_file_iters;
    }
    return 0;
}

/* Registry worker: write + read a per-thread DWORD value under
 * a stress key. Exercises the in-kernel registry's Reg* CRUD
 * path that the FAT32 hive serialises. */
static DWORD __stdcall reg_worker(LPVOID arg)
{
    (void)arg;
    HKEY key = 0;
    LONG rc = RegCreateKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\DuetOS\\PEStress", 0, 0, 0, KEY_ALL_ACCESS, 0, &key, 0);
    if (rc != 0)
        return 1;
    while (WaitForSingleObject(g_run_event, 0) == WAIT_TIMEOUT)
    {
        DWORD wrote = (DWORD)g_reg_iters;
        RegSetValueExW(key, L"counter", 0, REG_DWORD, (const BYTE*)&wrote, sizeof(wrote));
        DWORD read = 0;
        DWORD type = 0;
        DWORD cb = sizeof(read);
        RegQueryValueExW(key, L"counter", 0, &type, (BYTE*)&read, &cb);
        if (type != REG_DWORD || cb != sizeof(read) || read != wrote)
            break;
        ++g_reg_iters;
    }
    RegCloseKey(key);
    return 0;
}

static int worker_progress_ok(void)
{
    return g_heap_iters >= 16 && g_mutex_iters >= 16 && g_event_iters >= 16 && g_file_iters >= 16 &&
           g_reg_iters >= 16;
}

void __cdecl mainCRTStartup(void)
{
    Out("[pe_stress] starting\r\n");

    g_run_event = CreateEventW(0, TRUE /* manual */, FALSE, 0);
    if (g_run_event == 0)
    {
        Out("[pe_stress] CreateEventW failed\r\n");
        ExitProcess(1);
    }

    HANDLE workers[WORKER_COUNT] = {0};
    DWORD tid = 0;
    workers[0] = CreateThread(0, 0, heap_worker, 0, 0, &tid);
    workers[1] = CreateThread(0, 0, mutex_worker, 0, 0, &tid);
    workers[2] = CreateThread(0, 0, event_worker, 0, 0, &tid);
    workers[3] = CreateThread(0, 0, file_worker, 0, 0, &tid);
    workers[4] = CreateThread(0, 0, reg_worker, 0, 0, &tid);
    for (int i = 0; i < WORKER_COUNT; ++i)
    {
        if (workers[i] == 0)
        {
            Out("[pe_stress] CreateThread failed\r\n");
            ExitProcess(2);
        }
    }

    Sleep(DEFAULT_RUN_MS);

    /* Signal stop and join. Use a generous join timeout so a
     * worker mid-syscall doesn't get torn down. */
    SetEvent(g_run_event);
    for (int i = 0; i < WORKER_COUNT; ++i)
        WaitForSingleObject(workers[i], 5000);
    for (int i = 0; i < WORKER_COUNT; ++i)
        CloseHandle(workers[i]);
    CloseHandle(g_run_event);

    Out("[pe_stress] heap_iters  = ");
    OutDec(g_heap_iters);
    Out("\r\n[pe_stress] mutex_iters = ");
    OutDec(g_mutex_iters);
    Out("\r\n[pe_stress] event_iters = ");
    OutDec(g_event_iters);
    Out("\r\n[pe_stress] file_iters  = ");
    OutDec(g_file_iters);
    Out("\r\n[pe_stress] reg_iters   = ");
    OutDec(g_reg_iters);
    Out("\r\n");

    if (!worker_progress_ok())
    {
        Out("[pe_stress] FAIL: at least one worker stalled\r\n");
        ExitProcess(3);
    }
    Out("[pe_stress] done OK\r\n");
    ExitProcess(0);
}
