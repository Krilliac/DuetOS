/*
 * Mixed-provider import fixture for legacy-thunk retirement waves.
 *
 * Retired functions are deliberately split across kernel32, kernelbase, and
 * API-set import descriptors. The declarations stay ordinary dllimports; the
 * per-provider .def files decide which DLL name lld writes into the PE import
 * directory.
 */

typedef void* HANDLE;
typedef unsigned int DWORD;
typedef int LONG;
typedef int BOOL;
typedef const void* LPCVOID;
typedef DWORD* LPDWORD;
typedef DWORD(__stdcall* LPTHREAD_START_ROUTINE)(void*);

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define WAIT_OBJECT_0 0u

/* kernel32.dll: test support plus one retired pseudo-handle API. */
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE object);
__declspec(dllimport) HANDLE __stdcall CreateThread(void* attributes, unsigned long long stackSize,
                                                    LPTHREAD_START_ROUTINE startAddress, void* parameter,
                                                    DWORD creationFlags, DWORD* threadId);
__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall GetExitCodeThread(HANDLE thread, DWORD* exitCode);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE handle, DWORD milliseconds);
__declspec(dllimport) BOOL __stdcall WriteFile(HANDLE hFile, LPCVOID buffer, DWORD bytesToWrite, LPDWORD bytesWritten,
                                               void* overlapped);
__declspec(dllimport) void __stdcall ExitProcess(DWORD exitCode);
__declspec(dllimport) HANDLE __stdcall GetCurrentProcess(void);

/* kernelbase.dll: provider-convergence routes. */
__declspec(dllimport) HANDLE __stdcall GetCurrentThread(void);
__declspec(dllimport) LONG __stdcall InterlockedExchangeAdd(LONG volatile* addend, LONG value);

/* api-ms-win-core-processthreads-l1-1-0.dll: ID queries. */
__declspec(dllimport) DWORD __stdcall GetCurrentProcessId(void);
__declspec(dllimport) DWORD __stdcall GetCurrentThreadId(void);

/* api-ms-win-core-errorhandling-l1-1-0.dll: thread-local error state. */
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(DWORD errorCode);

/* api-ms-win-core-interlocked-l1-1-0.dll: 32-bit bitwise atomics. */
__declspec(dllimport) LONG __stdcall InterlockedAnd(LONG volatile* target, LONG value);
__declspec(dllimport) LONG __stdcall InterlockedOr(LONG volatile* target, LONG value);
__declspec(dllimport) LONG __stdcall InterlockedXor(LONG volatile* target, LONG value);

static volatile DWORD g_worker_process_id;
static volatile DWORD g_worker_thread_id;
static volatile LONG g_atomic_add_total;

static DWORD StringLength(const char* text)
{
    DWORD length = 0;
    while (text[length] != '\0')
    {
        ++length;
    }
    return length;
}

static void Out(const char* text)
{
    DWORD written = 0;
    (void)WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), text, StringLength(text), &written, 0);
}

static void Fail(const char* message, DWORD exitCode)
{
    Out(message);
    ExitProcess(exitCode);
}

static DWORD __stdcall IdentityAndLastErrorWorker(void* parameter)
{
    (void)parameter;
    g_worker_process_id = GetCurrentProcessId();
    g_worker_thread_id = GetCurrentThreadId();
    SetLastError(0xA11A50F2u);
    return GetLastError() == 0xA11A50F2u ? 0u : 0xA5u;
}

static DWORD __stdcall ContendedAtomicAddWorker(void* parameter)
{
    (void)parameter;
    for (DWORD i = 0; i < 65536u; ++i)
        (void)InterlockedExchangeAdd(&g_atomic_add_total, 1);
    return 0;
}

void __cdecl _start(void)
{
    if (GetCurrentProcess() != (HANDLE)(long long)-1)
    {
        Fail("[thunk_alias_smoke] FAIL kernel32.dll!GetCurrentProcess\r\n", 0xA1);
    }
    Out("[thunk_alias_smoke] kernel32.dll pseudo-handle PASS\r\n");

    if (GetCurrentThread() != (HANDLE)(long long)-2)
    {
        Fail("[thunk_alias_smoke] FAIL kernelbase.dll!GetCurrentThread\r\n", 0xA2);
    }
    Out("[thunk_alias_smoke] kernelbase.dll pseudo-handle PASS\r\n");

    const DWORD processId = GetCurrentProcessId();
    const DWORD threadId = GetCurrentThreadId();
    if (processId == 0 || threadId == 0)
    {
        Fail("[thunk_alias_smoke] FAIL api-ms-win-core-processthreads-l1-1-0.dll IDs\r\n", 0xA3);
    }
    Out("[thunk_alias_smoke] api-ms-win-core-processthreads-l1-1-0.dll IDs PASS\r\n");

    // A worker must share the process ID, have a distinct thread ID,
    // and modify only its own LastError slot. These comparisons catch
    // swapped/constant ID wrappers and process-global error storage.
    const DWORD expectedError = 0xA11A5002u;
    SetLastError(expectedError);
    g_worker_process_id = 0;
    g_worker_thread_id = 0;
    HANDLE worker = CreateThread(0, 0, IdentityAndLastErrorWorker, 0, 0, 0);
    if (worker == 0)
        Fail("[thunk_alias_smoke] FAIL worker create\r\n", 0xA4u);
    if (WaitForSingleObject(worker, 5000u) != WAIT_OBJECT_0)
        Fail("[thunk_alias_smoke] FAIL worker wait\r\n", 0xA5u);
    DWORD worker_exit = 0xFFFFFFFFu;
    if (!GetExitCodeThread(worker, &worker_exit) || worker_exit != 0u)
        Fail("[thunk_alias_smoke] FAIL worker exit\r\n", 0xA6u);
    const DWORD main_error = GetLastError();
    (void)CloseHandle(worker);
    if (g_worker_process_id != processId || g_worker_thread_id == 0 || g_worker_thread_id == threadId)
        Fail("[thunk_alias_smoke] FAIL process/thread ID isolation\r\n", 0xA7u);
    if (main_error != expectedError)
    {
        Fail("[thunk_alias_smoke] FAIL api-ms-win-core-errorhandling-l1-1-0.dll last-error isolation\r\n", 0xA8u);
    }
    Out("[thunk_alias_smoke] api-ms-win-core-errorhandling-l1-1-0.dll thread-local last-error PASS\r\n");

    volatile LONG atomic_value = 0x55;
    if (InterlockedExchangeAdd(&atomic_value, 0x10) != 0x55 || atomic_value != 0x65)
        Fail("[thunk_alias_smoke] FAIL kernelbase.dll!InterlockedExchangeAdd\r\n", 0xA9u);
    g_atomic_add_total = 0;
    HANDLE add_worker_a = CreateThread(0, 0, ContendedAtomicAddWorker, 0, 0, 0);
    HANDLE add_worker_b = CreateThread(0, 0, ContendedAtomicAddWorker, 0, 0, 0);
    if (add_worker_a == 0 || add_worker_b == 0)
        Fail("[thunk_alias_smoke] FAIL contended atomic worker create\r\n", 0xAAu);
    if (WaitForSingleObject(add_worker_a, 5000u) != WAIT_OBJECT_0 ||
        WaitForSingleObject(add_worker_b, 5000u) != WAIT_OBJECT_0)
    {
        Fail("[thunk_alias_smoke] FAIL contended atomic worker wait\r\n", 0xABu);
    }
    DWORD add_exit_a = 0xFFFFFFFFu;
    DWORD add_exit_b = 0xFFFFFFFFu;
    if (!GetExitCodeThread(add_worker_a, &add_exit_a) || !GetExitCodeThread(add_worker_b, &add_exit_b) ||
        add_exit_a != 0 || add_exit_b != 0 || g_atomic_add_total != 131072)
    {
        Fail("[thunk_alias_smoke] FAIL contended InterlockedExchangeAdd\r\n", 0xACu);
    }
    (void)CloseHandle(add_worker_a);
    (void)CloseHandle(add_worker_b);
    Out("[thunk_alias_smoke] kernelbase.dll InterlockedExchangeAdd PASS\r\n");

    if (InterlockedAnd(&atomic_value, 0x3F) != 0x65 || atomic_value != 0x25)
        Fail("[thunk_alias_smoke] FAIL api-ms-win-core-interlocked-l1-1-0.dll!InterlockedAnd\r\n", 0xADu);
    if (InterlockedOr(&atomic_value, 0x80) != 0x25 || atomic_value != 0xA5)
        Fail("[thunk_alias_smoke] FAIL api-ms-win-core-interlocked-l1-1-0.dll!InterlockedOr\r\n", 0xAEu);
    if (InterlockedXor(&atomic_value, 0xFF) != 0xA5 || atomic_value != 0x5A)
        Fail("[thunk_alias_smoke] FAIL api-ms-win-core-interlocked-l1-1-0.dll!InterlockedXor\r\n", 0xAFu);
    Out("[thunk_alias_smoke] api-ms-win-core-interlocked-l1-1-0.dll bitwise atomics PASS\r\n");

    Out("[ring3-thunk-alias-smoke] PASS\r\n");
    ExitProcess(0);
}
