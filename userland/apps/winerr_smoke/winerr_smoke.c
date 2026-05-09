/*
 * winerr_smoke — exercise error / last-error APIs.
 *
 *   GetLastError / SetLastError round-trip (already in module_smoke;
 *     re-verified here to catch regressions)
 *   FormatMessageA / FormatMessageW
 *   GetSystemErrorCode (skipped)
 *   SetErrorMode / GetErrorMode
 *   Per-thread LastError isolation across CreateThread
 *   RtlSetLastWin32Error (ntdll route to GetLastError)
 */
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int BOOL;
typedef void* HANDLE;
typedef void* LPVOID;
typedef unsigned short WCHAR;
typedef DWORD(__stdcall* LPTHREAD_START_ROUTINE)(LPVOID);

#define NULL ((void*)0)
#define TRUE 1
#define FALSE 0
#define WAIT_OBJECT_0 0x00000000u
#define WAIT_FAILED 0xFFFFFFFFu
#define ERROR_SUCCESS 0u
#define ERROR_PATH_NOT_FOUND 3u
#define FORMAT_MESSAGE_IGNORE_INSERTS 0x00000200u
#define FORMAT_MESSAGE_FROM_SYSTEM 0x00001000u
#define SEM_FAILCRITICALERRORS 0x0001u
#define STD_OUTPUT_HANDLE ((DWORD)-11)

__declspec(dllimport) HANDLE __stdcall GetStdHandle(DWORD nStdHandle);
__declspec(dllimport) BOOL __stdcall WriteConsoleA(HANDLE hConsoleOutput, const void* lpBuffer,
                                                   DWORD nNumberOfCharsToWrite, DWORD* lpNumberOfCharsWritten,
                                                   void* lpReserved);
__declspec(dllimport) DWORD __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(DWORD dwErrCode);
__declspec(dllimport) HANDLE __stdcall CreateThread(void* lpThreadAttributes, unsigned long long dwStackSize,
                                                    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter,
                                                    DWORD dwCreationFlags, DWORD* lpThreadId);
__declspec(dllimport) DWORD __stdcall WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
__declspec(dllimport) BOOL __stdcall CloseHandle(HANDLE hObject);
__declspec(dllimport) DWORD __stdcall FormatMessageA(DWORD dwFlags, const void* lpSource, DWORD dwMessageId,
                                                     DWORD dwLanguageId, char* lpBuffer, DWORD nSize, void* Arguments);
__declspec(dllimport) DWORD __stdcall FormatMessageW(DWORD dwFlags, const void* lpSource, DWORD dwMessageId,
                                                     DWORD dwLanguageId, WCHAR* lpBuffer, DWORD nSize, void* Arguments);
__declspec(dllimport) UINT __stdcall SetErrorMode(UINT uMode);
__declspec(dllimport) UINT __stdcall GetErrorMode(void);
__declspec(dllimport) __attribute__((noreturn)) void __stdcall ExitProcess(UINT uExitCode);

static volatile DWORD g_worker_last_error_ok = 0;

void* memset(void* dst, int value, unsigned long long size)
{
    unsigned char* p = (unsigned char*)dst;
    for (unsigned long long i = 0; i < size; ++i)
        p[i] = (unsigned char)value;
    return dst;
}

static DWORD __stdcall LastErrorWorker(LPVOID param)
{
    (void)param;
    SetLastError(0xBEEF);
    g_worker_last_error_ok = (GetLastError() == 0xBEEF) ? 1 : 0;
    return 0;
}

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
    Out("[winerr_smoke] starting\r\n");

    SetLastError(ERROR_PATH_NOT_FOUND);
    DWORD got = GetLastError();
    Out("[winerr_smoke] SetLastError + Get  = ");
    Out(got == ERROR_PATH_NOT_FOUND ? "PASS\r\n" : "FAIL\r\n");

    /* LastError is thread-local: a worker write must not clobber main. */
    {
        g_worker_last_error_ok = 0;
        SetLastError(0x1234);
        HANDLE t = CreateThread(NULL, 0, LastErrorWorker, NULL, 0, NULL);
        DWORD wait_rc = (t != NULL) ? WaitForSingleObject(t, 5000) : WAIT_FAILED;
        DWORD main_error = GetLastError();
        if (t != NULL)
            CloseHandle(t);
        BOOL ok = (t != NULL && wait_rc == WAIT_OBJECT_0 && g_worker_last_error_ok && main_error == 0x1234);
        Out("[winerr_smoke] LastError per-thread= ");
        Out(ok ? "PASS\r\n" : "FAIL\r\n");
    }

    /* FormatMessageA on ERROR_SUCCESS. */
    {
        char buf[256] = {0};
        DWORD n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_SUCCESS, 0,
                                 buf, sizeof(buf), NULL);
        Out("[winerr_smoke] FormatMessageA      = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* FormatMessageW on ERROR_SUCCESS. */
    {
        WCHAR buf[256] = {0};
        DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_SUCCESS, 0,
                                 buf, 256, NULL);
        Out("[winerr_smoke] FormatMessageW      = ");
        Out(n > 0 ? "PASS\r\n" : "FAIL/STUB\r\n");
    }

    /* SetErrorMode + GetErrorMode round-trip. */
    {
        UINT prev = SetErrorMode(SEM_FAILCRITICALERRORS);
        UINT now = GetErrorMode();
        Out("[winerr_smoke] SetErrorMode + Get  = ");
        Out(now == SEM_FAILCRITICALERRORS ? "PASS\r\n" : "FAIL/STUB\r\n");
        SetErrorMode(prev);
    }

    Out("[winerr_smoke] done\r\n");
    ExitProcess(0);
}
