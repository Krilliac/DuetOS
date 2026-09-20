/*
 * iocp_overlapped_smoke — verify T7-03 file→IOCP binding +
 * OVERLAPPED-aware ReadFile/WriteFile completion routing.
 *
 *   1. Create a file, write a known byte pattern.
 *   2. Re-open the file, bind it to an IOCP via
 *      CreateIoCompletionPort(hFile, hExisting, key, ...).
 *   3. Issue a ReadFile with a non-NULL OVERLAPPED.
 *   4. Drain the IOCP via GetQueuedCompletionStatus and
 *      verify (key, OVERLAPPED*, bytes) match.
 *   5. Exercise GetOverlappedResult / Ex success, pending,
 *      terminal-failure, and invalid-argument contracts.
 *
 * Acceptance for T7-03 ("a PE using overlapped file reads
 * receives completion through GetQueuedCompletionStatus") is
 * exactly what this smoke checks.
 */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#include <windows.h>

#define TEST_STATUS_PENDING ((ULONG_PTR)0x00000103UL)
#define TEST_STATUS_UNSUCCESSFUL ((ULONG_PTR)0xC0000001UL)

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

#define TEST_KEY 0xCAFEBABEULL
#define TEST_PATH "/disk/0/IOCPOVL.BIN"
#define TEST_BYTES 32

void __cdecl mainCRTStartup(void)
{
    Out("[iocp_overlapped] starting\r\n");

    /* 1. Write the test file. */
    HANDLE wf = CreateFileA(TEST_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (wf == INVALID_HANDLE_VALUE)
    {
        Out("[iocp_overlapped] CreateFileA(write) FAIL\r\n");
        ExitProcess(1);
    }
    CloseHandle(wf);
    wf = CreateFileA(TEST_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (wf == INVALID_HANDLE_VALUE || GetLastError() != ERROR_ALREADY_EXISTS)
    {
        Out("[iocp_overlapped] CreateFileA(replace) FAIL\r\n");
        ExitProcess(1);
    }
    char payload[TEST_BYTES];
    for (int i = 0; i < TEST_BYTES; ++i)
        payload[i] = (char)('A' + (i & 0x1F));
    DWORD wrote = 0;
    BOOL wr_ok = WriteFile(wf, payload, TEST_BYTES, &wrote, NULL);
    CloseHandle(wf);
    if (!wr_ok || wrote != TEST_BYTES)
    {
        Out("[iocp_overlapped] WriteFile FAIL\r\n");
        ExitProcess(1);
    }
    Out("[iocp_overlapped] WriteFile               = PASS\r\n");

    /* 2. Re-open + bind to a fresh IOCP. */
    HANDLE rf = CreateFileA(TEST_PATH, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (rf == INVALID_HANDLE_VALUE)
    {
        Out("[iocp_overlapped] CreateFileA(read) FAIL\r\n");
        ExitProcess(1);
    }
    HANDLE iocp = CreateIoCompletionPort(rf, NULL, TEST_KEY, 1);
    if (iocp == NULL)
    {
        Out("[iocp_overlapped] CreateIoCompletionPort FAIL\r\n");
        CloseHandle(rf);
        ExitProcess(1);
    }
    Out("[iocp_overlapped] CreateIoCompletionPort  = PASS\r\n");

    /* 3. ReadFile with OVERLAPPED. */
    char buf[TEST_BYTES];
    OVERLAPPED ov;
    for (unsigned i = 0; i < sizeof(ov); ++i)
        ((unsigned char*)&ov)[i] = 0;
    ov.Offset = 0;
    ov.OffsetHigh = 0;
    DWORD rd = 0;
    BOOL rd_ok = ReadFile(rf, buf, TEST_BYTES, &rd, &ov);
    if (!rd_ok || rd != TEST_BYTES)
    {
        Out("[iocp_overlapped] ReadFile(OVERLAPPED) FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }
    Out("[iocp_overlapped] ReadFile(OVERLAPPED)    = PASS\r\n");

    /* Verify payload round-trips byte-for-byte. */
    for (int i = 0; i < TEST_BYTES; ++i)
    {
        if (buf[i] != payload[i])
        {
            Out("[iocp_overlapped] payload mismatch FAIL\r\n");
            CloseHandle(iocp);
            CloseHandle(rf);
            ExitProcess(1);
        }
    }
    Out("[iocp_overlapped] payload round-trip      = PASS\r\n");

    /* 4. Drain the IOCP. */
    DWORD got_bytes = 0;
    ULONG_PTR got_key = 0;
    OVERLAPPED* got_ov = NULL;
    BOOL drained = GetQueuedCompletionStatus(iocp, &got_bytes, &got_key, &got_ov, 1000);
    if (!drained)
    {
        Out("[iocp_overlapped] GetQueuedCompletionStatus FAIL (no completion)\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }
    if (got_bytes != TEST_BYTES || got_key != TEST_KEY || got_ov != &ov)
    {
        Out("[iocp_overlapped] completion content mismatch FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }
    Out("[iocp_overlapped] completion delivery     = PASS\r\n");

    /* OVERLAPPED.Internal / InternalHigh should also have been
     * stamped by the I/O. */
    if (ov.InternalHigh != TEST_BYTES)
    {
        Out("[iocp_overlapped] OVERLAPPED.InternalHigh mismatch FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }
    Out("[iocp_overlapped] OVERLAPPED stamping     = PASS\r\n");

    /* 5. Completed operations surface their byte count through both
     * result APIs without clobbering an unrelated prior last-error. */
    DWORD result_bytes = 0xFFFFFFFFUL;
    SetLastError(0x2468UL);
    if (!GetOverlappedResult(rf, &ov, &result_bytes, FALSE) || result_bytes != TEST_BYTES || GetLastError() != 0x2468UL)
    {
        Out("[iocp_overlapped] GetOverlappedResult success FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }

    result_bytes = 0xFFFFFFFFUL;
    SetLastError(0x1357UL);
    if (!GetOverlappedResultEx(rf, &ov, &result_bytes, 0, FALSE) || result_bytes != TEST_BYTES ||
        GetLastError() != 0x1357UL)
    {
        Out("[iocp_overlapped] GetOverlappedResultEx success FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }
    Out("[iocp_overlapped] result success semantics = PASS\r\n");

    OVERLAPPED pending;
    for (unsigned i = 0; i < sizeof(pending); ++i)
        ((unsigned char*)&pending)[i] = 0;
    pending.Internal = TEST_STATUS_PENDING;
    pending.InternalHigh = 0x1234UL;

    result_bytes = 0xA5A5A5A5UL;
    SetLastError(ERROR_SUCCESS);
    if (GetOverlappedResult(rf, &pending, &result_bytes, FALSE) || GetLastError() != ERROR_IO_INCOMPLETE ||
        result_bytes != 0xA5A5A5A5UL)
    {
        Out("[iocp_overlapped] GetOverlappedResult pending FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }

    result_bytes = 0x5A5A5A5AUL;
    SetLastError(ERROR_SUCCESS);
    if (GetOverlappedResultEx(rf, &pending, &result_bytes, 1, TRUE) || GetLastError() != ERROR_IO_INCOMPLETE ||
        result_bytes != 0x5A5A5A5AUL)
    {
        Out("[iocp_overlapped] GetOverlappedResultEx pending FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }
    Out("[iocp_overlapped] result pending semantics = PASS\r\n");

    OVERLAPPED failed;
    for (unsigned i = 0; i < sizeof(failed); ++i)
        ((unsigned char*)&failed)[i] = 0;
    failed.Internal = TEST_STATUS_UNSUCCESSFUL;
    failed.InternalHigh = 7;
    result_bytes = 0;
    SetLastError(ERROR_SUCCESS);
    if (GetOverlappedResult(rf, &failed, &result_bytes, FALSE) || GetLastError() != ERROR_GEN_FAILURE ||
        result_bytes != 7)
    {
        Out("[iocp_overlapped] result terminal failure FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }

    result_bytes = 0x11223344UL;
    SetLastError(ERROR_SUCCESS);
    if (GetOverlappedResult(rf, NULL, &result_bytes, FALSE) || GetLastError() != ERROR_INVALID_PARAMETER ||
        result_bytes != 0x11223344UL)
    {
        Out("[iocp_overlapped] result invalid parameter FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }

    result_bytes = 0x55667788UL;
    SetLastError(ERROR_SUCCESS);
    if (GetOverlappedResult((HANDLE)(ULONG_PTR)0x7FFF0100UL, &ov, &result_bytes, FALSE) ||
        GetLastError() != ERROR_INVALID_HANDLE || result_bytes != 0x55667788UL)
    {
        Out("[iocp_overlapped] result invalid handle FAIL\r\n");
        CloseHandle(iocp);
        CloseHandle(rf);
        ExitProcess(1);
    }
    Out("[iocp_overlapped] result failure semantics = PASS\r\n");

    CloseHandle(iocp);
    CloseHandle(rf);
    Out("[ring3-iocp-overlapped-smoke] PASS\r\n");
    ExitProcess(0);
}
