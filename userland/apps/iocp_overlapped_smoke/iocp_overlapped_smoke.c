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
 *
 * Acceptance for T7-03 ("a PE using overlapped file reads
 * receives completion through GetQueuedCompletionStatus") is
 * exactly what this smoke checks.
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

#define TEST_KEY 0xCAFEBABEULL
#define TEST_PATH "/tmp/iocp_overlapped.tmp"
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

    CloseHandle(iocp);
    CloseHandle(rf);
    Out("[iocp_overlapped] done\r\n");
    ExitProcess(0);
}
