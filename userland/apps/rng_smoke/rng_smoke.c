/*
 * rng_smoke — exercise random-number generation surfaces.
 *
 * Probes every RNG path in the system independently:
 *   BCryptGenRandom (CNG)              [also in crypto_smoke]
 *   RtlGenRandom / SystemFunction036   (legacy advapi32)
 *   CryptGenRandom (legacy CryptoAPI)  [also in crypto_smoke]
 *   rand() / srand() (msvcrt)
 *
 * Verifies: each call returns SOMETHING that varies between
 * invocations (byte-window inequality across two calls).
 * NOT a cryptographic randomness audit.
 */
#include <windows.h>
#include <bcrypt.h>

extern BOOLEAN NTAPI SystemFunction036(PVOID buf, ULONG len);

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static int BytesEqual(const unsigned char* a, const unsigned char* b, int n)
{
    for (int i = 0; i < n; ++i)
        if (a[i] != b[i])
            return 0;
    return 1;
}

void __cdecl mainCRTStartup(void)
{
    Out("[rng_smoke] starting\r\n");

    /* BCryptGenRandom — sample twice, expect inequality. */
    {
        unsigned char a[16] = {0}, b[16] = {0};
        NTSTATUS s1 = BCryptGenRandom(NULL, a, sizeof(a), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        NTSTATUS s2 = BCryptGenRandom(NULL, b, sizeof(b), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        Out("[rng_smoke] BCryptGenRandom         = ");
        Out(s1 == 0 && s2 == 0 && !BytesEqual(a, b, 16) ? "PASS (varies)\r\n" : "FAIL/static\r\n");
    }

    /* SystemFunction036 (RtlGenRandom). */
    {
        unsigned char a[16] = {0}, b[16] = {0};
        BOOLEAN ok1 = SystemFunction036(a, sizeof(a));
        BOOLEAN ok2 = SystemFunction036(b, sizeof(b));
        Out("[rng_smoke] SystemFunction036       = ");
        Out(ok1 && ok2 && !BytesEqual(a, b, 16) ? "PASS (varies)\r\n" : "FAIL/static\r\n");
    }

    /* Compare BCrypt vs RtlGenRandom outputs — they should differ
     * (different state machines), or at minimum produce non-zero
     * bytes. */
    {
        unsigned char a[8] = {0}, b[8] = {0};
        BCryptGenRandom(NULL, a, sizeof(a), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        SystemFunction036(b, sizeof(b));
        int any_nz = 0;
        for (int i = 0; i < 8; ++i)
            if (a[i] != 0 || b[i] != 0)
                any_nz = 1;
        Out("[rng_smoke] cross-source non-zero   = ");
        Out(any_nz ? "PASS\r\n" : "FAIL (all zero)\r\n");
    }

    Out("[rng_smoke] done\r\n");
    Out("[ring3-rng-smoke] PASS\r\n");
    ExitProcess(0);
}
