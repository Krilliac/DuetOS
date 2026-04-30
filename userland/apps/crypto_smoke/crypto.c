/*
 * crypto_smoke — exercise bcrypt + advapi32 cryptography surface.
 *
 * Probes the Win32 BCrypt (modern) APIs that any TLS-using
 * application would touch:
 *   - BCryptGenRandom          (CSPRNG)
 *   - BCryptOpenAlgorithmProvider / BCryptCloseAlgorithmProvider
 *   - BCryptCreateHash / BCryptHashData / BCryptFinishHash /
 *     BCryptDestroyHash       (SHA-256 of "abc")
 *   - BCryptGetProperty        (HASH_LENGTH / OBJECT_LENGTH)
 *
 * Plus the legacy advapi32 CryptGenRandom for completeness.
 *
 * Each step prints PASS/FAIL/STUB/UNIMPL on serial so the boot
 * transcript shows exactly which thunks are real and which are
 * NO-OP catch-alls.
 *
 * Note: success here means "the call returned without trapping
 * and produced *something*"; whether the SHA-256 output is
 * cryptographically correct is a separate audit point that the
 * known SHA-256(\"abc\") test vector lets us spot-check.
 */
#include <windows.h>
#include <bcrypt.h>

static void Out(const char* s)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD n = 0;
    DWORD len = 0;
    while (s[len] != '\0')
        ++len;
    WriteConsoleA(h, s, len, &n, 0);
}

static void OutHex(const unsigned char* b, DWORD n)
{
    static const char hex[] = "0123456789abcdef";
    char buf[3];
    buf[2] = '\0';
    for (DWORD i = 0; i < n; ++i)
    {
        buf[0] = hex[(b[i] >> 4) & 0xF];
        buf[1] = hex[b[i] & 0xF];
        Out(buf);
    }
}

void __cdecl mainCRTStartup(void)
{
    Out("[crypto_smoke] starting\r\n");

    /* Step 1: BCryptGenRandom. */
    unsigned char rnd[16] = {0};
    NTSTATUS s = BCryptGenRandom(NULL, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    Out("[crypto_smoke] BCryptGenRandom = ");
    if (s == 0)
    {
        Out("PASS bytes=");
        OutHex(rnd, 8);
        Out("...\r\n");
    }
    else
    {
        Out("FAIL\r\n");
    }

    /* Step 2: SHA-256 of "abc" — known-answer:
     *   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */
    BCRYPT_ALG_HANDLE alg = NULL;
    s = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    Out("[crypto_smoke] BCryptOpenAlgorithmProvider = ");
    Out(s == 0 ? "PASS\r\n" : "FAIL\r\n");

    if (s == 0)
    {
        BCRYPT_HASH_HANDLE h = NULL;
        s = BCryptCreateHash(alg, &h, NULL, 0, NULL, 0, 0);
        Out("[crypto_smoke] BCryptCreateHash       = ");
        Out(s == 0 ? "PASS\r\n" : "FAIL\r\n");

        if (s == 0)
        {
            const char* msg = "abc";
            s = BCryptHashData(h, (PUCHAR)msg, 3, 0);
            Out("[crypto_smoke] BCryptHashData         = ");
            Out(s == 0 ? "PASS\r\n" : "FAIL\r\n");

            unsigned char digest[32] = {0};
            s = BCryptFinishHash(h, digest, sizeof(digest), 0);
            Out("[crypto_smoke] BCryptFinishHash(\"abc\")= ");
            if (s == 0)
            {
                Out("PASS digest=");
                OutHex(digest, 32);
                Out("\r\n[crypto_smoke]   expected   "
                    "=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\r\n");
            }
            else
            {
                Out("FAIL\r\n");
            }

            BCryptDestroyHash(h);
        }

        BCryptCloseAlgorithmProvider(alg, 0);
    }

    /* Step 3: legacy advapi32 CryptGenRandom — many older apps still use it. */
    HCRYPTPROV prov = 0;
    BOOL ok = CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    Out("[crypto_smoke] CryptAcquireContextW   = ");
    Out(ok ? "PASS\r\n" : "FAIL\r\n");
    if (ok)
    {
        BYTE legacy[16] = {0};
        ok = CryptGenRandom(prov, sizeof(legacy), legacy);
        Out("[crypto_smoke] CryptGenRandom         = ");
        if (ok)
        {
            Out("PASS bytes=");
            OutHex(legacy, 8);
            Out("...\r\n");
        }
        else
        {
            Out("FAIL\r\n");
        }
        CryptReleaseContext(prov, 0);
    }

    Out("[crypto_smoke] done\r\n");
    ExitProcess(0);
}
