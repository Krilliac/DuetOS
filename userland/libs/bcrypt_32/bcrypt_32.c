/* bcrypt_32.c — i386 bcrypt.dll v0 stubs. */
#include "../common/duet32_syscall.h"

/* SYS_RANDOM_BYTES (kernel/syscall/syscall.h) — kernel CSPRNG. */
#define SYS_RANDOM_BYTES 212

typedef unsigned int DWORD;
typedef int NTSTATUS;
typedef void* HANDLE;
typedef unsigned char UCHAR;
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002

/*
 * BCryptGenRandom is documented as a cryptographically secure RNG, so it must
 * draw from the kernel CSPRNG (SYS_RANDOM_BYTES, RDSEED/RDRAND seeded) or
 * fail. It previously ran the textbook glibc LCG
 *   ctr = ctr * 1103515245u + 12345u
 * and returned STATUS_SUCCESS, which is strictly worse than failing: callers
 * use this for key material, nonces and tokens, and a caller that sees an
 * error takes its failure path rather than shipping a predictable secret.
 *
 * STATUS_UNSUCCESSFUL on a short or failed fill — never a partial buffer
 * reported as success.
 */
__declspec(dllexport) NTSTATUS __stdcall BCryptGenRandom(HANDLE algo, UCHAR* buf, DWORD len, DWORD flags)
{
    (void)algo;
    (void)flags;
    if (len == 0)
        return 0; /* STATUS_SUCCESS */
    if (buf == 0)
        return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL */
    int wrote = duet_syscall2(SYS_RANDOM_BYTES, (unsigned)(unsigned long)buf, len);
    if (wrote < 0 || (DWORD)wrote != len)
        return (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL */
    return 0;                        /* STATUS_SUCCESS */
}
