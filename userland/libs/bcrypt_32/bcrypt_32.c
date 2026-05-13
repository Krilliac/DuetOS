/* bcrypt_32.c — i386 bcrypt.dll v0 stubs. */
typedef unsigned int DWORD;
typedef int NTSTATUS;
typedef void* HANDLE;
typedef unsigned char UCHAR;
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002

__declspec(dllexport) NTSTATUS __stdcall BCryptGenRandom(HANDLE algo, UCHAR* buf, DWORD len, DWORD flags)
{
    (void)algo;
    (void)flags;
    /* LCG entropy — same pattern as advapi32's SystemFunction036.
     * v0 acceptable for callers that just need "some bytes". */
    static unsigned ctr = 0xDEADBEEF;
    for (DWORD i = 0; i < len; ++i)
    {
        ctr = ctr * 1103515245u + 12345u;
        buf[i] = (UCHAR)(ctr >> 16);
    }
    return 0; /* STATUS_SUCCESS */
}
