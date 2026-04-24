/*
 * userland/libs/oleaut32/oleaut32.c — 5 BSTR + VARIANT stubs.
 *
 * BSTR is a length-prefixed UTF-16 string:
 *   [DWORD length_in_bytes][wchar_t chars...][u16 NUL]
 * SysAllocString returns a pointer to the CHARS (not the prefix).
 */

typedef unsigned int DWORD;
typedef unsigned long long SIZE_T;
typedef unsigned short wchar_t16;

/* VARIANT is a 16-byte tagged union. VariantInit sets vt = 0
 * (VT_EMPTY); VariantClear zeros the whole thing. */

__declspec(dllexport) void VariantInit(void* v)
{
    if (!v)
        return;
    unsigned char* b = (unsigned char*)v;
    for (int i = 0; i < 16; ++i)
        b[i] = 0;
}

__declspec(dllexport) unsigned long VariantClear(void* v)
{
    VariantInit(v);
    return 0; /* S_OK */
}

/* SysAllocString(str) -> BSTR. Allocate 4 + len*2 + 2 bytes on
 * the process heap; write the byte length at the start; copy
 * the chars; NUL-terminate; return pointer past the prefix. */
__declspec(dllexport) wchar_t16* SysAllocString(const wchar_t16* str)
{
    if (!str)
        return (wchar_t16*)0;
    /* Compute length. */
    SIZE_T n = 0;
    while (str[n])
        ++n;
    SIZE_T bytes = 4 + n * 2 + 2;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)bytes) : "memory");
    if (rv == 0)
        return (wchar_t16*)0;
    unsigned char* raw = (unsigned char*)rv;
    /* Write u32 length in bytes. */
    DWORD byte_len = (DWORD)(n * 2);
    for (int i = 0; i < 4; ++i)
        raw[i] = (unsigned char)(byte_len >> (i * 8));
    wchar_t16* chars = (wchar_t16*)(raw + 4);
    for (SIZE_T i = 0; i < n; ++i)
        chars[i] = str[i];
    chars[n] = 0;
    return chars;
}

__declspec(dllexport) void SysFreeString(wchar_t16* bstr)
{
    if (!bstr)
        return;
    /* Real pointer is 4 bytes before. */
    unsigned char* raw = ((unsigned char*)bstr) - 4;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)raw) : "memory");
}

__declspec(dllexport) unsigned int SysStringLen(const wchar_t16* bstr)
{
    if (!bstr)
        return 0;
    const unsigned char* raw = ((const unsigned char*)bstr) - 4;
    unsigned int byte_len = 0;
    for (int i = 0; i < 4; ++i)
        byte_len |= ((unsigned int)raw[i]) << (i * 8);
    return byte_len / 2; /* Return wchar count, not bytes. */
}
