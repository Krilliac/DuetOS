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

/* SysStringByteLen: byte length stored in the prefix. */
__declspec(dllexport) unsigned int SysStringByteLen(const wchar_t16* bstr)
{
    if (!bstr)
        return 0;
    const unsigned char* raw = ((const unsigned char*)bstr) - 4;
    unsigned int byte_len = 0;
    for (int i = 0; i < 4; ++i)
        byte_len |= ((unsigned int)raw[i]) << (i * 8);
    return byte_len;
}

/* SysAllocStringLen(str, ui) — allocate a fixed-length BSTR. If
 * str is non-null, copy `ui` chars from it; else leave zeros. */
__declspec(dllexport) wchar_t16* SysAllocStringLen(const wchar_t16* str, unsigned int ui)
{
    SIZE_T bytes = 4 + (SIZE_T)ui * 2 + 2;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)bytes) : "memory");
    if (rv == 0)
        return (wchar_t16*)0;
    unsigned char* raw = (unsigned char*)rv;
    DWORD byte_len = (DWORD)(ui * 2);
    for (int i = 0; i < 4; ++i)
        raw[i] = (unsigned char)(byte_len >> (i * 8));
    wchar_t16* chars = (wchar_t16*)(raw + 4);
    if (str)
    {
        for (unsigned int i = 0; i < ui; ++i)
            chars[i] = str[i];
    }
    else
    {
        for (unsigned int i = 0; i < ui; ++i)
            chars[i] = 0;
    }
    chars[ui] = 0;
    return chars;
}

/* SysAllocStringByteLen(psz, len) — allocate from a byte buffer.
 * Treats len as a byte count (the chars need not be UTF-16). */
__declspec(dllexport) wchar_t16* SysAllocStringByteLen(const char* psz, unsigned int len)
{
    SIZE_T bytes = 4 + (SIZE_T)len + 2;
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)bytes) : "memory");
    if (rv == 0)
        return (wchar_t16*)0;
    unsigned char* raw = (unsigned char*)rv;
    DWORD byte_len = (DWORD)len;
    for (int i = 0; i < 4; ++i)
        raw[i] = (unsigned char)(byte_len >> (i * 8));
    unsigned char* body = raw + 4;
    if (psz)
    {
        for (unsigned int i = 0; i < len; ++i)
            body[i] = (unsigned char)psz[i];
    }
    else
    {
        for (unsigned int i = 0; i < len; ++i)
            body[i] = 0;
    }
    body[len] = 0;
    body[len + 1] = 0;
    return (wchar_t16*)body;
}

/* SysReAllocString(pbstr, str) — replace *pbstr with a fresh copy
 * of `str`. Returns 1/0 success. */
__declspec(dllexport) int SysReAllocString(wchar_t16** pbstr, const wchar_t16* str)
{
    if (!pbstr)
        return 0;
    wchar_t16* fresh = SysAllocString(str);
    if (str && !fresh)
        return 0;
    SysFreeString(*pbstr);
    *pbstr = fresh;
    return 1;
}

/* VariantCopy(dst, src) — discard dst then deep-copy src. v0 has
 * no VT_BSTR / VT_DISPATCH refcount handling, so the deep-copy
 * is just a flat 16-byte memcpy. Real OLE callers using BSTR /
 * IDispatch values would leak the source on copy; v0 workloads
 * don't hit that. */
__declspec(dllexport) unsigned long VariantCopy(void* dst, const void* src)
{
    if (!dst)
        return 0x80004003UL; /* E_POINTER */
    if (!src)
    {
        VariantInit(dst);
        return 0;
    }
    VariantClear(dst);
    const unsigned char* sb = (const unsigned char*)src;
    unsigned char* db = (unsigned char*)dst;
    for (int i = 0; i < 16; ++i)
        db[i] = sb[i];
    return 0;
}
