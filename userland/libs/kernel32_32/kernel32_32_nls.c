/*
 * userland/libs/kernel32_32/kernel32_32_nls.c
 *
 * __stdcall export wrappers for the code-page / collation core in
 * kernel32_32_nls.h. Every wrapper is calling-convention glue plus
 * the argument handling Win32 specifies at the API edge (the
 * lpUsedDefaultChar out-flag, the ignored locale / flag words); all
 * of the actual conversion lives in the header so it can be unit
 * tested on the host — see tests/host/test_kernel32_32_nls.cpp.
 */

#include "kernel32_32_internal.h"
#include "kernel32_32_nls.h"

__declspec(dllexport) int __stdcall MultiByteToWideChar(UINT CodePage, DWORD dwFlags, const char* lpMultiByteStr,
                                                        int cbMultiByte, wchar_t16* lpWideCharStr, int cchWideChar)
{
    (void)CodePage; /* 1:1 narrowing — see the GAP note in the header. */
    (void)dwFlags;  /* MB_PRECOMPOSED / MB_ERR_INVALID_CHARS are moot for 1:1. */
    return Duet32MultiByteToWideChar(lpMultiByteStr, cbMultiByte, (unsigned short*)lpWideCharStr, cchWideChar);
}

__declspec(dllexport) int __stdcall WideCharToMultiByte(UINT CodePage, DWORD dwFlags, const wchar_t16* lpWideCharStr,
                                                        int cchWideChar, char* lpMultiByteStr, int cbMultiByte,
                                                        const char* lpDefaultChar, BOOL* lpUsedDefaultChar)
{
    (void)CodePage;
    (void)dwFlags;
    (void)lpDefaultChar; /* Never consulted: the 1:1 mapping is total. */
    if (lpUsedDefaultChar != (BOOL*)0)
        *lpUsedDefaultChar = 0;
    return Duet32WideCharToMultiByte((const unsigned short*)lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte);
}

__declspec(dllexport) int __stdcall CompareStringW(unsigned long Locale, DWORD dwCmpFlags, const wchar_t16* lpString1,
                                                   int cchCount1, const wchar_t16* lpString2, int cchCount2)
{
    (void)Locale; /* Ordinal compare — see the GAP note in the header. */
    return Duet32CompareStringW(dwCmpFlags, (const unsigned short*)lpString1, cchCount1,
                                (const unsigned short*)lpString2, cchCount2);
}
