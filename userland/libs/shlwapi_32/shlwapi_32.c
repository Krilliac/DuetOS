/* shlwapi_32.c — i386 shlwapi.dll v0 stubs. */
typedef int BOOL;

/* PathAppendA: append `lpszMore` to `pszPath` with a separator.
 * v0 walks until NUL, inserts a '\\', then copies. No quoting. */
__declspec(dllexport) BOOL __stdcall PathAppendA(char* pszPath, const char* lpszMore)
{
    if (!pszPath || !lpszMore)
        return 0;
    /* Find end of path. */
    char* p = pszPath;
    while (*p)
        ++p;
    /* If non-empty and doesn't already end in / or \, add separator. */
    if (p != pszPath && p[-1] != '\\' && p[-1] != '/')
        *p++ = '\\';
    while (*lpszMore)
        *p++ = *lpszMore++;
    *p = 0;
    return 1;
}
