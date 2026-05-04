/* comdlg32.dll — common dialog boxes. No UI; user "cancelled" every dialog. */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;

__declspec(dllexport) BOOL GetOpenFileNameA(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL GetOpenFileNameW(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL GetSaveFileNameA(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL GetSaveFileNameW(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL ChooseColorA(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL ChooseColorW(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL ChooseFontA(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL ChooseFontW(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL PrintDlgA(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL PrintDlgW(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) DWORD CommDlgExtendedError(void)
{
    return 0;
}

/* PageSetupDlg + ReplaceText + FindText: same "user cancelled"
 * stub semantic — return 0 / null-result and let the caller fall
 * through to a non-dialog path. */
__declspec(dllexport) BOOL PageSetupDlgA(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) BOOL PageSetupDlgW(void* p)
{
    (void)p;
    return 0;
}
__declspec(dllexport) HANDLE FindTextA(void* p)
{
    (void)p;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE FindTextW(void* p)
{
    (void)p;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE ReplaceTextA(void* p)
{
    (void)p;
    return (HANDLE)0;
}
__declspec(dllexport) HANDLE ReplaceTextW(void* p)
{
    (void)p;
    return (HANDLE)0;
}

/* GetFileTitleA / GetFileTitleW — extract the basename of a path,
 * stripping the trailing extension if present. The Win32 contract
 * is that the function copies the "title" portion to the buffer,
 * returns 0 on success, > 0 == required buffer size on too-small,
 * < 0 on error. We honour all three branches. */
__declspec(dllexport) short GetFileTitleA(const char* file, char* title, unsigned short len)
{
    if (!file)
        return -1;
    /* Find start of basename (after last separator). */
    const char* base = file;
    for (const char* p = file; *p; ++p)
    {
        if (*p == '\\' || *p == '/' || *p == ':')
            base = p + 1;
    }
    /* Find end of basename (last '.' if any, otherwise end of string). */
    const char* end = base;
    const char* dot = (const char*)0;
    while (*end)
    {
        if (*end == '.')
            dot = end;
        ++end;
    }
    const char* stop = dot ? dot : end;
    unsigned long n = (unsigned long)(stop - base);
    if (!title || len <= n)
        return (short)(n + 1);
    for (unsigned long i = 0; i < n; ++i)
        title[i] = base[i];
    title[n] = 0;
    return 0;
}
__declspec(dllexport) short GetFileTitleW(const void* file, void* title, unsigned short len)
{
    if (!file)
        return -1;
    const unsigned short* src = (const unsigned short*)file;
    const unsigned short* base = src;
    for (const unsigned short* p = src; *p; ++p)
    {
        if (*p == '\\' || *p == '/' || *p == ':')
            base = p + 1;
    }
    const unsigned short* end = base;
    const unsigned short* dot = (const unsigned short*)0;
    while (*end)
    {
        if (*end == '.')
            dot = end;
        ++end;
    }
    const unsigned short* stop = dot ? dot : end;
    unsigned long n = (unsigned long)(stop - base);
    if (!title || len <= n)
        return (short)(n + 1);
    unsigned short* dst = (unsigned short*)title;
    for (unsigned long i = 0; i < n; ++i)
        dst[i] = base[i];
    dst[n] = 0;
    return 0;
}
