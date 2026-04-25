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

__declspec(dllexport) short GetFileTitleA(const char* file, char* title, unsigned short len)
{
    (void)file;
    (void)len;
    if (title)
        title[0] = 0;
    return 0;
}
__declspec(dllexport) short GetFileTitleW(const void* file, void* title, unsigned short len)
{
    (void)file;
    (void)len;
    if (title)
    {
        unsigned char* p = (unsigned char*)title;
        p[0] = 0;
        p[1] = 0;
    }
    return 0;
}
