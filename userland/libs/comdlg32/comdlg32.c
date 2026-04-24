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
