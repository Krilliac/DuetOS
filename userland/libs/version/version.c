/* version.dll — file version info. No PE resource parser; all fail. */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

__declspec(dllexport) DWORD GetFileVersionInfoSizeA(const char* file, DWORD* hnd)
{
    (void)file;
    if (hnd)
        *hnd = 0;
    return 0;
}
__declspec(dllexport) DWORD GetFileVersionInfoSizeW(const wchar_t16* file, DWORD* hnd)
{
    (void)file;
    if (hnd)
        *hnd = 0;
    return 0;
}
__declspec(dllexport) BOOL GetFileVersionInfoA(const char* file, DWORD hnd, DWORD len, void* data)
{
    (void)file;
    (void)hnd;
    (void)len;
    (void)data;
    return 0;
}
__declspec(dllexport) BOOL GetFileVersionInfoW(const wchar_t16* file, DWORD hnd, DWORD len, void* data)
{
    (void)file;
    (void)hnd;
    (void)len;
    (void)data;
    return 0;
}
__declspec(dllexport) BOOL VerQueryValueA(const void* block, const char* sub, void** ptr, unsigned int* len)
{
    (void)block;
    (void)sub;
    if (ptr)
        *ptr = (void*)0;
    if (len)
        *len = 0;
    return 0;
}
__declspec(dllexport) BOOL VerQueryValueW(const void* block, const wchar_t16* sub, void** ptr, unsigned int* len)
{
    (void)block;
    (void)sub;
    if (ptr)
        *ptr = (void*)0;
    if (len)
        *len = 0;
    return 0;
}
