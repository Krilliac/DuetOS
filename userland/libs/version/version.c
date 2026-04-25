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

/* GetFileVersionInfoExW(flags, file, hnd, len, data) — newer Win32
 * 8.1+ entry point, same v0 stub semantics. */
__declspec(dllexport) BOOL GetFileVersionInfoExW(DWORD flags, const wchar_t16* file, DWORD hnd, DWORD len, void* data)
{
    (void)flags;
    (void)file;
    (void)hnd;
    (void)len;
    (void)data;
    return 0;
}
__declspec(dllexport) BOOL GetFileVersionInfoExA(DWORD flags, const char* file, DWORD hnd, DWORD len, void* data)
{
    (void)flags;
    (void)file;
    (void)hnd;
    (void)len;
    (void)data;
    return 0;
}

/* VerLanguageNameA/W: human-readable name for a language ID.
 * v0 reports "Language Neutral" for every locale; matches what
 * Windows returns for LANG_NEUTRAL (0). */
__declspec(dllexport) DWORD VerLanguageNameA(DWORD lang, char* buf, DWORD buf_size)
{
    static const char kName[] = "Language Neutral";
    const DWORD need = sizeof(kName) - 1;
    (void)lang;
    if (!buf || buf_size == 0)
        return need;
    DWORD i = 0;
    for (; i + 1 < buf_size && kName[i]; ++i)
        buf[i] = kName[i];
    buf[i] = 0;
    return i;
}

__declspec(dllexport) DWORD VerLanguageNameW(DWORD lang, wchar_t16* buf, DWORD buf_size)
{
    static const char kName[] = "Language Neutral";
    const DWORD need = sizeof(kName) - 1;
    (void)lang;
    if (!buf || buf_size == 0)
        return need;
    DWORD i = 0;
    for (; i + 1 < buf_size && kName[i]; ++i)
        buf[i] = (wchar_t16)kName[i];
    buf[i] = 0;
    return i;
}
