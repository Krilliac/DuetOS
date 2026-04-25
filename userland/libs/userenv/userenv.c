/* userenv.dll — user environment. v0 reports a single fixed
 * "X:\\" profile root for callers that need a non-empty answer
 * to find a config file. */
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

/* Helper: write the fixed "X:\\Users\\duetos" profile path into
 * the user buffer if it fits. Updates *size to chars-written +
 * NUL or required size. Matches Win32 GetUserProfileDirectoryW
 * semantics (FALSE + ERROR_INSUFFICIENT_BUFFER on too-small). */
static BOOL profile_w(wchar_t16* path, DWORD* size)
{
    static const char kPath[] = "X:\\Users\\duetos";
    const DWORD need = sizeof(kPath); /* chars including NUL */
    if (!size)
        return 0;
    if (!path || *size < need)
    {
        *size = need;
        return 0;
    }
    for (DWORD i = 0; i < need; ++i)
        path[i] = (wchar_t16)kPath[i];
    *size = need - 1;
    return 1;
}

static BOOL profile_a(char* path, DWORD* size)
{
    static const char kPath[] = "X:\\Users\\duetos";
    const DWORD need = sizeof(kPath);
    if (!size)
        return 0;
    if (!path || *size < need)
    {
        *size = need;
        return 0;
    }
    for (DWORD i = 0; i < need; ++i)
        path[i] = kPath[i];
    *size = need - 1;
    return 1;
}

__declspec(dllexport) BOOL GetUserProfileDirectoryA(HANDLE token, char* path, DWORD* size)
{
    (void)token;
    return profile_a(path, size);
}
__declspec(dllexport) BOOL GetUserProfileDirectoryW(HANDLE token, wchar_t16* path, DWORD* size)
{
    (void)token;
    return profile_w(path, size);
}
__declspec(dllexport) BOOL GetAllUsersProfileDirectoryA(char* path, DWORD* size)
{
    return profile_a(path, size);
}
__declspec(dllexport) BOOL GetAllUsersProfileDirectoryW(wchar_t16* path, DWORD* size)
{
    return profile_w(path, size);
}
__declspec(dllexport) BOOL GetDefaultUserProfileDirectoryW(wchar_t16* path, DWORD* size)
{
    return profile_w(path, size);
}
__declspec(dllexport) BOOL GetProfilesDirectoryW(wchar_t16* path, DWORD* size)
{
    return profile_w(path, size);
}
__declspec(dllexport) BOOL CreateEnvironmentBlock(void** env_block, HANDLE token, BOOL inherit)
{
    (void)token;
    (void)inherit;
    if (env_block)
        *env_block = (void*)0;
    return 0;
}
__declspec(dllexport) BOOL DestroyEnvironmentBlock(void* env_block)
{
    (void)env_block;
    return 1;
}
__declspec(dllexport) BOOL LoadUserProfileW(HANDLE token, void* profile_info)
{
    (void)token;
    (void)profile_info;
    return 0;
}
__declspec(dllexport) BOOL UnloadUserProfile(HANDLE token, HANDLE profile)
{
    (void)token;
    (void)profile;
    return 1;
}
