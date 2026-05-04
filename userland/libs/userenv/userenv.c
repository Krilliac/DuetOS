/* userenv.dll — user environment. v0 reports a single fixed
 * "X:\\" profile root for callers that need a non-empty answer
 * to find a config file. */
typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned long HRESULT;
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

__declspec(dllexport) BOOL GetUserProfileDirectoryW(HANDLE token, wchar_t16* path, DWORD* size);

/* ExpandEnvironmentStringsForUserA / W — per-user expansion.
 * v0 has a single environment; just copy through. */
__declspec(dllexport) BOOL ExpandEnvironmentStringsForUserA(HANDLE token, const char* src, char* dst, DWORD dst_size)
{
    (void)token;
    if (!src)
    {
        if (dst && dst_size > 0)
            dst[0] = 0;
        return 1;
    }
    DWORD i = 0;
    if (dst != (char*)0 && dst_size > 0)
    {
        for (; src[i] != 0 && i + 1 < dst_size; ++i)
            dst[i] = src[i];
        dst[i] = 0;
    }
    return 1;
}

__declspec(dllexport) BOOL ExpandEnvironmentStringsForUserW(HANDLE token, const wchar_t16* src, wchar_t16* dst,
                                                            DWORD dst_size)
{
    (void)token;
    if (!src)
    {
        if (dst && dst_size > 0)
            dst[0] = 0;
        return 1;
    }
    DWORD i = 0;
    if (dst != (wchar_t16*)0 && dst_size > 0)
    {
        for (; src[i] != 0 && i + 1 < dst_size; ++i)
            dst[i] = src[i];
        dst[i] = 0;
    }
    return 1;
}

/* RefreshPolicy / RefreshPolicyEx / EnterCriticalPolicySection /
 * LeaveCriticalPolicySection — Group Policy hooks. v0 has no GP
 * engine; succeed with NULL section handle. */
__declspec(dllexport) BOOL RefreshPolicy(BOOL machine)
{
    (void)machine;
    return 1;
}

__declspec(dllexport) BOOL RefreshPolicyEx(BOOL machine, DWORD options)
{
    (void)machine;
    (void)options;
    return 1;
}

__declspec(dllexport) HANDLE EnterCriticalPolicySection(BOOL machine)
{
    (void)machine;
    return (HANDLE)1; /* sentinel */
}

__declspec(dllexport) BOOL LeaveCriticalPolicySection(HANDLE section)
{
    (void)section;
    return 1;
}

/* GetGPOListW — Group Policy Object list. Empty + S_OK so the
 * caller treats the user as policy-clean. */
__declspec(dllexport) BOOL GetGPOListW(HANDLE token, const wchar_t16* name, const wchar_t16* host_name,
                                       const wchar_t16* class_name, DWORD flags, void** gpo_list)
{
    (void)token;
    (void)name;
    (void)host_name;
    (void)class_name;
    (void)flags;
    if (gpo_list)
        *gpo_list = (void*)0;
    return 1;
}

__declspec(dllexport) BOOL FreeGPOListW(void* gpo_list)
{
    (void)gpo_list;
    return 1;
}

__declspec(dllexport) BOOL GetAppliedGPOListW(DWORD flags, const wchar_t16* machine_name, void* sid_user,
                                              const void* guid_extension_or_snapin, void** gpo_list)
{
    (void)flags;
    (void)machine_name;
    (void)sid_user;
    (void)guid_extension_or_snapin;
    if (gpo_list)
        *gpo_list = (void*)0;
    return 1;
}

/* RegisterGPNotification / UnregisterGPNotification — wait on
 * GP changes. v0: never fires. */
__declspec(dllexport) BOOL RegisterGPNotification(HANDLE event, BOOL machine)
{
    (void)event;
    (void)machine;
    return 1;
}

__declspec(dllexport) BOOL UnregisterGPNotification(HANDLE event)
{
    (void)event;
    return 1;
}

/* CreateProfile — Vista+. v0 doesn't store profiles; report
 * "already exists" via ERROR_ALREADY_EXISTS-equivalent HRESULT. */
__declspec(dllexport) HRESULT CreateProfile(const wchar_t16* user_sid, const wchar_t16* user_name, wchar_t16* path_buf,
                                            DWORD path_size)
{
    (void)user_sid;
    (void)user_name;
    if (path_buf && path_size > 0)
    {
        return GetUserProfileDirectoryW((HANDLE)0, path_buf, &path_size) ? 0UL : 0UL;
    }
    return 0UL;
}

__declspec(dllexport) BOOL DeleteProfileW(const wchar_t16* sid_string, const wchar_t16* profile_path,
                                          const wchar_t16* computer_name)
{
    (void)sid_string;
    (void)profile_path;
    (void)computer_name;
    return 1;
}

/* GetProfileType — single-user system. Always reports
 * PT_TEMPORARY = 0x00 (no roaming, no mandatory). */
__declspec(dllexport) BOOL GetProfileType(DWORD* flags)
{
    if (flags)
        *flags = 0;
    return 1;
}

/* GetUserProfileDirectoryW prototype already defined in this TU
 * but we want the local helper too. */
__declspec(dllexport) BOOL GetProfilesDirectoryA(char* path, DWORD* size)
{
    return profile_a(path, size);
}

__declspec(dllexport) BOOL GetDefaultUserProfileDirectoryA(char* path, DWORD* size)
{
    return profile_a(path, size);
}
