/* userenv.dll — user environment. All stubs. */
typedef int BOOL;
typedef unsigned long DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

__declspec(dllexport) BOOL GetUserProfileDirectoryA(HANDLE token, char* path, DWORD* size)
{ (void) token; if (path) path[0] = 0; if (size) *size = 0; return 0; }
__declspec(dllexport) BOOL GetUserProfileDirectoryW(HANDLE token, wchar_t16* path, DWORD* size)
{ (void) token; if (path) path[0] = 0; if (size) *size = 0; return 0; }
__declspec(dllexport) BOOL GetAllUsersProfileDirectoryW(wchar_t16* path, DWORD* size)
{ if (path) path[0] = 0; if (size) *size = 0; return 0; }
__declspec(dllexport) BOOL CreateEnvironmentBlock(void** env_block, HANDLE token, BOOL inherit)
{ (void) token; (void) inherit; if (env_block) *env_block = (void*) 0; return 0; }
__declspec(dllexport) BOOL DestroyEnvironmentBlock(void* env_block) { (void) env_block; return 1; }
__declspec(dllexport) BOOL LoadUserProfileW(HANDLE token, void* profile_info) { (void) token; (void) profile_info; return 0; }
__declspec(dllexport) BOOL UnloadUserProfile(HANDLE token, HANDLE profile) { (void) token; (void) profile; return 1; }
