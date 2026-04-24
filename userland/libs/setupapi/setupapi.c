/* setupapi.dll — device installation / INF parsing. All fail. */
typedef int            BOOL;
typedef unsigned int   DWORD;
typedef void*          HANDLE;
typedef unsigned short wchar_t16;

#define INVALID_HANDLE_VALUE ((HANDLE) (long long) -1)

__declspec(dllexport) HANDLE SetupDiGetClassDevsA(const void* guid, const char* enumerator, HANDLE parent, DWORD flags)
{ (void) guid; (void) enumerator; (void) parent; (void) flags; return INVALID_HANDLE_VALUE; }
__declspec(dllexport) HANDLE SetupDiGetClassDevsW(const void* guid, const wchar_t16* enumerator, HANDLE parent, DWORD flags)
{ (void) guid; (void) enumerator; (void) parent; (void) flags; return INVALID_HANDLE_VALUE; }
__declspec(dllexport) BOOL SetupDiDestroyDeviceInfoList(HANDLE h) { (void) h; return 1; }
__declspec(dllexport) BOOL SetupDiEnumDeviceInfo(HANDLE h, DWORD idx, void* info) { (void) h; (void) idx; (void) info; return 0; }
__declspec(dllexport) HANDLE SetupOpenInfFileA(const char* file, const char* cls, DWORD style, unsigned int* err_line)
{ (void) file; (void) cls; (void) style; if (err_line) *err_line = 0; return INVALID_HANDLE_VALUE; }
__declspec(dllexport) HANDLE SetupOpenInfFileW(const wchar_t16* file, const wchar_t16* cls, DWORD style, unsigned int* err_line)
{ (void) file; (void) cls; (void) style; if (err_line) *err_line = 0; return INVALID_HANDLE_VALUE; }
__declspec(dllexport) BOOL SetupCloseInfFile(HANDLE h) { (void) h; return 1; }
