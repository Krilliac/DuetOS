/* winhttp.dll — modern HTTP client. No network; all ops fail. */
typedef int            BOOL;
typedef unsigned int   DWORD;
typedef void*          HANDLE;
typedef unsigned short wchar_t16;

__declspec(dllexport) HANDLE WinHttpOpen(const wchar_t16* agent, DWORD accessType, const wchar_t16* proxy,
                                         const wchar_t16* bypass, DWORD flags)
{ (void) agent; (void) accessType; (void) proxy; (void) bypass; (void) flags; return (HANDLE) 0; }
__declspec(dllexport) HANDLE WinHttpConnect(HANDLE h, const wchar_t16* server, unsigned short port, DWORD rsv)
{ (void) h; (void) server; (void) port; (void) rsv; return (HANDLE) 0; }
__declspec(dllexport) HANDLE WinHttpOpenRequest(HANDLE h, const wchar_t16* verb, const wchar_t16* obj,
                                                const wchar_t16* ver, const wchar_t16* ref,
                                                const wchar_t16** types, DWORD flags)
{ (void) h; (void) verb; (void) obj; (void) ver; (void) ref; (void) types; (void) flags; return (HANDLE) 0; }
__declspec(dllexport) BOOL WinHttpSendRequest(HANDLE h, const wchar_t16* hdrs, DWORD hlen, void* opt, DWORD ol,
                                              DWORD total, unsigned long long ctx)
{ (void) h; (void) hdrs; (void) hlen; (void) opt; (void) ol; (void) total; (void) ctx; return 0; }
__declspec(dllexport) BOOL WinHttpReceiveResponse(HANDLE h, void* rsv) { (void) h; (void) rsv; return 0; }
__declspec(dllexport) BOOL WinHttpReadData(HANDLE h, void* buf, DWORD cb, DWORD* read)
{ (void) h; (void) buf; (void) cb; if (read) *read = 0; return 0; }
__declspec(dllexport) BOOL WinHttpCloseHandle(HANDLE h) { (void) h; return 1; }
