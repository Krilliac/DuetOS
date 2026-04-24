/* wininet.dll — Wininet HTTP client. No network in v0; all ops fail. */
typedef int            BOOL;
typedef unsigned int   DWORD;
typedef void*          HANDLE;
typedef unsigned short wchar_t16;

__declspec(dllexport) HANDLE InternetOpenA(const char* agent, DWORD type, const char* proxy,
                                           const char* proxyBypass, DWORD flags)
{ (void) agent; (void) type; (void) proxy; (void) proxyBypass; (void) flags; return (HANDLE) 0; }
__declspec(dllexport) HANDLE InternetOpenW(const wchar_t16* agent, DWORD type, const wchar_t16* proxy,
                                           const wchar_t16* proxyBypass, DWORD flags)
{ (void) agent; (void) type; (void) proxy; (void) proxyBypass; (void) flags; return (HANDLE) 0; }
__declspec(dllexport) HANDLE InternetConnectA(HANDLE h, const char* server, unsigned short port, const char* user,
                                             const char* pw, DWORD svc, DWORD flags, unsigned long long ctx)
{ (void) h; (void) server; (void) port; (void) user; (void) pw; (void) svc; (void) flags; (void) ctx; return (HANDLE) 0; }
__declspec(dllexport) HANDLE HttpOpenRequestA(HANDLE h, const char* verb, const char* obj, const char* ver,
                                             const char* ref, const char** types, DWORD flags, unsigned long long ctx)
{ (void) h; (void) verb; (void) obj; (void) ver; (void) ref; (void) types; (void) flags; (void) ctx; return (HANDLE) 0; }
__declspec(dllexport) BOOL HttpSendRequestA(HANDLE h, const char* hdrs, DWORD hlen, void* opt, DWORD ol)
{ (void) h; (void) hdrs; (void) hlen; (void) opt; (void) ol; return 0; }
__declspec(dllexport) BOOL InternetReadFile(HANDLE h, void* buf, DWORD cb, DWORD* read)
{ (void) h; (void) buf; (void) cb; if (read) *read = 0; return 0; }
__declspec(dllexport) BOOL InternetCloseHandle(HANDLE h) { (void) h; return 1; }
__declspec(dllexport) HANDLE InternetOpenUrlA(HANDLE h, const char* url, const char* hdrs, DWORD hlen,
                                              DWORD flags, unsigned long long ctx)
{ (void) h; (void) url; (void) hdrs; (void) hlen; (void) flags; (void) ctx; return (HANDLE) 0; }
