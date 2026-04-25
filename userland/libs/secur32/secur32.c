/* secur32.dll — Security Support Provider Interface. All stubs. */
typedef int BOOL;
typedef unsigned long DWORD;
typedef unsigned long SECURITY_STATUS;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define SEC_E_OK 0UL
#define SEC_E_UNSUPPORTED_FUNCTION 0x80090302UL

__declspec(dllexport) SECURITY_STATUS AcquireCredentialsHandleA(const char* principal, const char* package,
                                                                DWORD cred_use, void* logon_id, void* auth_data,
                                                                void* get_key_fn, void* get_key_arg, void* cred,
                                                                void* expiry)
{
    (void)principal;
    (void)package;
    (void)cred_use;
    (void)logon_id;
    (void)auth_data;
    (void)get_key_fn;
    (void)get_key_arg;
    (void)cred;
    (void)expiry;
    return SEC_E_UNSUPPORTED_FUNCTION;
}
__declspec(dllexport) SECURITY_STATUS FreeCredentialsHandle(void* cred)
{
    (void)cred;
    return SEC_E_OK;
}
__declspec(dllexport) SECURITY_STATUS InitializeSecurityContextA(void* cred, void* ctx, const char* target,
                                                                 DWORD fContextReq, DWORD reserved1, DWORD target_dr,
                                                                 void* input, DWORD reserved2, void* new_ctx,
                                                                 void* output, DWORD* attrs, void* expiry)
{
    (void)cred;
    (void)ctx;
    (void)target;
    (void)fContextReq;
    (void)reserved1;
    (void)target_dr;
    (void)input;
    (void)reserved2;
    (void)new_ctx;
    (void)output;
    (void)expiry;
    if (attrs)
        *attrs = 0;
    return SEC_E_UNSUPPORTED_FUNCTION;
}
__declspec(dllexport) SECURITY_STATUS DeleteSecurityContext(void* ctx)
{
    (void)ctx;
    return SEC_E_OK;
}
/* GetUserNameEx{A,W}: return "duetos" for any requested name
 * format. Apps that read this to label log lines / window titles
 * see a non-empty answer instead of treating the empty string
 * as an error. */
__declspec(dllexport) BOOL GetUserNameExA(int name_format, char* name, DWORD* size)
{
    static const char kName[] = "duetos";
    const DWORD need = sizeof(kName);
    (void)name_format;
    if (!size)
        return 0;
    if (!name || *size < need)
    {
        *size = need;
        return 0;
    }
    for (DWORD i = 0; i < need; ++i)
        name[i] = kName[i];
    *size = need - 1;
    return 1;
}
__declspec(dllexport) BOOL GetUserNameExW(int name_format, wchar_t16* name, DWORD* size)
{
    static const char kName[] = "duetos";
    const DWORD need = sizeof(kName);
    (void)name_format;
    if (!size)
        return 0;
    if (!name || *size < need)
    {
        *size = need;
        return 0;
    }
    for (DWORD i = 0; i < need; ++i)
        name[i] = (wchar_t16)kName[i];
    *size = need - 1;
    return 1;
}

/* AcceptSecurityContext / EnumerateSecurityPackagesA/W: round
 * out the SSPI surface so callers don't trip on first-call
 * probe failures. */
__declspec(dllexport) SECURITY_STATUS AcceptSecurityContext(void* cred, void* ctx, void* input, DWORD fContextReq,
                                                            DWORD target_dr, void* new_ctx, void* output, DWORD* attrs,
                                                            void* expiry)
{
    (void)cred;
    (void)ctx;
    (void)input;
    (void)fContextReq;
    (void)target_dr;
    (void)new_ctx;
    (void)output;
    (void)expiry;
    if (attrs)
        *attrs = 0;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

__declspec(dllexport) SECURITY_STATUS EnumerateSecurityPackagesA(unsigned long* num, void** packages)
{
    if (num)
        *num = 0;
    if (packages)
        *packages = (void*)0;
    return SEC_E_OK;
}

__declspec(dllexport) SECURITY_STATUS EnumerateSecurityPackagesW(unsigned long* num, void** packages)
{
    if (num)
        *num = 0;
    if (packages)
        *packages = (void*)0;
    return SEC_E_OK;
}

__declspec(dllexport) SECURITY_STATUS FreeContextBuffer(void* buf)
{
    (void)buf;
    return SEC_E_OK;
}

__declspec(dllexport) SECURITY_STATUS QueryContextAttributesA(void* ctx, DWORD attr, void* buf)
{
    (void)ctx;
    (void)attr;
    (void)buf;
    return SEC_E_UNSUPPORTED_FUNCTION;
}
