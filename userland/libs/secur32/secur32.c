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
__declspec(dllexport) BOOL GetUserNameExA(int name_format, char* name, DWORD* size)
{
    (void)name_format;
    if (name)
        name[0] = 0;
    if (size)
        *size = 0;
    return 0;
}
__declspec(dllexport) BOOL GetUserNameExW(int name_format, wchar_t16* name, DWORD* size)
{
    (void)name_format;
    if (name)
        name[0] = 0;
    if (size)
        *size = 0;
    return 0;
}
