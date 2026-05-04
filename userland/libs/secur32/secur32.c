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

__declspec(dllexport) SECURITY_STATUS QueryContextAttributesW(void* ctx, DWORD attr, void* buf)
{
    (void)ctx;
    (void)attr;
    (void)buf;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

__declspec(dllexport) SECURITY_STATUS QuerySecurityPackageInfoA(const char* pkg, void** info)
{
    (void)pkg;
    if (info)
        *info = (void*)0;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

__declspec(dllexport) SECURITY_STATUS QuerySecurityPackageInfoW(const wchar_t16* pkg, void** info)
{
    (void)pkg;
    if (info)
        *info = (void*)0;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

/* Wide variants of the credential and SCI calls. */
__declspec(dllexport) SECURITY_STATUS AcquireCredentialsHandleW(const wchar_t16* principal, const wchar_t16* package,
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

__declspec(dllexport) SECURITY_STATUS InitializeSecurityContextW(void* cred, void* ctx, const wchar_t16* target,
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

/* Lsa* — the legacy LSA call surface. v0 reports
 * "not implemented" as an honest answer. */
__declspec(dllexport) SECURITY_STATUS LsaConnectUntrusted(HANDLE* lsa_handle)
{
    if (lsa_handle)
        *lsa_handle = (HANDLE)0;
    return 0xC0000002UL; /* STATUS_NOT_IMPLEMENTED */
}

__declspec(dllexport) SECURITY_STATUS LsaDeregisterLogonProcess(HANDLE lsa_handle)
{
    (void)lsa_handle;
    return 0; /* STATUS_SUCCESS */
}

__declspec(dllexport) SECURITY_STATUS LsaLookupAuthenticationPackage(HANDLE lsa_handle, void* pkg_name,
                                                                     unsigned long* auth_pkg)
{
    (void)lsa_handle;
    (void)pkg_name;
    if (auth_pkg)
        *auth_pkg = 0;
    return 0xC0000002UL;
}

__declspec(dllexport) SECURITY_STATUS LsaCallAuthenticationPackage(HANDLE lsa_handle, unsigned long auth_pkg,
                                                                   void* in_buf, unsigned long in_len, void** out_buf,
                                                                   unsigned long* out_len, SECURITY_STATUS* sub_status)
{
    (void)lsa_handle;
    (void)auth_pkg;
    (void)in_buf;
    (void)in_len;
    if (out_buf)
        *out_buf = (void*)0;
    if (out_len)
        *out_len = 0;
    if (sub_status)
        *sub_status = 0;
    return 0xC0000002UL;
}

__declspec(dllexport) SECURITY_STATUS LsaFreeReturnBuffer(void* buf)
{
    (void)buf;
    return 0;
}

__declspec(dllexport) SECURITY_STATUS LsaRegisterLogonProcess(void* logon_proc_name, HANDLE* lsa_handle,
                                                              unsigned long* security_mode)
{
    (void)logon_proc_name;
    if (lsa_handle)
        *lsa_handle = (HANDLE)0;
    if (security_mode)
        *security_mode = 0;
    return 0xC0000002UL;
}

__declspec(dllexport) SECURITY_STATUS LsaLogonUser(HANDLE lsa_handle, void* origin_name, unsigned int logon_type,
                                                   unsigned long auth_pkg, void* auth_info, unsigned long auth_info_len,
                                                   void* local_groups, void* source_ctx, void** profile_buf,
                                                   unsigned long* profile_buf_len, void* logon_id, HANDLE* token,
                                                   void* quotas, SECURITY_STATUS* sub_status)
{
    (void)lsa_handle;
    (void)origin_name;
    (void)logon_type;
    (void)auth_pkg;
    (void)auth_info;
    (void)auth_info_len;
    (void)local_groups;
    (void)source_ctx;
    if (profile_buf)
        *profile_buf = (void*)0;
    if (profile_buf_len)
        *profile_buf_len = 0;
    (void)logon_id;
    if (token)
        *token = (HANDLE)0;
    (void)quotas;
    if (sub_status)
        *sub_status = 0;
    return 0xC0000002UL;
}

/* TranslateNameA/W — name format conversion. v0 reports
 * "no mapping found". */
__declspec(dllexport) BOOL TranslateNameA(const char* in_name, int in_format, int desired_format, char* out_name,
                                          unsigned long* out_size)
{
    (void)in_name;
    (void)in_format;
    (void)desired_format;
    if (out_name && out_size && *out_size > 0)
        out_name[0] = 0;
    if (out_size)
        *out_size = 0;
    return 0;
}

__declspec(dllexport) BOOL TranslateNameW(const wchar_t16* in_name, int in_format, int desired_format,
                                          wchar_t16* out_name, unsigned long* out_size)
{
    (void)in_name;
    (void)in_format;
    (void)desired_format;
    if (out_name && out_size && *out_size > 0)
        out_name[0] = 0;
    if (out_size)
        *out_size = 0;
    return 0;
}

/* CompleteAuthToken / ImpersonateSecurityContext / RevertSecurityContext */
__declspec(dllexport) SECURITY_STATUS CompleteAuthToken(void* ctx, void* token)
{
    (void)ctx;
    (void)token;
    return SEC_E_OK;
}

__declspec(dllexport) SECURITY_STATUS ImpersonateSecurityContext(void* ctx)
{
    (void)ctx;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

__declspec(dllexport) SECURITY_STATUS RevertSecurityContext(void* ctx)
{
    (void)ctx;
    return SEC_E_OK;
}

/* MakeSignature / VerifySignature / EncryptMessage / DecryptMessage — SSPI message ops. */
__declspec(dllexport) SECURITY_STATUS MakeSignature(void* ctx, DWORD qop, void* msg, DWORD seq)
{
    (void)ctx;
    (void)qop;
    (void)msg;
    (void)seq;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

__declspec(dllexport) SECURITY_STATUS VerifySignature(void* ctx, void* msg, DWORD seq, DWORD* qop)
{
    (void)ctx;
    (void)msg;
    (void)seq;
    if (qop)
        *qop = 0;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

__declspec(dllexport) SECURITY_STATUS EncryptMessage(void* ctx, DWORD qop, void* msg, DWORD seq)
{
    (void)ctx;
    (void)qop;
    (void)msg;
    (void)seq;
    return SEC_E_UNSUPPORTED_FUNCTION;
}

__declspec(dllexport) SECURITY_STATUS DecryptMessage(void* ctx, void* msg, DWORD seq, DWORD* qop)
{
    (void)ctx;
    (void)msg;
    (void)seq;
    if (qop)
        *qop = 0;
    return SEC_E_UNSUPPORTED_FUNCTION;
}
