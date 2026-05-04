/* crypt32.dll — certificate / CMS stubs. All fail. */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

__declspec(dllexport) HANDLE CertOpenStore(const void* prov, DWORD enc, HANDLE hcp, DWORD flags, const void* para)
{
    (void)prov;
    (void)enc;
    (void)hcp;
    (void)flags;
    (void)para;
    return (HANDLE)0;
}
__declspec(dllexport) BOOL CertCloseStore(HANDLE h, DWORD flags)
{
    (void)h;
    (void)flags;
    return 1;
}
__declspec(dllexport) const void* CertFindCertificateInStore(HANDLE h, DWORD enc, DWORD flags, DWORD find_type,
                                                             const void* p, const void* prev)
{
    (void)h;
    (void)enc;
    (void)flags;
    (void)find_type;
    (void)p;
    (void)prev;
    return (void*)0;
}
__declspec(dllexport) BOOL CertFreeCertificateContext(const void* ctx)
{
    (void)ctx;
    return 1;
}
__declspec(dllexport) BOOL CryptAcquireContextA(unsigned long long* h, const char* ct, const char* prov, DWORD type,
                                                DWORD flags)
{
    (void)ct;
    (void)prov;
    (void)type;
    (void)flags;
    if (h)
        *h = 0xC597001ULL; /* sentinel CSP handle */
    return 1;
}

typedef unsigned short wchar_t16;
__declspec(dllexport) BOOL CryptAcquireContextW(unsigned long long* h, const wchar_t16* ct, const wchar_t16* prov,
                                                DWORD type, DWORD flags)
{
    (void)ct;
    (void)prov;
    (void)type;
    (void)flags;
    if (h)
        *h = 0xC597001ULL;
    return 1;
}
__declspec(dllexport) BOOL CryptReleaseContext(unsigned long long h, DWORD flags)
{
    (void)h;
    (void)flags;
    return 1;
}
__declspec(dllexport) BOOL CryptGenRandom(unsigned long long h, DWORD len, unsigned char* buf)
{
    (void)h;
    if (!buf || len == 0)
        return 1;
    /* Tick-mixed SPLITMIX64. The kernel performance counter
     * (SYS_PERF_COUNTER, 100 Hz) is XORed into the state on
     * every call so the output isn't a static repeat sequence
     * across the process lifetime. Still NOT cryptographic —
     * crypto callers should route through bcrypt's rdrand path. */
    static unsigned long long s = 0xA5A5A5A5A5A5A5A5ULL;
    long long ticks;
    __asm__ volatile("int $0x80" : "=a"(ticks) : "a"((long long)13) : "memory");
    s ^= (unsigned long long)ticks;
    for (DWORD i = 0; i < len; ++i)
    {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        buf[i] = (unsigned char)(s >> 56);
    }
    return 1;
}
__declspec(dllexport) BOOL CryptProtectData(void* in, const wchar_t16* desc, void* entropy, void* reserved,
                                            void* prompt, DWORD flags, void* out)
{
    (void)in;
    (void)desc;
    (void)entropy;
    (void)reserved;
    (void)prompt;
    (void)flags;
    (void)out;
    return 0;
}
__declspec(dllexport) BOOL CryptUnprotectData(void* in, wchar_t16** desc, void* entropy, void* reserved, void* prompt,
                                              DWORD flags, void* out)
{
    (void)in;
    (void)desc;
    (void)entropy;
    (void)reserved;
    (void)prompt;
    (void)flags;
    (void)out;
    return 0;
}

__declspec(dllexport) BOOL CryptStringToBinaryA(const char* str, DWORD str_len, DWORD flags, unsigned char* binary,
                                                DWORD* binary_size, DWORD* skip, DWORD* used_flags)
{
    (void)str;
    (void)str_len;
    (void)flags;
    (void)binary;
    if (binary_size)
        *binary_size = 0;
    if (skip)
        *skip = 0;
    if (used_flags)
        *used_flags = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptBinaryToStringA(const unsigned char* binary, DWORD binary_size, DWORD flags, char* str,
                                                DWORD* str_len)
{
    (void)binary;
    (void)binary_size;
    (void)flags;
    (void)str;
    if (str_len)
        *str_len = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptCreateHash(unsigned long long h, DWORD algid, unsigned long long key, DWORD flags,
                                           unsigned long long* hash)
{
    (void)h;
    (void)algid;
    (void)key;
    (void)flags;
    if (hash)
        *hash = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptHashData(unsigned long long h, const unsigned char* data, DWORD len, DWORD flags)
{
    (void)h;
    (void)data;
    (void)len;
    (void)flags;
    return 0;
}

__declspec(dllexport) BOOL CryptDestroyHash(unsigned long long h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL CryptGetHashParam(unsigned long long h, DWORD param, unsigned char* buf, DWORD* len,
                                             DWORD flags)
{
    (void)h;
    (void)param;
    (void)buf;
    (void)flags;
    if (len)
        *len = 0;
    return 0;
}

__declspec(dllexport) const void* CertEnumCertificatesInStore(HANDLE store, const void* prev)
{
    (void)store;
    (void)prev;
    return (void*)0;
}

__declspec(dllexport) DWORD CertGetNameStringW(const void* ctx, DWORD type, DWORD flags, void* type_param,
                                               wchar_t16* name, DWORD name_len)
{
    (void)ctx;
    (void)type;
    (void)flags;
    (void)type_param;
    (void)name_len;
    if (name)
        name[0] = 0;
    return 1; /* "" + NUL char count */
}

__declspec(dllexport) BOOL CertVerifyCertificateChainPolicy(const void* policy, void* chain, void* params, void* status)
{
    (void)policy;
    (void)chain;
    (void)params;
    if (status)
    {
        unsigned char* p = (unsigned char*)status;
        for (int i = 0; i < 16; ++i)
            p[i] = 0;
    }
    return 1; /* "policy succeeded" — caller still inspects status. */
}

/* Wide-name & extended cert helpers. */
__declspec(dllexport) DWORD CertGetNameStringA(const void* ctx, DWORD type, DWORD flags, void* type_param, char* name,
                                               DWORD name_len)
{
    (void)ctx;
    (void)type;
    (void)flags;
    (void)type_param;
    (void)name_len;
    if (name)
        name[0] = 0;
    return 1;
}

__declspec(dllexport) BOOL CertGetCertificateContextProperty(const void* ctx, DWORD prop_id, void* data,
                                                             DWORD* data_size)
{
    (void)ctx;
    (void)prop_id;
    (void)data;
    if (data_size)
        *data_size = 0;
    return 0;
}

__declspec(dllexport) BOOL CertSetCertificateContextProperty(const void* ctx, DWORD prop_id, DWORD flags,
                                                             const void* data)
{
    (void)ctx;
    (void)prop_id;
    (void)flags;
    (void)data;
    return 0;
}

__declspec(dllexport) BOOL CertControlStore(HANDLE store, DWORD flags, DWORD ctrl_type, const void* ctrl_para)
{
    (void)store;
    (void)flags;
    (void)ctrl_type;
    (void)ctrl_para;
    return 1;
}

__declspec(dllexport) DWORD CertNameToStrA(DWORD enc, const void* name_blob, DWORD str_type, char* psz, DWORD csz)
{
    (void)enc;
    (void)name_blob;
    (void)str_type;
    if (psz && csz > 0)
        psz[0] = 0;
    return 1;
}

__declspec(dllexport) DWORD CertNameToStrW(DWORD enc, const void* name_blob, DWORD str_type, wchar_t16* psz, DWORD csz)
{
    (void)enc;
    (void)name_blob;
    (void)str_type;
    if (psz && csz > 0)
        psz[0] = 0;
    return 1;
}

/* PFXImportCertStore / PFXExportCertStore / PFXIsPFXBlob —
 * PKCS#12 envelope. v0 has no PFX engine. */
__declspec(dllexport) HANDLE PFXImportCertStore(const void* pfx_blob, const wchar_t16* password, DWORD flags)
{
    (void)pfx_blob;
    (void)password;
    (void)flags;
    return (HANDLE)0;
}

__declspec(dllexport) BOOL PFXExportCertStore(HANDLE store, void* pfx_blob, const wchar_t16* password, DWORD flags)
{
    (void)store;
    (void)pfx_blob;
    (void)password;
    (void)flags;
    return 0;
}

__declspec(dllexport) BOOL PFXIsPFXBlob(const void* pfx_blob)
{
    (void)pfx_blob;
    return 0;
}

/* CryptStringToBinaryW — wide variant. */
__declspec(dllexport) BOOL CryptStringToBinaryW(const wchar_t16* str, DWORD str_len, DWORD flags, unsigned char* binary,
                                                DWORD* binary_size, DWORD* skip, DWORD* used_flags)
{
    (void)str;
    (void)str_len;
    (void)flags;
    (void)binary;
    if (binary_size)
        *binary_size = 0;
    if (skip)
        *skip = 0;
    if (used_flags)
        *used_flags = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptBinaryToStringW(const unsigned char* binary, DWORD binary_size, DWORD flags,
                                                wchar_t16* str, DWORD* str_len)
{
    (void)binary;
    (void)binary_size;
    (void)flags;
    (void)str;
    if (str_len)
        *str_len = 0;
    return 0;
}

/* CryptDecodeObject / Ex / CryptEncodeObject / Ex — ASN.1
 * decode/encode. v0 has no ASN.1 parser; report failure with
 * size = 0 so callers fall through. */
__declspec(dllexport) BOOL CryptDecodeObject(DWORD enc, const void* type, const unsigned char* data, DWORD data_size,
                                             DWORD flags, void* out, DWORD* out_size)
{
    (void)enc;
    (void)type;
    (void)data;
    (void)data_size;
    (void)flags;
    (void)out;
    if (out_size)
        *out_size = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptDecodeObjectEx(DWORD enc, const void* type, const unsigned char* data, DWORD data_size,
                                               DWORD flags, void* p_decode_para, void* out, DWORD* out_size)
{
    (void)enc;
    (void)type;
    (void)data;
    (void)data_size;
    (void)flags;
    (void)p_decode_para;
    (void)out;
    if (out_size)
        *out_size = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptEncodeObject(DWORD enc, const void* type, const void* data, unsigned char* out,
                                             DWORD* out_size)
{
    (void)enc;
    (void)type;
    (void)data;
    (void)out;
    if (out_size)
        *out_size = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptEncodeObjectEx(DWORD enc, const void* type, const void* data, DWORD flags,
                                               void* p_encode_para, void* out, DWORD* out_size)
{
    (void)enc;
    (void)type;
    (void)data;
    (void)flags;
    (void)p_encode_para;
    (void)out;
    if (out_size)
        *out_size = 0;
    return 0;
}

/* CertAddCertificateContextToStore — accepts but does nothing
 * persistent. */
__declspec(dllexport) BOOL CertAddCertificateContextToStore(HANDLE store, const void* ctx, DWORD disposition,
                                                            const void** stored_ctx)
{
    (void)store;
    (void)ctx;
    (void)disposition;
    if (stored_ctx)
        *stored_ctx = (void*)0;
    return 0;
}

__declspec(dllexport) BOOL CertDeleteCertificateFromStore(const void* ctx)
{
    (void)ctx;
    return 1;
}

__declspec(dllexport) const void* CertCreateCertificateContext(DWORD enc, const unsigned char* der_bytes,
                                                               DWORD der_byte_count)
{
    (void)enc;
    (void)der_bytes;
    (void)der_byte_count;
    return (void*)0;
}

__declspec(dllexport) const void* CertDuplicateCertificateContext(const void* ctx)
{
    return ctx;
}

/* CryptVerifyCertificateSignature / Ex — signature verification.
 * v0 reports "valid" so callers proceed; real verification needs
 * an X.509 ASN.1 parser. This is a deliberate facade — the
 * caller will revoke trust later when the actual TLS handshake
 * parses the cert with bcrypt or schannel. */
__declspec(dllexport) BOOL CryptVerifyCertificateSignature(unsigned long long crypt_provider, DWORD enc,
                                                           const unsigned char* der_bytes, DWORD der_size,
                                                           void* pub_key)
{
    (void)crypt_provider;
    (void)enc;
    (void)der_bytes;
    (void)der_size;
    (void)pub_key;
    return 1;
}

__declspec(dllexport) BOOL CryptVerifyCertificateSignatureEx(unsigned long long crypt_provider, DWORD enc,
                                                             DWORD subject_type, void* subject, DWORD issuer_type,
                                                             void* issuer, DWORD flags, void* extra)
{
    (void)crypt_provider;
    (void)enc;
    (void)subject_type;
    (void)subject;
    (void)issuer_type;
    (void)issuer;
    (void)flags;
    (void)extra;
    return 1;
}

/* CertGetIssuerCertificateFromStore — chain helper. v0 no-cert. */
__declspec(dllexport) const void* CertGetIssuerCertificateFromStore(HANDLE store, const void* subject, const void* prev,
                                                                    DWORD* flags)
{
    (void)store;
    (void)subject;
    (void)prev;
    if (flags)
        *flags = 0;
    return (void*)0;
}

__declspec(dllexport) BOOL CertGetCertificateChain(HANDLE chain_engine, const void* leaf, void* time, HANDLE store,
                                                   void* pchain_para, DWORD flags, void* reserved, void** chain_ctx)
{
    (void)chain_engine;
    (void)leaf;
    (void)time;
    (void)store;
    (void)pchain_para;
    (void)flags;
    (void)reserved;
    if (chain_ctx)
        *chain_ctx = (void*)0;
    return 0;
}

__declspec(dllexport) void CertFreeCertificateChain(const void* chain)
{
    (void)chain;
}

/* CryptMsgOpenToDecode / CryptMsgUpdate / CryptMsgGetParam /
 * CryptMsgClose — PKCS#7 / CMS messages. */
__declspec(dllexport) HANDLE CryptMsgOpenToDecode(DWORD enc, DWORD flags, DWORD msg_type, unsigned long long crypt,
                                                  void* recipient_info, void* stream_info)
{
    (void)enc;
    (void)flags;
    (void)msg_type;
    (void)crypt;
    (void)recipient_info;
    (void)stream_info;
    return (HANDLE)0;
}

__declspec(dllexport) BOOL CryptMsgUpdate(HANDLE msg, const unsigned char* data, DWORD data_len, BOOL final)
{
    (void)msg;
    (void)data;
    (void)data_len;
    (void) final;
    return 0;
}

__declspec(dllexport) BOOL CryptMsgGetParam(HANDLE msg, DWORD param_type, DWORD index, void* data, DWORD* data_len)
{
    (void)msg;
    (void)param_type;
    (void)index;
    (void)data;
    if (data_len)
        *data_len = 0;
    return 0;
}

__declspec(dllexport) BOOL CryptMsgClose(HANDLE msg)
{
    (void)msg;
    return 1;
}

__declspec(dllexport) BOOL CryptSignAndEncryptMessage(void* sign_para, void* encrypt_para, DWORD num_recipients,
                                                      const void** recipient_certs, const unsigned char* in,
                                                      DWORD in_len, unsigned char* out, DWORD* out_len)
{
    (void)sign_para;
    (void)encrypt_para;
    (void)num_recipients;
    (void)recipient_certs;
    (void)in;
    (void)in_len;
    (void)out;
    if (out_len)
        *out_len = 0;
    return 0;
}
