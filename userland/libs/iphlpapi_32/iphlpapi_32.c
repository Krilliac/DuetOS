/* iphlpapi_32.c — i386 iphlpapi.dll v0 stubs. */
typedef unsigned int DWORD;
typedef unsigned long ULONG;

__declspec(dllexport) ULONG __stdcall GetAdaptersAddresses(ULONG family, ULONG flags, void* rsv, void* adapter_addrs,
                                                           ULONG* size)
{
    (void)family;
    (void)flags;
    (void)rsv;
    (void)adapter_addrs;
    if (size)
        *size = 0;
    return 111; /* ERROR_BUFFER_OVERFLOW — keeps caller's "sized" path */
}

__declspec(dllexport) DWORD __stdcall GetBestRoute2(void* iface_luid, ULONG iface_index, const void* source_addr,
                                                    const void* dest_addr, ULONG opts, void* row, void* hop)
{
    (void)iface_luid;
    (void)iface_index;
    (void)source_addr;
    (void)dest_addr;
    (void)opts;
    (void)row;
    (void)hop;
    return 1; /* generic failure — caller falls back */
}

__declspec(dllexport) DWORD __stdcall GetUnicastIpAddressTable(unsigned family, void** table)
{
    (void)family;
    if (table)
        *table = 0;
    return 1;
}

__declspec(dllexport) void __stdcall FreeMibTable(void* table)
{
    (void)table;
}
