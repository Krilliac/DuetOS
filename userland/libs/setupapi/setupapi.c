/* setupapi.dll — device installation / INF parsing. All fail. */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)

__declspec(dllexport) HANDLE SetupDiGetClassDevsA(const void* guid, const char* enumerator, HANDLE parent, DWORD flags)
{
    (void)guid;
    (void)enumerator;
    (void)parent;
    (void)flags;
    return INVALID_HANDLE_VALUE;
}
__declspec(dllexport) HANDLE SetupDiGetClassDevsW(const void* guid, const wchar_t16* enumerator, HANDLE parent,
                                                  DWORD flags)
{
    (void)guid;
    (void)enumerator;
    (void)parent;
    (void)flags;
    return INVALID_HANDLE_VALUE;
}
__declspec(dllexport) BOOL SetupDiDestroyDeviceInfoList(HANDLE h)
{
    (void)h;
    return 1;
}
__declspec(dllexport) BOOL SetupDiEnumDeviceInfo(HANDLE h, DWORD idx, void* info)
{
    (void)h;
    (void)idx;
    (void)info;
    return 0;
}
__declspec(dllexport) HANDLE SetupOpenInfFileA(const char* file, const char* cls, DWORD style, unsigned int* err_line)
{
    (void)file;
    (void)cls;
    (void)style;
    if (err_line)
        *err_line = 0;
    return INVALID_HANDLE_VALUE;
}
__declspec(dllexport) HANDLE SetupOpenInfFileW(const wchar_t16* file, const wchar_t16* cls, DWORD style,
                                               unsigned int* err_line)
{
    (void)file;
    (void)cls;
    (void)style;
    if (err_line)
        *err_line = 0;
    return INVALID_HANDLE_VALUE;
}
__declspec(dllexport) BOOL SetupCloseInfFile(HANDLE h)
{
    (void)h;
    return 1;
}

__declspec(dllexport) BOOL SetupDiGetDeviceRegistryPropertyA(HANDLE h, void* did, DWORD prop, DWORD* type, void* buf,
                                                             DWORD buf_size, DWORD* required)
{
    (void)h;
    (void)did;
    (void)prop;
    (void)buf;
    (void)buf_size;
    if (type)
        *type = 0;
    if (required)
        *required = 0;
    return 0;
}

__declspec(dllexport) BOOL SetupDiGetDeviceRegistryPropertyW(HANDLE h, void* did, DWORD prop, DWORD* type, void* buf,
                                                             DWORD buf_size, DWORD* required)
{
    (void)h;
    (void)did;
    (void)prop;
    (void)buf;
    (void)buf_size;
    if (type)
        *type = 0;
    if (required)
        *required = 0;
    return 0;
}

__declspec(dllexport) BOOL SetupDiGetDeviceInterfaceDetailA(HANDLE h, void* iface, void* detail, DWORD detail_size,
                                                            DWORD* required, void* did)
{
    (void)h;
    (void)iface;
    (void)detail;
    (void)detail_size;
    (void)did;
    if (required)
        *required = 0;
    return 0;
}

__declspec(dllexport) BOOL SetupDiGetDeviceInterfaceDetailW(HANDLE h, void* iface, void* detail, DWORD detail_size,
                                                            DWORD* required, void* did)
{
    (void)h;
    (void)iface;
    (void)detail;
    (void)detail_size;
    (void)did;
    if (required)
        *required = 0;
    return 0;
}

__declspec(dllexport) BOOL SetupDiEnumDeviceInterfaces(HANDLE h, void* did, const void* iface_class_guid, DWORD idx,
                                                       void* iface_data)
{
    (void)h;
    (void)did;
    (void)iface_class_guid;
    (void)idx;
    (void)iface_data;
    return 0; /* No more devices. */
}

__declspec(dllexport) BOOL SetupGetLineByIndexA(HANDLE h, const char* section, DWORD idx, void* line_ctx)
{
    (void)h;
    (void)section;
    (void)idx;
    (void)line_ctx;
    return 0;
}

__declspec(dllexport) BOOL SetupFindFirstLineA(HANDLE h, const char* section, const char* key, void* line_ctx)
{
    (void)h;
    (void)section;
    (void)key;
    (void)line_ctx;
    return 0;
}

__declspec(dllexport) BOOL SetupFindNextLine(void* line_ctx, void* next_line)
{
    (void)line_ctx;
    (void)next_line;
    return 0;
}
