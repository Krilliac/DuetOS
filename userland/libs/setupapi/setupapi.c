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
    return (HANDLE)(unsigned long long)0x5E700001ULL; /* sentinel device-info-set */
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

/* SetupDiCreateDeviceInfoList — create empty device-info list. */
__declspec(dllexport) HANDLE SetupDiCreateDeviceInfoList(const void* class_guid, HANDLE wnd_parent)
{
    (void)class_guid;
    (void)wnd_parent;
    return (HANDLE)(unsigned long long)0x5E700001ULL;
}

__declspec(dllexport) HANDLE SetupDiCreateDeviceInfoListExW(const void* class_guid, HANDLE wnd_parent,
                                                            const wchar_t16* machine, void* reserved)
{
    (void)class_guid;
    (void)wnd_parent;
    (void)machine;
    (void)reserved;
    return (HANDLE)(unsigned long long)0x5E700001ULL;
}

__declspec(dllexport) BOOL SetupDiOpenDeviceInfoA(HANDLE list, const char* device_id, HANDLE wnd, DWORD flags,
                                                  void* did)
{
    (void)list;
    (void)device_id;
    (void)wnd;
    (void)flags;
    (void)did;
    return 0;
}

__declspec(dllexport) BOOL SetupDiOpenDeviceInfoW(HANDLE list, const wchar_t16* device_id, HANDLE wnd, DWORD flags,
                                                  void* did)
{
    (void)list;
    (void)device_id;
    (void)wnd;
    (void)flags;
    (void)did;
    return 0;
}

__declspec(dllexport) BOOL SetupDiBuildClassInfoList(DWORD flags, void* guid_array, DWORD guid_array_size, DWORD* req)
{
    (void)flags;
    (void)guid_array;
    (void)guid_array_size;
    if (req)
        *req = 0;
    return 1;
}

__declspec(dllexport) BOOL SetupDiClassGuidsFromNameA(const char* class_name, void* guid_array, DWORD guid_array_size,
                                                      DWORD* req)
{
    (void)class_name;
    (void)guid_array;
    (void)guid_array_size;
    if (req)
        *req = 0;
    return 1;
}

__declspec(dllexport) BOOL SetupDiClassGuidsFromNameW(const wchar_t16* class_name, void* guid_array,
                                                      DWORD guid_array_size, DWORD* req)
{
    (void)class_name;
    (void)guid_array;
    (void)guid_array_size;
    if (req)
        *req = 0;
    return 1;
}

__declspec(dllexport) BOOL SetupDiClassNameFromGuidA(const void* guid, char* name, DWORD name_size, DWORD* req)
{
    (void)guid;
    if (name && name_size > 0)
        name[0] = 0;
    if (req)
        *req = 0;
    return 1;
}

__declspec(dllexport) BOOL SetupDiClassNameFromGuidW(const void* guid, wchar_t16* name, DWORD name_size, DWORD* req)
{
    (void)guid;
    if (name && name_size > 0)
        name[0] = 0;
    if (req)
        *req = 0;
    return 1;
}

/* SetupDiOpenDevRegKey — open per-device registry key. v0 has
 * no per-device hive; report INVALID_HANDLE so callers fall
 * through to "no driver-specific config". */
__declspec(dllexport) HANDLE SetupDiOpenDevRegKey(HANDLE list, void* did, DWORD scope, DWORD hw_profile, DWORD key,
                                                  DWORD sam_desired)
{
    (void)list;
    (void)did;
    (void)scope;
    (void)hw_profile;
    (void)key;
    (void)sam_desired;
    return INVALID_HANDLE_VALUE;
}

__declspec(dllexport) HANDLE SetupDiOpenClassRegKey(const void* class_guid, DWORD sam_desired)
{
    (void)class_guid;
    (void)sam_desired;
    return INVALID_HANDLE_VALUE;
}

__declspec(dllexport) HANDLE SetupDiOpenClassRegKeyExA(const void* class_guid, DWORD sam_desired, DWORD flags,
                                                       const char* machine, void* reserved)
{
    (void)class_guid;
    (void)sam_desired;
    (void)flags;
    (void)machine;
    (void)reserved;
    return INVALID_HANDLE_VALUE;
}

__declspec(dllexport) HANDLE SetupDiOpenClassRegKeyExW(const void* class_guid, DWORD sam_desired, DWORD flags,
                                                       const wchar_t16* machine, void* reserved)
{
    (void)class_guid;
    (void)sam_desired;
    (void)flags;
    (void)machine;
    (void)reserved;
    return INVALID_HANDLE_VALUE;
}

/* SetupDiCreateDeviceInfoA / W — create new device-info entry.
 * v0 reports failure (we don't track devices). */
__declspec(dllexport) BOOL SetupDiCreateDeviceInfoA(HANDLE list, const char* device_name, const void* class_guid,
                                                    const char* desc, HANDLE wnd_parent, DWORD flags, void* did)
{
    (void)list;
    (void)device_name;
    (void)class_guid;
    (void)desc;
    (void)wnd_parent;
    (void)flags;
    (void)did;
    return 0;
}

__declspec(dllexport) BOOL SetupDiCreateDeviceInfoW(HANDLE list, const wchar_t16* device_name, const void* class_guid,
                                                    const wchar_t16* desc, HANDLE wnd_parent, DWORD flags, void* did)
{
    (void)list;
    (void)device_name;
    (void)class_guid;
    (void)desc;
    (void)wnd_parent;
    (void)flags;
    (void)did;
    return 0;
}

__declspec(dllexport) BOOL SetupDiSetDeviceRegistryPropertyA(HANDLE list, void* did, DWORD prop, const void* buf,
                                                             DWORD buf_size)
{
    (void)list;
    (void)did;
    (void)prop;
    (void)buf;
    (void)buf_size;
    return 0;
}

__declspec(dllexport) BOOL SetupDiSetDeviceRegistryPropertyW(HANDLE list, void* did, DWORD prop, const void* buf,
                                                             DWORD buf_size)
{
    (void)list;
    (void)did;
    (void)prop;
    (void)buf;
    (void)buf_size;
    return 0;
}

__declspec(dllexport) BOOL SetupDiCallClassInstaller(DWORD install_function, HANDLE list, void* did)
{
    (void)install_function;
    (void)list;
    (void)did;
    return 0;
}

__declspec(dllexport) BOOL SetupDiInstallDevice(HANDLE list, void* did)
{
    (void)list;
    (void)did;
    return 0;
}

__declspec(dllexport) BOOL SetupDiInstallClassA(HANDLE wnd, const char* inf_path, DWORD flags, HANDLE q)
{
    (void)wnd;
    (void)inf_path;
    (void)flags;
    (void)q;
    return 0;
}

__declspec(dllexport) BOOL SetupDiInstallClassW(HANDLE wnd, const wchar_t16* inf_path, DWORD flags, HANDLE q)
{
    (void)wnd;
    (void)inf_path;
    (void)flags;
    (void)q;
    return 0;
}

/* SetupCopyOEMInfA / W — copy an INF into the system store.
 * v0 reports failure. */
__declspec(dllexport) BOOL SetupCopyOEMInfA(const char* source_inf, const char* loc, DWORD media_type, DWORD flags,
                                            char* dest, DWORD dest_size, DWORD* req, char** dest_inf_name)
{
    (void)source_inf;
    (void)loc;
    (void)media_type;
    (void)flags;
    if (dest && dest_size > 0)
        dest[0] = 0;
    if (req)
        *req = 0;
    if (dest_inf_name)
        *dest_inf_name = (char*)0;
    return 0;
}

__declspec(dllexport) BOOL SetupCopyOEMInfW(const wchar_t16* source_inf, const wchar_t16* loc, DWORD media_type,
                                            DWORD flags, wchar_t16* dest, DWORD dest_size, DWORD* req,
                                            wchar_t16** dest_inf_name)
{
    (void)source_inf;
    (void)loc;
    (void)media_type;
    (void)flags;
    if (dest && dest_size > 0)
        dest[0] = 0;
    if (req)
        *req = 0;
    if (dest_inf_name)
        *dest_inf_name = (wchar_t16*)0;
    return 0;
}

__declspec(dllexport) BOOL SetupUninstallOEMInfA(const char* inf_file_name, DWORD flags, void* reserved)
{
    (void)inf_file_name;
    (void)flags;
    (void)reserved;
    return 0;
}

__declspec(dllexport) BOOL SetupUninstallOEMInfW(const wchar_t16* inf_file_name, DWORD flags, void* reserved)
{
    (void)inf_file_name;
    (void)flags;
    (void)reserved;
    return 0;
}

/* CM_* — Configuration Manager. v0 reports CR_FAILURE for
 * everything that asks for real device data. */
__declspec(dllexport) DWORD CM_Get_Device_ID_Size(DWORD* len, DWORD dev_inst, DWORD flags)
{
    (void)dev_inst;
    (void)flags;
    if (len)
        *len = 0;
    return 0x12; /* CR_NO_SUCH_DEVNODE */
}

__declspec(dllexport) DWORD CM_Get_Device_IDA(DWORD dev_inst, char* buf, DWORD len, DWORD flags)
{
    (void)dev_inst;
    (void)flags;
    if (buf && len > 0)
        buf[0] = 0;
    return 0x12;
}

__declspec(dllexport) DWORD CM_Get_Device_IDW(DWORD dev_inst, wchar_t16* buf, DWORD len, DWORD flags)
{
    (void)dev_inst;
    (void)flags;
    if (buf && len > 0)
        buf[0] = 0;
    return 0x12;
}

__declspec(dllexport) DWORD CM_Locate_DevNodeA(DWORD* dev_inst, char* dev_id, DWORD flags)
{
    (void)dev_id;
    (void)flags;
    if (dev_inst)
        *dev_inst = 0;
    return 0x12;
}

__declspec(dllexport) DWORD CM_Locate_DevNodeW(DWORD* dev_inst, wchar_t16* dev_id, DWORD flags)
{
    (void)dev_id;
    (void)flags;
    if (dev_inst)
        *dev_inst = 0;
    return 0x12;
}
