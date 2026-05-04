/* version.dll — file version info. No PE resource parser; all fail. */
typedef int BOOL;
typedef unsigned int DWORD;
typedef void* HANDLE;
typedef unsigned short wchar_t16;

/* Synthetic VS_VERSIONINFO block — DuetOS doesn't ship a real PE
 * resource walker, but every modern Win32 PE blocks at startup
 * unless GetFileVersionInfoSize returns non-zero. We hand back a
 * minimum well-formed block that satisfies the parse:
 *
 *   struct VS_VERSIONINFO {
 *     WORD wLength;            // total length of this struct
 *     WORD wValueLength;        // = sizeof(VS_FIXEDFILEINFO) = 52
 *     WORD wType;               // 0 = binary, 1 = text
 *     WCHAR szKey[16];          // L"VS_VERSION_INFO"
 *     WORD Padding1[1];         // align to 4
 *     VS_FIXEDFILEINFO Value;   // 52 bytes
 *     // optional StringFileInfo + VarFileInfo children
 *   };
 *
 * Total = 2 + 2 + 2 + 32 + 2 + 52 = 92 bytes.
 *
 * VS_FIXEDFILEINFO carries dwSignature = 0xFEEF04BD,
 * dwStrucVersion = 0x00010000, dwFileVersionMS / LS, etc. v0
 * reports "DuetOS 1.0.0" for every queried file — caller-side
 * version-gating proceeds happily under "this binary is at least
 * version 1." */
#define DUET_VERINFO_SIZE 92u

static DWORD duet_make_verinfo(unsigned char* dst, DWORD cap)
{
    if (dst == (unsigned char*)0 || cap < DUET_VERINFO_SIZE)
        return 0;
    /* Zero everything first. */
    for (DWORD i = 0; i < DUET_VERINFO_SIZE; ++i)
        dst[i] = 0;
    /* wLength = 92, wValueLength = 52, wType = 0 (binary). */
    dst[0] = 92;
    dst[2] = 52;
    /* szKey[] = "VS_VERSION_INFO" (16 wchars including NUL). */
    static const char kKey[] = "VS_VERSION_INFO";
    for (int i = 0; kKey[i] != 0 && i < 15; ++i)
    {
        dst[6 + i * 2] = (unsigned char)kKey[i];
        dst[6 + i * 2 + 1] = 0;
    }
    /* Padding1[1] at offset 38 is already zero. */
    /* VS_FIXEDFILEINFO at offset 40:
     *   dwSignature     = 0xFEEF04BD (little-endian)
     *   dwStrucVersion  = 0x00010000 (struct version 1.0)
     *   dwFileVersionMS = 0x00010000 (file version 1.0)
     *   dwFileVersionLS = 0x00000000
     *   dwProductVersionMS = 0x00010000
     *   dwProductVersionLS = 0x00000000
     *   ... rest zero */
    const unsigned char fixed_sig[] = {0xBD, 0x04, 0xEF, 0xFE};
    for (int i = 0; i < 4; ++i)
        dst[40 + i] = fixed_sig[i];
    dst[44 + 2] = 1; /* dwStrucVersion = 0x00010000 */
    dst[48 + 2] = 1; /* dwFileVersionMS = 0x00010000 */
    dst[56 + 2] = 1; /* dwProductVersionMS = 0x00010000 */
    return DUET_VERINFO_SIZE;
}

__declspec(dllexport) DWORD GetFileVersionInfoSizeA(const char* file, DWORD* hnd)
{
    (void)file;
    if (hnd)
        *hnd = 0;
    return DUET_VERINFO_SIZE;
}
__declspec(dllexport) DWORD GetFileVersionInfoSizeW(const wchar_t16* file, DWORD* hnd)
{
    (void)file;
    if (hnd)
        *hnd = 0;
    return DUET_VERINFO_SIZE;
}
__declspec(dllexport) BOOL GetFileVersionInfoA(const char* file, DWORD hnd, DWORD len, void* data)
{
    (void)file;
    (void)hnd;
    return duet_make_verinfo((unsigned char*)data, len) != 0 ? 1 : 0;
}
__declspec(dllexport) BOOL GetFileVersionInfoW(const wchar_t16* file, DWORD hnd, DWORD len, void* data)
{
    (void)file;
    (void)hnd;
    return duet_make_verinfo((unsigned char*)data, len) != 0 ? 1 : 0;
}
__declspec(dllexport) BOOL VerQueryValueA(const void* block, const char* sub, void** ptr, unsigned int* len)
{
    (void)block;
    (void)sub;
    if (ptr)
        *ptr = (void*)0;
    if (len)
        *len = 0;
    return 0;
}
__declspec(dllexport) BOOL VerQueryValueW(const void* block, const wchar_t16* sub, void** ptr, unsigned int* len)
{
    (void)block;
    (void)sub;
    if (ptr)
        *ptr = (void*)0;
    if (len)
        *len = 0;
    return 0;
}

/* GetFileVersionInfoExW(flags, file, hnd, len, data) — newer Win32
 * 8.1+ entry point, same v0 stub semantics. */
__declspec(dllexport) BOOL GetFileVersionInfoExW(DWORD flags, const wchar_t16* file, DWORD hnd, DWORD len, void* data)
{
    (void)flags;
    (void)file;
    (void)hnd;
    (void)len;
    (void)data;
    return 0;
}
__declspec(dllexport) BOOL GetFileVersionInfoExA(DWORD flags, const char* file, DWORD hnd, DWORD len, void* data)
{
    (void)flags;
    (void)file;
    (void)hnd;
    (void)len;
    (void)data;
    return 0;
}

/* VerLanguageNameA/W: human-readable name for a language ID.
 * v0 reports "Language Neutral" for every locale; matches what
 * Windows returns for LANG_NEUTRAL (0). */
__declspec(dllexport) DWORD VerLanguageNameA(DWORD lang, char* buf, DWORD buf_size)
{
    static const char kName[] = "Language Neutral";
    const DWORD need = sizeof(kName) - 1;
    (void)lang;
    if (!buf || buf_size == 0)
        return need;
    DWORD i = 0;
    for (; i + 1 < buf_size && kName[i]; ++i)
        buf[i] = kName[i];
    buf[i] = 0;
    return i;
}

__declspec(dllexport) DWORD VerLanguageNameW(DWORD lang, wchar_t16* buf, DWORD buf_size)
{
    static const char kName[] = "Language Neutral";
    const DWORD need = sizeof(kName) - 1;
    (void)lang;
    if (!buf || buf_size == 0)
        return need;
    DWORD i = 0;
    for (; i + 1 < buf_size && kName[i]; ++i)
        buf[i] = (wchar_t16)kName[i];
    buf[i] = 0;
    return i;
}

/* GetFileVersionInfoSizeExA / W — Vista+. Same canned size. */
__declspec(dllexport) DWORD GetFileVersionInfoSizeExA(DWORD flags, const char* file, DWORD* hnd)
{
    (void)flags;
    (void)file;
    if (hnd)
        *hnd = 0;
    return DUET_VERINFO_SIZE;
}

__declspec(dllexport) DWORD GetFileVersionInfoSizeExW(DWORD flags, const wchar_t16* file, DWORD* hnd)
{
    (void)flags;
    (void)file;
    if (hnd)
        *hnd = 0;
    return DUET_VERINFO_SIZE;
}

/* VerFindFileA / W — Win-Setup helper. Always reports
 * "use the destination dir" so the caller drops the file in
 * place rather than searching system paths. */
__declspec(dllexport) DWORD VerFindFileA(DWORD flags, const char* file_name, const char* win_dir, const char* app_dir,
                                         char* cur_dir, DWORD* cur_dir_len, char* dest_dir, DWORD* dest_dir_len)
{
    (void)flags;
    (void)file_name;
    (void)win_dir;
    if (cur_dir && cur_dir_len && *cur_dir_len > 0)
    {
        cur_dir[0] = 0;
    }
    if (cur_dir_len)
        *cur_dir_len = 0;
    if (dest_dir && dest_dir_len && *dest_dir_len > 0)
    {
        DWORD i = 0;
        if (app_dir)
        {
            for (; app_dir[i] != 0 && i + 1 < *dest_dir_len; ++i)
                dest_dir[i] = app_dir[i];
        }
        dest_dir[i] = 0;
    }
    if (dest_dir_len)
        *dest_dir_len = 0;
    return 0; /* VFF_CURNEDEST = neither set */
}

__declspec(dllexport) DWORD VerFindFileW(DWORD flags, const wchar_t16* file_name, const wchar_t16* win_dir,
                                         const wchar_t16* app_dir, wchar_t16* cur_dir, DWORD* cur_dir_len,
                                         wchar_t16* dest_dir, DWORD* dest_dir_len)
{
    (void)flags;
    (void)file_name;
    (void)win_dir;
    (void)app_dir;
    if (cur_dir && cur_dir_len && *cur_dir_len > 0)
        cur_dir[0] = 0;
    if (cur_dir_len)
        *cur_dir_len = 0;
    if (dest_dir && dest_dir_len && *dest_dir_len > 0)
        dest_dir[0] = 0;
    if (dest_dir_len)
        *dest_dir_len = 0;
    return 0;
}

/* VerInstallFileA / W — installer helper. Reports "ok, no
 * extra work needed" so the install path completes quietly. */
__declspec(dllexport) DWORD VerInstallFileA(DWORD flags, const char* src_file_name, const char* dest_file_name,
                                            const char* src_dir, const char* dest_dir, const char* cur_dir,
                                            char* tmp_file, DWORD* tmp_file_len)
{
    (void)flags;
    (void)src_file_name;
    (void)dest_file_name;
    (void)src_dir;
    (void)dest_dir;
    (void)cur_dir;
    if (tmp_file && tmp_file_len && *tmp_file_len > 0)
        tmp_file[0] = 0;
    if (tmp_file_len)
        *tmp_file_len = 0;
    return 0;
}

__declspec(dllexport) DWORD VerInstallFileW(DWORD flags, const wchar_t16* src_file_name,
                                            const wchar_t16* dest_file_name, const wchar_t16* src_dir,
                                            const wchar_t16* dest_dir, const wchar_t16* cur_dir, wchar_t16* tmp_file,
                                            DWORD* tmp_file_len)
{
    (void)flags;
    (void)src_file_name;
    (void)dest_file_name;
    (void)src_dir;
    (void)dest_dir;
    (void)cur_dir;
    if (tmp_file && tmp_file_len && *tmp_file_len > 0)
        tmp_file[0] = 0;
    if (tmp_file_len)
        *tmp_file_len = 0;
    return 0;
}
