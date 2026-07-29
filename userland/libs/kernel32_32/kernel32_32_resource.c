/*
 * userland/libs/kernel32_32/kernel32_32_resource.c
 *
 * The i386 (PE32) half of the Win32 resource API, over the same shared
 * `.rsrc` walker the x86_64 sibling uses
 * (userland/libs/common/pe_resources.h). The walker is bitness-agnostic
 * because it only ever handles u32 RVAs; the optional-header magic tells
 * it where DataDirectory starts.
 *
 * Only the thin Win32 translation layer is duplicated between this file
 * and userland/libs/kernel32/kernel32_resource.c, and deliberately so:
 * the calling convention (__stdcall), the pointer width, and the
 * MAKEINTRESOURCE high-half test all differ. Sharing that layer would
 * mean a 64-bit shape leaking into a `_32` DLL, which is the exact
 * mistake wiki/reference/Design-Decisions.md warns about.
 *
 * The handle model matches the sibling: HRSRC is a pointer to the
 * IMAGE_RESOURCE_DATA_ENTRY inside the module's own mapped image and
 * HGLOBAL is the resource bytes' address, so nothing is allocated and
 * LockResource is the identity. Caller-supplied handles are always
 * re-validated against the module's resource directory before being
 * dereferenced.
 *
 * Contracts mirror the x86_64 sibling except where called out inline.
 */

#include "kernel32_32_internal.h"

#include "../common/pe_resources.h"

typedef long LONG_PTR;

typedef BOOL(__stdcall* ENUMRESTYPEPROCW)(HANDLE, wchar_t16*, LONG_PTR);
typedef BOOL(__stdcall* ENUMRESNAMEPROCW)(HANDLE, const wchar_t16*, wchar_t16*, LONG_PTR);

#define ERROR_RESOURCE_TYPE_NOT_FOUND 1813u
#define ERROR_RESOURCE_NAME_NOT_FOUND 1814u
#define ERROR_INVALID_PARAMETER 87u

#define DUET_RES_NAME_MAX 255u

__declspec(dllexport) void __stdcall SetLastError(DWORD dwErrCode);

/* IS_INTRESOURCE. On i386 a pointer is 32 bits, so the high half is a
 * u16 — this is the shape difference from the x86_64 sibling that stops
 * the two translation layers from being shared. */
static int res_is_int(const wchar_t16* p)
{
    return ((unsigned long)(const void*)p >> 16) == 0ul;
}

static unsigned int res_wcslen(const wchar_t16* s)
{
    unsigned int n = 0;
    while (s[n] != 0 && n < 0xFFFFu)
        ++n;
    return n;
}

static DUET_RES_KEY res_key_from_wide(const wchar_t16* p)
{
    DUET_RES_KEY k;
    k.by_name = 0;
    k.id = 0;
    k.name = (const unsigned short*)0;
    k.name_len = 0;
    if (p == (const wchar_t16*)0)
        return k;
    if (res_is_int(p))
    {
        k.id = (unsigned int)(unsigned long)(const void*)p;
        return k;
    }
    k.by_name = 1;
    k.name = (const unsigned short*)p;
    k.name_len = res_wcslen(p);
    return k;
}

static int res_view_for(HANDLE hModule, DUET_RES_VIEW* view)
{
    const void* base = (const void*)hModule;
    if (base == (const void*)0)
        base = (const void*)GetModuleHandleW((const wchar_t16*)0);
    if (base == (const void*)0)
        return 0;
    return duet_res_init(base, view);
}

/* Validate a caller-supplied HRSRC: it must be a 4-byte-aligned
 * IMAGE_RESOURCE_DATA_ENTRY inside this module's resource directory.
 * A fabricated or cross-module handle is rejected undereferenced. */
static int res_decode_hrsrc(HANDLE hModule, HANDLE hResInfo, DUET_RES_VIEW* view, unsigned int* out_rva,
                            unsigned int* out_size)
{
    const unsigned char* entry = (const unsigned char*)hResInfo;
    const unsigned char* dir_start;
    unsigned int offset;
    unsigned int rva;
    unsigned int size;

    if (entry == (const unsigned char*)0 || !res_view_for(hModule, view))
        return 0;
    dir_start = view->base + view->dir_rva;
    if (entry < dir_start)
        return 0;
    offset = (unsigned int)(entry - dir_start);
    if (offset > view->dir_span || view->dir_span - offset < DUET_RES_DATA_ENTRY_SIZE)
        return 0;
    if ((offset & 3u) != 0u)
        return 0;

    rva = duet_res_u32(entry);
    size = duet_res_u32(entry + 4u);
    if (size == 0u || duet_res_at(view, rva, size) == (const unsigned char*)0)
        return 0;
    *out_rva = rva;
    *out_size = size;
    return 1;
}

/* --- FindResource family ------------------------------------------ */

__declspec(dllexport) HANDLE __stdcall FindResourceExW(HANDLE hModule, const wchar_t16* lpType, const wchar_t16* lpName,
                                                       unsigned short wLanguage)
{
    DUET_RES_VIEW view;
    DUET_RES_KEY type;
    DUET_RES_KEY name;
    unsigned int name_dir;
    unsigned int lang_dir;
    unsigned int data_off;
    int is_dir;

    if (lpType == (const wchar_t16*)0 || lpName == (const wchar_t16*)0)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return (HANDLE)0;
    }
    if (!res_view_for(hModule, &view))
    {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return (HANDLE)0;
    }

    type = res_key_from_wide(lpType);
    name = res_key_from_wide(lpName);
    if (!duet_res_lookup(&view, 0u, &type, &name_dir, &is_dir) || !is_dir)
    {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return (HANDLE)0;
    }
    if (!duet_res_lookup(&view, name_dir, &name, &lang_dir, &is_dir) || !is_dir)
    {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return (HANDLE)0;
    }
    if (!duet_res_pick_language(&view, lang_dir, wLanguage, wLanguage != 0, &data_off))
    {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return (HANDLE)0;
    }
    if (duet_res_dir_at(&view, data_off, DUET_RES_DATA_ENTRY_SIZE) == (const unsigned char*)0)
    {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return (HANDLE)0;
    }
    return (HANDLE)(void*)(view.base + view.dir_rva + data_off);
}

/* FindResource takes (name, type); FindResourceEx takes (type, name). */
__declspec(dllexport) HANDLE __stdcall FindResourceW(HANDLE hModule, const wchar_t16* lpName, const wchar_t16* lpType)
{
    return FindResourceExW(hModule, lpType, lpName, 0);
}

static const wchar_t16* res_widen(const char* s, wchar_t16* buf, unsigned int cap)
{
    unsigned int i = 0;
    if (s == (const char*)0)
        return (const wchar_t16*)0;
    if (((unsigned long)(const void*)s >> 16) == 0ul)
        return (const wchar_t16*)(const void*)s;
    while (s[i] != 0 && i + 1u < cap)
    {
        buf[i] = (wchar_t16)(unsigned char)s[i];
        ++i;
    }
    buf[i] = 0;
    return buf;
}

__declspec(dllexport) HANDLE __stdcall FindResourceExA(HANDLE hModule, const char* lpType, const char* lpName,
                                                       unsigned short wLanguage)
{
    wchar_t16 type_buf[DUET_RES_NAME_MAX + 1u];
    wchar_t16 name_buf[DUET_RES_NAME_MAX + 1u];
    const wchar_t16* type = res_widen(lpType, type_buf, DUET_RES_NAME_MAX + 1u);
    const wchar_t16* name = res_widen(lpName, name_buf, DUET_RES_NAME_MAX + 1u);
    return FindResourceExW(hModule, type, name, wLanguage);
}

__declspec(dllexport) HANDLE __stdcall FindResourceA(HANDLE hModule, const char* lpName, const char* lpType)
{
    return FindResourceExA(hModule, lpType, lpName, 0);
}

/* --- Load / Lock / Size / Free ------------------------------------- */

__declspec(dllexport) HANDLE __stdcall LoadResource(HANDLE hModule, HANDLE hResInfo)
{
    DUET_RES_VIEW view;
    unsigned int rva;
    unsigned int size;
    if (!res_decode_hrsrc(hModule, hResInfo, &view, &rva, &size))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return (HANDLE)0;
    }
    return (HANDLE)(void*)(view.base + rva);
}

__declspec(dllexport) void* __stdcall LockResource(HANDLE hResData)
{
    return (void*)hResData;
}

__declspec(dllexport) DWORD __stdcall SizeofResource(HANDLE hModule, HANDLE hResInfo)
{
    DUET_RES_VIEW view;
    unsigned int rva;
    unsigned int size;
    if (!res_decode_hrsrc(hModule, hResInfo, &view, &rva, &size))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    return (DWORD)size;
}

__declspec(dllexport) BOOL __stdcall FreeResource(HANDLE hResData)
{
    /* Nothing was allocated. Win32 documents FreeResource as returning
     * FALSE on success for 32-bit and later modules. */
    (void)hResData;
    return 0;
}

/* --- Enumeration --------------------------------------------------- */

static int res_key_to_callback_arg(const DUET_RES_KEY* key, wchar_t16* buf, unsigned int cap, wchar_t16** out)
{
    unsigned int i;
    if (!key->by_name)
    {
        *out = (wchar_t16*)(void*)(unsigned long)key->id;
        return 1;
    }
    if (key->name_len == 0u || key->name_len + 1u > cap)
        return 0;
    for (i = 0; i < key->name_len; ++i)
        buf[i] = (wchar_t16)key->name[i];
    buf[key->name_len] = 0;
    *out = buf;
    return 1;
}

__declspec(dllexport) BOOL __stdcall EnumResourceTypesW(HANDLE hModule, ENUMRESTYPEPROCW lpEnumFunc, LONG_PTR lParam)
{
    DUET_RES_VIEW view;
    unsigned int total;
    unsigned int i;
    int any = 0;

    if (lpEnumFunc == (ENUMRESTYPEPROCW)0 || !res_view_for(hModule, &view))
    {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return 0;
    }
    total = duet_res_dir_count(&view, 0u, (unsigned int*)0);
    for (i = 0; i < total; ++i)
    {
        wchar_t16 buf[DUET_RES_NAME_MAX + 1u];
        wchar_t16* arg;
        DUET_RES_KEY key;
        unsigned int child;
        int is_dir;
        if (!duet_res_dir_entry(&view, 0u, i, &key, &child, &is_dir))
            break;
        if (!res_key_to_callback_arg(&key, buf, DUET_RES_NAME_MAX + 1u, &arg))
            continue;
        any = 1;
        if (!lpEnumFunc(hModule, arg, lParam))
            return 1;
    }
    if (!any)
    {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return 0;
    }
    return 1;
}

__declspec(dllexport) BOOL __stdcall EnumResourceNamesW(HANDLE hModule, const wchar_t16* lpType,
                                                        ENUMRESNAMEPROCW lpEnumFunc, LONG_PTR lParam)
{
    DUET_RES_VIEW view;
    DUET_RES_KEY type;
    unsigned int type_dir;
    unsigned int total;
    unsigned int i;
    int is_dir;
    int any = 0;

    if (lpEnumFunc == (ENUMRESNAMEPROCW)0 || lpType == (const wchar_t16*)0 || !res_view_for(hModule, &view))
    {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return 0;
    }
    type = res_key_from_wide(lpType);
    if (!duet_res_lookup(&view, 0u, &type, &type_dir, &is_dir) || !is_dir)
    {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return 0;
    }
    total = duet_res_dir_count(&view, type_dir, (unsigned int*)0);
    for (i = 0; i < total; ++i)
    {
        wchar_t16 buf[DUET_RES_NAME_MAX + 1u];
        wchar_t16* arg;
        DUET_RES_KEY key;
        unsigned int child;
        if (!duet_res_dir_entry(&view, type_dir, i, &key, &child, &is_dir))
            break;
        if (!res_key_to_callback_arg(&key, buf, DUET_RES_NAME_MAX + 1u, &arg))
            continue;
        any = 1;
        if (!lpEnumFunc(hModule, lpType, arg, lParam))
            return 1;
    }
    if (!any)
    {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return 0;
    }
    return 1;
}
