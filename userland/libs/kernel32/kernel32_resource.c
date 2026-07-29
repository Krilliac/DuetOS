/*
 * userland/libs/kernel32/kernel32_resource.c — the Win32 resource API
 * (FindResource* / LoadResource / LockResource / SizeofResource /
 * FreeResource / EnumResource*) over the shared `.rsrc` walker in
 * userland/libs/common/pe_resources.h.
 *
 * These used to resolve to the kernel thunk page's kOffPinReturn0 rows,
 * i.e. every call returned NULL. The loader prefers a preloaded DLL's
 * export table over the thunk page (see ResolveImports' resolved_via_dll
 * ordering in kernel/loader/pe_loader.cpp), so exporting them here
 * retires those thunk rows without editing the thunk table.
 *
 * HANDLE MODEL
 *   HRSRC   — a pointer to the IMAGE_RESOURCE_DATA_ENTRY inside the
 *             module's own mapped image. Nothing is allocated, so
 *             nothing has to be freed, which is why FreeResource is a
 *             no-op that reports success. This is the same shape Windows
 *             itself uses for a mapped image.
 *   HGLOBAL — the resource bytes' address. LockResource is therefore the
 *             identity function, exactly as it is on Win32 for module
 *             resources.
 *
 * A guest can hand back any pointer it likes as an HRSRC, so every entry
 * point re-validates it against the module's resource-directory extent
 * before dereferencing rather than trusting that it came from us.
 */
#include "kernel32_internal.h"

#include "../common/pe_resources.h"

typedef long long LONG_PTR;

/* Callback shapes from winuser.h / winbase.h. */
typedef BOOL (*ENUMRESTYPEPROCW)(HANDLE, wchar_t16*, LONG_PTR);
typedef BOOL (*ENUMRESNAMEPROCW)(HANDLE, const wchar_t16*, wchar_t16*, LONG_PTR);

#define ERROR_RESOURCE_TYPE_NOT_FOUND 1813u
#define ERROR_RESOURCE_NAME_NOT_FOUND 1814u
#define ERROR_INVALID_PARAMETER 87u

/* Longest named type / name handed to an enumeration callback. The
 * callback needs a NUL-terminated string but IMAGE_RESOURCE_DIR_STRING_U
 * is counted and unterminated, so the name is copied to a stack buffer
 * first. */
#define DUET_RES_NAME_MAX 255u

/* IS_INTRESOURCE: a MAKEINTRESOURCE value is an integer below 0x10000
 * cast to a pointer, so anything with a non-zero high half is a real
 * string pointer. */
static int res_is_int(const wchar_t16* p)
{
    return ((unsigned long long)(const void*)p >> 16) == 0ull;
}

static unsigned int res_wcslen(const wchar_t16* s)
{
    unsigned int n = 0;
    while (s[n] != 0 && n < 0xFFFFu)
        ++n;
    return n;
}

/* Build a lookup key from a Win32 LPCWSTR type/name argument. */
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
        k.id = (unsigned int)(unsigned long long)(const void*)p;
        return k;
    }
    k.by_name = 1;
    k.name = (const unsigned short*)p;
    k.name_len = res_wcslen(p);
    return k;
}

/* Resolve an HMODULE to a resource view. NULL means the calling process
 * image, which is what GetModuleHandleW(NULL) returns. */
static int res_view_for(HANDLE hModule, DUET_RES_VIEW* view)
{
    const void* base = (const void*)hModule;
    if (base == (const void*)0)
        base = GetModuleHandleW((const wchar_t16*)0);
    if (base == (const void*)0)
        return 0;
    return duet_res_init(base, view);
}

/* Validate a caller-supplied HRSRC and decode the resource it names.
 *
 * The handle must point at a 16-byte-aligned IMAGE_RESOURCE_DATA_ENTRY
 * inside this module's resource directory. Anything else — a stale
 * handle from another module, a fabricated pointer, a handle that is
 * merely close — is rejected without being dereferenced. */
static int res_decode_hrsrc(HANDLE hModule, HANDLE hResInfo, DUET_RES_VIEW* view, unsigned int* out_rva,
                            unsigned int* out_size)
{
    const unsigned char* entry = (const unsigned char*)hResInfo;
    const unsigned char* dir_start;
    unsigned long long offset;
    unsigned int rva;
    unsigned int size;

    if (entry == (const unsigned char*)0 || !res_view_for(hModule, view))
        return 0;
    dir_start = view->base + view->dir_rva;
    if (entry < dir_start)
        return 0;
    offset = (unsigned long long)(entry - dir_start);
    if (offset > (unsigned long long)view->dir_span ||
        (unsigned long long)view->dir_span - offset < (unsigned long long)DUET_RES_DATA_ENTRY_SIZE)
        return 0;
    if ((offset & 3ull) != 0ull)
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

__declspec(dllexport) HANDLE FindResourceExW(HANDLE hModule, const wchar_t16* lpType, const wchar_t16* lpName,
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

    /* The HRSRC is the data entry itself. Bounds-check it here so the
     * handle we hand out is one res_decode_hrsrc will accept. */
    if (duet_res_dir_at(&view, data_off, DUET_RES_DATA_ENTRY_SIZE) == (const unsigned char*)0)
    {
        SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND);
        return (HANDLE)0;
    }
    return (HANDLE)(void*)(view.base + view.dir_rva + data_off);
}

__declspec(dllexport) HANDLE FindResourceW(HANDLE hModule, const wchar_t16* lpName, const wchar_t16* lpType)
{
    /* Note the argument order: FindResource takes (name, type) while
     * FindResourceEx takes (type, name). */
    return FindResourceExW(hModule, lpType, lpName, 0);
}

/* Widen an ASCII type/name argument for the A-variants. A
 * MAKEINTRESOURCE integer passes through untouched. */
static const wchar_t16* res_widen(const char* s, wchar_t16* buf, unsigned int cap)
{
    unsigned int i = 0;
    if (s == (const char*)0)
        return (const wchar_t16*)0;
    if (((unsigned long long)(const void*)s >> 16) == 0ull)
        return (const wchar_t16*)(const void*)s;
    while (s[i] != 0 && i + 1u < cap)
    {
        buf[i] = (wchar_t16)(unsigned char)s[i];
        ++i;
    }
    buf[i] = 0;
    return buf;
}

__declspec(dllexport) HANDLE FindResourceExA(HANDLE hModule, const char* lpType, const char* lpName,
                                             unsigned short wLanguage)
{
    wchar_t16 type_buf[DUET_RES_NAME_MAX + 1u];
    wchar_t16 name_buf[DUET_RES_NAME_MAX + 1u];
    const wchar_t16* type = res_widen(lpType, type_buf, DUET_RES_NAME_MAX + 1u);
    const wchar_t16* name = res_widen(lpName, name_buf, DUET_RES_NAME_MAX + 1u);
    return FindResourceExW(hModule, type, name, wLanguage);
}

__declspec(dllexport) HANDLE FindResourceA(HANDLE hModule, const char* lpName, const char* lpType)
{
    return FindResourceExA(hModule, lpType, lpName, 0);
}

/* --- Load / Lock / Size / Free ------------------------------------- */

__declspec(dllexport) HANDLE LoadResource(HANDLE hModule, HANDLE hResInfo)
{
    DUET_RES_VIEW view;
    unsigned int rva;
    unsigned int size;
    if (!res_decode_hrsrc(hModule, hResInfo, &view, &rva, &size))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return (HANDLE)0;
    }
    /* The image is already mapped, so "loading" is address arithmetic.
     * The HGLOBAL is the data pointer itself. */
    return (HANDLE)(void*)(view.base + rva);
}

__declspec(dllexport) void* LockResource(HANDLE hResData)
{
    /* Identity by construction: LoadResource already returned the
     * mapped address. Win32 documents LockResource on a module resource
     * as a no-op lock for exactly this reason. */
    return (void*)hResData;
}

__declspec(dllexport) DWORD SizeofResource(HANDLE hModule, HANDLE hResInfo)
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

__declspec(dllexport) BOOL FreeResource(HANDLE hResData)
{
    /* Nothing was allocated — the bytes live in the module's own
     * mapping. Win32 documents FreeResource as returning FALSE on
     * success for 32-bit and later modules. */
    (void)hResData;
    return 0;
}

/* --- Enumeration --------------------------------------------------- */

/* Copy a directory entry's key into the NUL-terminated form the Win32
 * callbacks expect: a MAKEINTRESOURCE integer for an ordinal entry, or a
 * pointer into `buf` for a named one. Returns 0 when the name does not
 * fit, which skips that entry rather than truncating it into a different
 * name. */
static int res_key_to_callback_arg(const DUET_RES_KEY* key, wchar_t16* buf, unsigned int cap, wchar_t16** out)
{
    unsigned int i;
    if (!key->by_name)
    {
        *out = (wchar_t16*)(void*)(unsigned long long)key->id;
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

__declspec(dllexport) BOOL EnumResourceTypesW(HANDLE hModule, ENUMRESTYPEPROCW lpEnumFunc, LONG_PTR lParam)
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
            break; /* fail closed: a truncated table ends the walk */
        if (!res_key_to_callback_arg(&key, buf, DUET_RES_NAME_MAX + 1u, &arg))
            continue;
        any = 1;
        if (!lpEnumFunc(hModule, arg, lParam))
            return 1; /* callback asked to stop — still a success */
    }
    if (!any)
    {
        SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND);
        return 0;
    }
    return 1;
}

__declspec(dllexport) BOOL EnumResourceNamesW(HANDLE hModule, const wchar_t16* lpType, ENUMRESNAMEPROCW lpEnumFunc,
                                              LONG_PTR lParam)
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
