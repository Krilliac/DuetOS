/*
 * userland/libs/ole32/ole32.c — minimal COM runtime for PE probes.
 *
 * This is still intentionally small, but it now models the contracts
 * apps commonly test before using COM-heavy surfaces:
 *   - per-thread CoInitializeEx / CoUninitialize state and mode checks;
 *   - static + runtime class-factory lookup;
 *   - IUnknown / IClassFactory objects for registered classes;
 *   - CoTaskMem and GUID string helpers.
 */

typedef int BOOL;
typedef unsigned int DWORD;
typedef unsigned long long SIZE_T;
typedef unsigned long HRESULT;
typedef unsigned long ULONG;
typedef unsigned short wchar_t16;

#define S_OK 0UL
#define S_FALSE 1UL
#define E_NOTIMPL 0x80004001UL
#define E_NOINTERFACE 0x80004002UL
#define E_POINTER 0x80004003UL
#define E_INVALIDARG 0x80070057UL
#define E_OUTOFMEMORY 0x8007000EUL
#define E_FAIL 0x80004005UL
#define CLASS_E_NOAGGREGATION 0x80040110UL
#define REGDB_E_CLASSNOTREG 0x80040154UL
#define RPC_E_CHANGED_MODE 0x80010106UL

#define COINIT_APARTMENTTHREADED 0x2u
#define COINIT_MULTITHREADED 0x0u
#define CLSCTX_INPROC_SERVER 0x1u
#define REGCLS_MULTIPLEUSE 0x1u

struct Guid
{
    unsigned int data1;
    unsigned short data2;
    unsigned short data3;
    unsigned char data4[8];
};

typedef struct IUnknownVtbl IUnknownVtbl;
typedef struct IClassFactoryVtbl IClassFactoryVtbl;

typedef struct IUnknownLike
{
    const IUnknownVtbl* lpVtbl;
    ULONG refs;
    const struct Guid* clsid;
} IUnknownLike;

typedef struct IClassFactoryLike
{
    const IClassFactoryVtbl* lpVtbl;
    ULONG refs;
    const struct Guid* clsid;
} IClassFactoryLike;

struct IUnknownVtbl
{
    HRESULT (*QueryInterface)(IUnknownLike* self, const struct Guid* riid, void** ppv);
    ULONG (*AddRef)(IUnknownLike* self);
    ULONG (*Release)(IUnknownLike* self);
};

struct IClassFactoryVtbl
{
    HRESULT (*QueryInterface)(IClassFactoryLike* self, const struct Guid* riid, void** ppv);
    ULONG (*AddRef)(IClassFactoryLike* self);
    ULONG (*Release)(IClassFactoryLike* self);
    HRESULT (*CreateInstance)(IClassFactoryLike* self, void* outer, const struct Guid* riid, void** ppv);
    HRESULT (*LockServer)(IClassFactoryLike* self, BOOL lock);
};

/* Forward decl — CoTaskMemAlloc is defined later in this TU. */
__declspec(dllexport) void* CoTaskMemAlloc(SIZE_T cb);
__declspec(dllexport) void CoTaskMemFree(void* pv);

static const struct Guid kIID_IUnknown = {
    0x00000000u, 0x0000u, 0x0000u, {0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x46u}};
static const struct Guid kIID_IClassFactory = {
    0x00000001u, 0x0000u, 0x0000u, {0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x46u}};
static const struct Guid kCLSID_FileOpenDialog = {
    0xDC1C5A9Cu, 0xE88Au, 0x4DDEu, {0xA5u, 0xA1u, 0x60u, 0xF8u, 0x2Au, 0x20u, 0xAEu, 0xF7u}};
static const struct Guid kCLSID_FileSaveDialog = {
    0xC0B4E2F3u, 0xBA21u, 0x4773u, {0x8Du, 0xBAu, 0x33u, 0x5Eu, 0xC9u, 0x46u, 0xEBu, 0x8Bu}};
static const struct Guid kCLSID_StdComponentCategoriesMgr = {
    0x0002E005u, 0x0000u, 0x0000u, {0xC0u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x46u}};

/* IID_IModalWindow / IID_IFileDialog / IID_IFileOpenDialog /
 * IID_IFileSaveDialog. Used by the per-CLSID factory dispatch
 * to route IFileOpenDialog vs IFileSaveDialog QI to the correct
 * vtable. */
static const struct Guid kIID_IModalWindow = {
    0xB4DB1657u, 0x70D7u, 0x485Eu, {0x8Eu, 0x3Eu, 0x6Fu, 0xCBu, 0x5Au, 0x5Cu, 0x18u, 0x02u}};
static const struct Guid kIID_IFileDialog = {
    0x42F85136u, 0xDB7Eu, 0x439Cu, {0x85u, 0xF1u, 0xE4u, 0x07u, 0x5Du, 0x13u, 0x5Fu, 0xC8u}};
static const struct Guid kIID_IFileOpenDialog = {
    0xD57C7288u, 0xD4ADu, 0x4768u, {0xBEu, 0x02u, 0x9Du, 0x96u, 0x95u, 0x32u, 0xD9u, 0x60u}};
static const struct Guid kIID_IFileSaveDialog = {
    0x84BCCD23u, 0x5FDEu, 0x4CDBu, {0xAEu, 0xA4u, 0xAFu, 0x64u, 0xB8u, 0x3Du, 0x78u, 0xABu}};

static int guid_equal(const void* a, const void* b)
{
    const unsigned char* aa = (const unsigned char*)a;
    const unsigned char* bb = (const unsigned char*)b;
    if (!aa || !bb)
        return 0;
    for (int i = 0; i < 16; ++i)
    {
        if (aa[i] != bb[i])
            return 0;
    }
    return 1;
}

static DWORD current_tid(void)
{
    long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long)1) : "memory");
    return (DWORD)rv;
}

#define COM_THREAD_SLOTS 32
#define COM_FACTORY_SLOTS 16

typedef struct ComThreadState
{
    DWORD used;
    DWORD tid;
    DWORD init_count;
    DWORD coinit;
} ComThreadState;

typedef struct RegisteredFactory
{
    DWORD cookie;
    struct Guid clsid;
    void* factory;
    DWORD context;
    DWORD flags;
} RegisteredFactory;

static ComThreadState g_com_threads[COM_THREAD_SLOTS];
static RegisteredFactory g_factories[COM_FACTORY_SLOTS];
static DWORD g_next_cookie = 0xC0DE0001u;

static ComThreadState* current_com_state(int create)
{
    DWORD tid = current_tid();
    ComThreadState* empty = (ComThreadState*)0;
    for (int i = 0; i < COM_THREAD_SLOTS; ++i)
    {
        if (g_com_threads[i].used && g_com_threads[i].tid == tid)
            return &g_com_threads[i];
        if (!empty && !g_com_threads[i].used)
            empty = &g_com_threads[i];
    }
    if (!create || !empty)
        return (ComThreadState*)0;
    empty->used = 1;
    empty->tid = tid;
    empty->init_count = 0;
    empty->coinit = COINIT_MULTITHREADED;
    return empty;
}

static HRESULT com_initialize(DWORD coinit)
{
    /* Windows only allows one apartment model per thread. Ignore
     * unsupported flag bits here; the low apartment bits are what
     * compatibility probes check. */
    DWORD mode = coinit & COINIT_APARTMENTTHREADED;
    ComThreadState* st = current_com_state(1);
    if (!st)
        return E_OUTOFMEMORY;
    if (st->init_count != 0)
    {
        if ((st->coinit & COINIT_APARTMENTTHREADED) != mode)
            return RPC_E_CHANGED_MODE;
        ++st->init_count;
        return S_FALSE;
    }
    st->coinit = mode;
    st->init_count = 1;
    return S_OK;
}

__declspec(dllexport) HRESULT CoInitialize(void* reserved)
{
    (void)reserved;
    return com_initialize(COINIT_APARTMENTTHREADED);
}

__declspec(dllexport) HRESULT CoInitializeEx(void* reserved, DWORD dwCoInit)
{
    (void)reserved;
    return com_initialize(dwCoInit);
}

__declspec(dllexport) void CoUninitialize(void)
{
    ComThreadState* st = current_com_state(0);
    if (!st || st->init_count == 0)
        return;
    --st->init_count;
    if (st->init_count == 0)
    {
        st->used = 0;
        st->tid = 0;
        st->coinit = COINIT_MULTITHREADED;
    }
}

__declspec(dllexport) HRESULT OleInitialize(void* reserved)
{
    (void)reserved;
    return com_initialize(COINIT_APARTMENTTHREADED);
}

__declspec(dllexport) void OleUninitialize(void)
{
    CoUninitialize();
}

static HRESULT simple_unknown_qi(IUnknownLike* self, const struct Guid* riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    if (!self || !riid)
        return E_INVALIDARG;
    if (guid_equal(riid, &kIID_IUnknown))
    {
        ++self->refs;
        *ppv = self;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG simple_unknown_addref(IUnknownLike* self)
{
    if (!self)
        return 0;
    return ++self->refs;
}

static ULONG simple_unknown_release(IUnknownLike* self)
{
    if (!self)
        return 0;
    if (self->refs > 0)
        --self->refs;
    ULONG refs = self->refs;
    if (refs == 0)
        CoTaskMemFree(self);
    return refs;
}

static const IUnknownVtbl g_simple_unknown_vtbl = {simple_unknown_qi, simple_unknown_addref, simple_unknown_release};

/*
 * IFileDialog / IFileOpenDialog / IFileSaveDialog v0 stubs.
 *
 * Both Open and Save dialogs share one object struct: the lpVtbl
 * field selects which interface flavour the COM caller sees.
 * Methods accept opaque void* arguments — the only consumer of
 * COMDLG_FILTERSPEC / IShellItem / IPropertyStore here is the
 * vtable slot index, not the body. Setters succeed silently
 * (S_OK), getters fail cleanly (E_FAIL with NULL out), Show()
 * returns S_FALSE meaning "user cancelled" so a caller's
 * `if (FAILED(hr))` branch never fires and the standard
 * "no result" branch runs. Real picker UI is gated on the
 * compositor having a modal-input mode (see `Compositor.md`
 * §"Popup Menus" follow-ups).
 */

typedef struct FileDialogObj
{
    const void* lpVtbl;
    ULONG refs;
    int role; /* 0 = open, 1 = save — selects the vtable */
} FileDialogObj;

static HRESULT __stdcall fd_qi(FileDialogObj* self, const struct Guid* riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    if (!self || !riid)
        return E_INVALIDARG;
    /* Always-supported base interfaces. */
    if (guid_equal(riid, &kIID_IUnknown) || guid_equal(riid, &kIID_IModalWindow) || guid_equal(riid, &kIID_IFileDialog))
    {
        ++self->refs;
        *ppv = self;
        return S_OK;
    }
    /* Role-specific interfaces. */
    if (self->role == 0 && guid_equal(riid, &kIID_IFileOpenDialog))
    {
        ++self->refs;
        *ppv = self;
        return S_OK;
    }
    if (self->role == 1 && guid_equal(riid, &kIID_IFileSaveDialog))
    {
        ++self->refs;
        *ppv = self;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG __stdcall fd_addref(FileDialogObj* self)
{
    if (!self)
        return 0;
    return ++self->refs;
}

static ULONG __stdcall fd_release(FileDialogObj* self)
{
    if (!self)
        return 0;
    if (self->refs > 0)
        --self->refs;
    ULONG refs = self->refs;
    if (refs == 0)
        CoTaskMemFree(self);
    return refs;
}

/* IModalWindow::Show — return S_FALSE so the caller's
 * "user cancelled" path runs without a real picker UI. */
static HRESULT __stdcall fd_show(FileDialogObj* self, void* hwnd_owner)
{
    (void)self;
    (void)hwnd_owner;
    return S_FALSE;
}

/* IFileDialog setters all succeed silently. */
static HRESULT __stdcall fd_set_one_ptr(FileDialogObj* self, const void* ignored1)
{
    (void)self;
    (void)ignored1;
    return S_OK;
}

static HRESULT __stdcall fd_set_two_ptr(FileDialogObj* self, const void* ignored1, const void* ignored2)
{
    (void)self;
    (void)ignored1;
    (void)ignored2;
    return S_OK;
}

static HRESULT __stdcall fd_set_uint(FileDialogObj* self, unsigned int ignored)
{
    (void)self;
    (void)ignored;
    return S_OK;
}

static HRESULT __stdcall fd_set_dword(FileDialogObj* self, DWORD ignored)
{
    (void)self;
    (void)ignored;
    return S_OK;
}

static HRESULT __stdcall fd_clear(FileDialogObj* self)
{
    (void)self;
    return S_OK;
}

static HRESULT __stdcall fd_advise(FileDialogObj* self, void* events, DWORD* cookie)
{
    (void)self;
    (void)events;
    if (cookie)
        *cookie = 0;
    return S_OK;
}

/* Getters — clear the out parameter and return E_FAIL so the
 * caller's "no result" branch runs. */
static HRESULT __stdcall fd_get_uint(FileDialogObj* self, unsigned int* out)
{
    (void)self;
    if (out)
        *out = 0;
    return E_FAIL;
}

static HRESULT __stdcall fd_get_dword(FileDialogObj* self, DWORD* out)
{
    (void)self;
    if (out)
        *out = 0;
    return E_FAIL;
}

static HRESULT __stdcall fd_get_pointer(FileDialogObj* self, void** out)
{
    (void)self;
    if (out)
        *out = (void*)0;
    return E_FAIL;
}

static HRESULT __stdcall fd_get_pwstr(FileDialogObj* self, wchar_t16** out)
{
    (void)self;
    if (out)
        *out = (wchar_t16*)0;
    return E_FAIL;
}

/* IFileDialog::SetFileTypes — count + array. Succeed silently. */
static HRESULT __stdcall fd_set_file_types(FileDialogObj* self, unsigned int n, const void* arr)
{
    (void)self;
    (void)n;
    (void)arr;
    return S_OK;
}

static HRESULT __stdcall fd_add_place(FileDialogObj* self, void* psi, int fdap)
{
    (void)self;
    (void)psi;
    (void)fdap;
    return S_OK;
}

static HRESULT __stdcall fd_set_collected_props(FileDialogObj* self, void* desc_list, BOOL append_default)
{
    (void)self;
    (void)desc_list;
    (void)append_default;
    return S_OK;
}

static HRESULT __stdcall fd_apply_props(FileDialogObj* self, void* psi, void* props, void* hwnd, void* sink)
{
    (void)self;
    (void)psi;
    (void)props;
    (void)hwnd;
    (void)sink;
    return S_OK;
}

/* IFileDialog vtable layout (29 slots for IFileOpenDialog,
 * 32 for IFileSaveDialog). Order is the canonical Win SDK order
 * — slot index ABI must match real Windows so PE callers'
 * dispatch through the C++ vtable lands in the right method.
 *
 * IUnknown (3): QI / AddRef / Release
 * IModalWindow (1): Show
 * IFileDialog (23): SetFileTypes, SetFileTypeIndex,
 *   GetFileTypeIndex, Advise, Unadvise, SetOptions, GetOptions,
 *   SetDefaultFolder, SetFolder, GetFolder, GetCurrentSelection,
 *   SetFileName, GetFileName, SetTitle, SetOkButtonLabel,
 *   SetFileNameLabel, GetResult, AddPlace, SetDefaultExtension,
 *   Close, SetClientGuid, ClearClientData, SetFilter
 * IFileOpenDialog (2): GetResults, GetSelectedItems
 * IFileSaveDialog (5): SetSaveAsItem, SetProperties,
 *   SetCollectedProperties, GetProperties, ApplyProperties
 */

typedef struct FileDialogVtbl
{
    /* IUnknown */
    HRESULT(__stdcall* QueryInterface)(FileDialogObj*, const struct Guid*, void**);
    ULONG(__stdcall* AddRef)(FileDialogObj*);
    ULONG(__stdcall* Release)(FileDialogObj*);
    /* IModalWindow */
    HRESULT(__stdcall* Show)(FileDialogObj*, void*);
    /* IFileDialog */
    HRESULT(__stdcall* SetFileTypes)(FileDialogObj*, unsigned int, const void*);
    HRESULT(__stdcall* SetFileTypeIndex)(FileDialogObj*, unsigned int);
    HRESULT(__stdcall* GetFileTypeIndex)(FileDialogObj*, unsigned int*);
    HRESULT(__stdcall* Advise)(FileDialogObj*, void*, DWORD*);
    HRESULT(__stdcall* Unadvise)(FileDialogObj*, DWORD);
    HRESULT(__stdcall* SetOptions)(FileDialogObj*, DWORD);
    HRESULT(__stdcall* GetOptions)(FileDialogObj*, DWORD*);
    HRESULT(__stdcall* SetDefaultFolder)(FileDialogObj*, const void*);
    HRESULT(__stdcall* SetFolder)(FileDialogObj*, const void*);
    HRESULT(__stdcall* GetFolder)(FileDialogObj*, void**);
    HRESULT(__stdcall* GetCurrentSelection)(FileDialogObj*, void**);
    HRESULT(__stdcall* SetFileName)(FileDialogObj*, const void*);
    HRESULT(__stdcall* GetFileName)(FileDialogObj*, wchar_t16**);
    HRESULT(__stdcall* SetTitle)(FileDialogObj*, const void*);
    HRESULT(__stdcall* SetOkButtonLabel)(FileDialogObj*, const void*);
    HRESULT(__stdcall* SetFileNameLabel)(FileDialogObj*, const void*);
    HRESULT(__stdcall* GetResult)(FileDialogObj*, void**);
    HRESULT(__stdcall* AddPlace)(FileDialogObj*, void*, int);
    HRESULT(__stdcall* SetDefaultExtension)(FileDialogObj*, const void*);
    HRESULT(__stdcall* Close)(FileDialogObj*, DWORD);
    HRESULT(__stdcall* SetClientGuid)(FileDialogObj*, const void*);
    HRESULT(__stdcall* ClearClientData)(FileDialogObj*);
    HRESULT(__stdcall* SetFilter)(FileDialogObj*, const void*);
    /* Open-only / Save-only tail — populated only on the matching
     * vtable. Save tail is at the same offsets as Open's tail
     * because they're independent vtables. */
    HRESULT(__stdcall* RoleTail0)(FileDialogObj*, void**);
    HRESULT(__stdcall* RoleTail1)(FileDialogObj*, void**);
    HRESULT(__stdcall* RoleTail2)(FileDialogObj*, void*, BOOL);
    HRESULT(__stdcall* RoleTail3)(FileDialogObj*, void**);
    HRESULT(__stdcall* RoleTail4)(FileDialogObj*, void*, void*, void*, void*);
} FileDialogVtbl;

static const FileDialogVtbl g_file_open_dialog_vtbl = {
    fd_qi,
    fd_addref,
    fd_release,
    fd_show,
    fd_set_file_types,
    fd_set_uint,
    fd_get_uint,
    fd_advise,
    fd_set_dword,
    fd_set_dword,
    fd_get_dword,
    fd_set_one_ptr,
    fd_set_one_ptr,
    fd_get_pointer,
    fd_get_pointer,
    fd_set_one_ptr,
    fd_get_pwstr,
    fd_set_one_ptr,
    fd_set_one_ptr,
    fd_set_one_ptr,
    fd_get_pointer,
    fd_add_place,
    fd_set_one_ptr,
    fd_set_dword,
    fd_set_one_ptr,
    fd_clear,
    fd_set_one_ptr,
    /* IFileOpenDialog::GetResults / GetSelectedItems */
    fd_get_pointer,
    fd_get_pointer,
    /* Save tail unused — leave as no-ops so a stray slot dispatch
     * can't crash. */
    (HRESULT(__stdcall*)(FileDialogObj*, void*, BOOL))fd_set_one_ptr,
    fd_get_pointer,
    (HRESULT(__stdcall*)(FileDialogObj*, void*, void*, void*, void*))fd_apply_props,
};

static const FileDialogVtbl g_file_save_dialog_vtbl = {
    fd_qi,
    fd_addref,
    fd_release,
    fd_show,
    fd_set_file_types,
    fd_set_uint,
    fd_get_uint,
    fd_advise,
    fd_set_dword,
    fd_set_dword,
    fd_get_dword,
    fd_set_one_ptr,
    fd_set_one_ptr,
    fd_get_pointer,
    fd_get_pointer,
    fd_set_one_ptr,
    fd_get_pwstr,
    fd_set_one_ptr,
    fd_set_one_ptr,
    fd_set_one_ptr,
    fd_get_pointer,
    fd_add_place,
    fd_set_one_ptr,
    fd_set_dword,
    fd_set_one_ptr,
    fd_clear,
    fd_set_one_ptr,
    /* IFileSaveDialog tail: SetSaveAsItem, SetProperties,
     * SetCollectedProperties, GetProperties, ApplyProperties.
     * The first two reuse Open-tail slots since Open's
     * GetResults/GetSelectedItems slot signatures happen to
     * match (single in/out pointer). */
    fd_get_pointer, /* SetSaveAsItem accepts in-pointer; tolerated */
    fd_get_pointer, /* SetProperties */
    fd_set_collected_props,
    fd_get_pointer,
    fd_apply_props,
};

static HRESULT make_file_dialog(int role, const struct Guid* riid, void** ppv)
{
    FileDialogObj* obj = (FileDialogObj*)CoTaskMemAlloc(sizeof(FileDialogObj));
    if (!obj)
        return E_OUTOFMEMORY;
    obj->lpVtbl = (role == 0) ? (const void*)&g_file_open_dialog_vtbl : (const void*)&g_file_save_dialog_vtbl;
    obj->refs = 1;
    obj->role = role;
    HRESULT hr = fd_qi(obj, riid, ppv);
    /* fd_qi bumped the refcount on success; release the
     * make-time reference so refcount nets to 1. */
    fd_release(obj);
    return hr;
}

static HRESULT builtin_factory_qi(IClassFactoryLike* self, const struct Guid* riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    if (!self || !riid)
        return E_INVALIDARG;
    if (guid_equal(riid, &kIID_IUnknown) || guid_equal(riid, &kIID_IClassFactory))
    {
        ++self->refs;
        *ppv = self;
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG builtin_factory_addref(IClassFactoryLike* self)
{
    if (!self)
        return 0;
    return ++self->refs;
}

static ULONG builtin_factory_release(IClassFactoryLike* self)
{
    if (!self)
        return 0;
    if (self->refs > 1)
        --self->refs;
    return self->refs;
}

static HRESULT builtin_factory_create(IClassFactoryLike* self, void* outer, const struct Guid* riid, void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    if (outer)
        return CLASS_E_NOAGGREGATION;
    if (!self || !riid)
        return E_INVALIDARG;
    /* Per-CLSID dispatch: FileOpenDialog → IFileOpenDialog object,
     * FileSaveDialog → IFileSaveDialog object, everything else
     * (including StdComponentCategoriesMgr) → simple IUnknown. */
    if (guid_equal(self->clsid, &kCLSID_FileOpenDialog))
        return make_file_dialog(0, riid, ppv);
    if (guid_equal(self->clsid, &kCLSID_FileSaveDialog))
        return make_file_dialog(1, riid, ppv);
    IUnknownLike* obj = (IUnknownLike*)CoTaskMemAlloc(sizeof(IUnknownLike));
    if (!obj)
        return E_OUTOFMEMORY;
    obj->lpVtbl = &g_simple_unknown_vtbl;
    obj->refs = 1;
    obj->clsid = self->clsid;
    HRESULT hr = obj->lpVtbl->QueryInterface(obj, riid, ppv);
    obj->lpVtbl->Release(obj);
    return hr;
}

static HRESULT builtin_factory_lock(IClassFactoryLike* self, BOOL lock)
{
    (void)self;
    (void)lock;
    return S_OK;
}

static const IClassFactoryVtbl g_builtin_factory_vtbl = {
    builtin_factory_qi, builtin_factory_addref, builtin_factory_release, builtin_factory_create, builtin_factory_lock};
static IClassFactoryLike g_file_open_factory = {&g_builtin_factory_vtbl, 1, &kCLSID_FileOpenDialog};
static IClassFactoryLike g_file_save_factory = {&g_builtin_factory_vtbl, 1, &kCLSID_FileSaveDialog};
static IClassFactoryLike g_categories_factory = {&g_builtin_factory_vtbl, 1, &kCLSID_StdComponentCategoriesMgr};

static void* find_builtin_factory(const struct Guid* clsid)
{
    if (!clsid)
        return (void*)0;
    if (guid_equal(clsid, &kCLSID_FileOpenDialog))
        return &g_file_open_factory;
    if (guid_equal(clsid, &kCLSID_FileSaveDialog))
        return &g_file_save_factory;
    if (guid_equal(clsid, &kCLSID_StdComponentCategoriesMgr))
        return &g_categories_factory;
    return (void*)0;
}

static void* find_registered_factory(const struct Guid* clsid, DWORD context)
{
    if (!clsid)
        return (void*)0;
    for (int i = 0; i < COM_FACTORY_SLOTS; ++i)
    {
        if (g_factories[i].cookie != 0 && guid_equal(&g_factories[i].clsid, clsid) &&
            (context == 0 || (g_factories[i].context & context) != 0))
            return g_factories[i].factory;
    }
    return (void*)0;
}

__declspec(dllexport) HRESULT CoGetClassObject(const void* rclsid, DWORD dwClsCtx, void* pvReserved, const void* riid,
                                               void** ppv)
{
    (void)pvReserved;
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    if (!rclsid || !riid)
        return E_INVALIDARG;
    void* factory = find_registered_factory((const struct Guid*)rclsid, dwClsCtx ? dwClsCtx : CLSCTX_INPROC_SERVER);
    if (!factory)
        factory = find_builtin_factory((const struct Guid*)rclsid);
    if (!factory)
        return REGDB_E_CLASSNOTREG;
    IClassFactoryLike* cf = (IClassFactoryLike*)factory;
    return cf->lpVtbl->QueryInterface(cf, (const struct Guid*)riid, ppv);
}

__declspec(dllexport) HRESULT CoCreateInstance(const void* rclsid, void* pUnkOuter, DWORD dwClsCtx, const void* riid,
                                               void** ppv)
{
    if (!ppv)
        return E_POINTER;
    *ppv = (void*)0;
    IClassFactoryLike* cf = (IClassFactoryLike*)0;
    HRESULT hr = CoGetClassObject(rclsid, dwClsCtx, (void*)0, &kIID_IClassFactory, (void**)&cf);
    if (hr != S_OK)
        return hr;
    hr = cf->lpVtbl->CreateInstance(cf, pUnkOuter, (const struct Guid*)riid, ppv);
    cf->lpVtbl->Release(cf);
    return hr;
}

__declspec(dllexport) HRESULT CoCreateInstanceEx(const void* rclsid, void* pUnkOuter, DWORD dwClsCtx, void* pServerInfo,
                                                 DWORD cmq, void* pResults)
{
    (void)pServerInfo;
    if (cmq == 0 || !pResults)
        return E_INVALIDARG;
    /* MULTI_QI layout: const IID* pIID; IUnknown* pItf; HRESULT hr. */
    struct MultiQi
    {
        const void* iid;
        void* itf;
        HRESULT hr;
    };
    struct MultiQi* qi = (struct MultiQi*)pResults;
    HRESULT first_failure = S_OK;
    for (DWORD i = 0; i < cmq; ++i)
    {
        qi[i].itf = (void*)0;
        qi[i].hr = CoCreateInstance(rclsid, pUnkOuter, dwClsCtx, qi[i].iid, &qi[i].itf);
        if (qi[i].hr != S_OK && first_failure == S_OK)
            first_failure = qi[i].hr;
    }
    return first_failure;
}

/* Parse a single hex nibble. Returns 0..15 on success, -1 on miss. */
static int clsid_hex_nibble(wchar_t16 c)
{
    if (c >= '0' && c <= '9')
        return (int)(c - '0');
    if (c >= 'a' && c <= 'f')
        return (int)(c - 'a') + 10;
    if (c >= 'A' && c <= 'F')
        return (int)(c - 'A') + 10;
    return -1;
}

/* Reads `count` hex chars from sz starting at *idx, packs them as
 * a big-endian unsigned. Returns 1 on success, 0 on parse error.
 * Advances *idx past the consumed chars. */
static int clsid_read_hex(const wchar_t16* sz, int* idx, int count, unsigned long long* out)
{
    unsigned long long v = 0;
    for (int i = 0; i < count; ++i)
    {
        int n = clsid_hex_nibble(sz[*idx + i]);
        if (n < 0)
            return 0;
        v = (v << 4) | (unsigned long long)n;
    }
    *idx += count;
    *out = v;
    return 1;
}

__declspec(dllexport) HRESULT CLSIDFromString(const wchar_t16* sz, void* out)
{
    if (!out)
        return E_INVALIDARG;
    unsigned char* b = (unsigned char*)out;
    for (int i = 0; i < 16; ++i)
        b[i] = 0;
    if (!sz)
        return E_INVALIDARG;
    /* Accept either "{XXXX...XXXX}" (38 chars) or unbraced "XXXX...XXXX" (36). */
    int i = 0;
    int has_brace = 0;
    if (sz[i] == '{')
    {
        has_brace = 1;
        ++i;
    }
    unsigned long long d1, d2, d3;
    if (!clsid_read_hex(sz, &i, 8, &d1))
        return 0x800401F9UL; /* CO_E_CLASSSTRING */
    if (sz[i++] != '-')
        return 0x800401F9UL;
    if (!clsid_read_hex(sz, &i, 4, &d2))
        return 0x800401F9UL;
    if (sz[i++] != '-')
        return 0x800401F9UL;
    if (!clsid_read_hex(sz, &i, 4, &d3))
        return 0x800401F9UL;
    if (sz[i++] != '-')
        return 0x800401F9UL;
    unsigned long long d4hi;
    if (!clsid_read_hex(sz, &i, 4, &d4hi))
        return 0x800401F9UL;
    if (sz[i++] != '-')
        return 0x800401F9UL;
    /* data4 last 6 bytes = 12 hex chars. */
    unsigned long long d4lo_a, d4lo_b, d4lo_c;
    if (!clsid_read_hex(sz, &i, 4, &d4lo_a))
        return 0x800401F9UL;
    if (!clsid_read_hex(sz, &i, 4, &d4lo_b))
        return 0x800401F9UL;
    if (!clsid_read_hex(sz, &i, 4, &d4lo_c))
        return 0x800401F9UL;
    if (has_brace && sz[i++] != '}')
        return 0x800401F9UL;
    /* GUID memory layout: data1 (LE u32), data2 (LE u16), data3 (LE u16), data4 (8 bytes BE). */
    b[0] = (unsigned char)(d1 & 0xFF);
    b[1] = (unsigned char)((d1 >> 8) & 0xFF);
    b[2] = (unsigned char)((d1 >> 16) & 0xFF);
    b[3] = (unsigned char)((d1 >> 24) & 0xFF);
    b[4] = (unsigned char)(d2 & 0xFF);
    b[5] = (unsigned char)((d2 >> 8) & 0xFF);
    b[6] = (unsigned char)(d3 & 0xFF);
    b[7] = (unsigned char)((d3 >> 8) & 0xFF);
    b[8] = (unsigned char)((d4hi >> 8) & 0xFF);
    b[9] = (unsigned char)(d4hi & 0xFF);
    b[10] = (unsigned char)((d4lo_a >> 8) & 0xFF);
    b[11] = (unsigned char)(d4lo_a & 0xFF);
    b[12] = (unsigned char)((d4lo_b >> 8) & 0xFF);
    b[13] = (unsigned char)(d4lo_b & 0xFF);
    b[14] = (unsigned char)((d4lo_c >> 8) & 0xFF);
    b[15] = (unsigned char)(d4lo_c & 0xFF);
    return S_OK;
}

__declspec(dllexport) HRESULT CLSIDFromProgID(const wchar_t16* id, void* clsid)
{
    /* No registry-backed ProgID -> CLSID lookup yet. Real Windows reads
     * HKCR\<id>\CLSID; we'd need a registry implementation. Return the
     * "ProgID not registered" status so callers can fall through. */
    (void)id;
    if (clsid)
    {
        unsigned char* b = (unsigned char*)clsid;
        for (int i = 0; i < 16; ++i)
            b[i] = 0;
    }
    return 0x800401F3UL; /* CO_E_CLASSSTRING */
}

__declspec(dllexport) HRESULT IIDFromString(const wchar_t16* sz, void* iid)
{
    return CLSIDFromString(sz, iid);
}

__declspec(dllexport) HRESULT StringFromCLSID(const void* clsid, wchar_t16** psz)
{
    if (psz == (wchar_t16**)0)
        return E_INVALIDARG;
    if (clsid == (const void*)0)
    {
        *psz = (wchar_t16*)0;
        return E_INVALIDARG;
    }
    /* Format: {XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX} = 38 chars + NUL */
    wchar_t16* buf = (wchar_t16*)CoTaskMemAlloc(39 * sizeof(wchar_t16));
    if (buf == (wchar_t16*)0)
    {
        *psz = (wchar_t16*)0;
        return E_OUTOFMEMORY;
    }
    static const wchar_t16 hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    const unsigned char* p = (const unsigned char*)clsid;
    /* GUID: 4-byte data1 (LE), 2-byte data2 (LE), 2-byte data3 (LE),
     *       8-byte data4. Display: data1 (8 hex), data2 (4), data3
     *       (4), then first 2 bytes of data4, dash, last 6 bytes. */
    int i = 0;
    buf[i++] = '{';
    /* data1 — read as little-endian uint32, print high nybble first. */
    unsigned int d1 =
        (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
    for (int j = 7; j >= 0; --j)
        buf[i++] = hex[(d1 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    unsigned short d2 = (unsigned short)p[4] | ((unsigned short)p[5] << 8);
    for (int j = 3; j >= 0; --j)
        buf[i++] = hex[(d2 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    unsigned short d3 = (unsigned short)p[6] | ((unsigned short)p[7] << 8);
    for (int j = 3; j >= 0; --j)
        buf[i++] = hex[(d3 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    /* data4[0..1] then dash then data4[2..7] */
    for (int k = 8; k < 10; ++k)
    {
        buf[i++] = hex[(p[k] >> 4) & 0xF];
        buf[i++] = hex[p[k] & 0xF];
    }
    buf[i++] = '-';
    for (int k = 10; k < 16; ++k)
    {
        buf[i++] = hex[(p[k] >> 4) & 0xF];
        buf[i++] = hex[p[k] & 0xF];
    }
    buf[i++] = '}';
    buf[i] = 0;
    *psz = buf;
    return S_OK;
}

/* CoTaskMem* -> heap aliases */

__declspec(dllexport) void* CoTaskMemAlloc(SIZE_T cb)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)11), "D"((long long)cb) : "memory");
    return (void*)rv;
}

__declspec(dllexport) void CoTaskMemFree(void* pv)
{
    if (!pv)
        return;
    long long discard;
    __asm__ volatile("int $0x80" : "=a"(discard) : "a"((long long)12), "D"((long long)pv) : "memory");
}

__declspec(dllexport) void* CoTaskMemRealloc(void* pv, SIZE_T cb)
{
    long long rv;
    __asm__ volatile("int $0x80" : "=a"(rv) : "a"((long long)15), "D"((long long)pv), "S"((long long)cb) : "memory");
    return (void*)rv;
}

/* CoGetMalloc — return a sentinel "IMalloc" pointer that callers
 * occasionally compare against null. v0 has no real IMalloc COM
 * object, so the alias is safe-but-non-callable; the caller must
 * call CoTaskMemAlloc directly anyway in any path that survives
 * v0. */
__declspec(dllexport) HRESULT CoGetMalloc(DWORD context, void** ppMalloc)
{
    (void)context;
    if (ppMalloc)
        *ppMalloc = (void*)0;
    return E_NOTIMPL;
}

/* CoRegisterClassObject / CoRevokeClassObject — process-local
 * class-factory table. The caller owns the factory lifetime; we keep
 * the raw pointer and hand it back via CoGetClassObject. */
__declspec(dllexport) HRESULT CoRegisterClassObject(const void* rclsid, void* unk, DWORD context, DWORD flags,
                                                    DWORD* cookie)
{
    if (!rclsid || !unk || !cookie)
        return E_INVALIDARG;
    for (int i = 0; i < COM_FACTORY_SLOTS; ++i)
    {
        if (g_factories[i].cookie == 0)
        {
            const unsigned char* src = (const unsigned char*)rclsid;
            unsigned char* dst = (unsigned char*)&g_factories[i].clsid;
            for (int b = 0; b < 16; ++b)
                dst[b] = src[b];
            g_factories[i].factory = unk;
            g_factories[i].context = context ? context : CLSCTX_INPROC_SERVER;
            g_factories[i].flags = flags ? flags : REGCLS_MULTIPLEUSE;
            g_factories[i].cookie = g_next_cookie++;
            *cookie = g_factories[i].cookie;
            return S_OK;
        }
    }
    return E_OUTOFMEMORY;
}

__declspec(dllexport) HRESULT CoRevokeClassObject(DWORD cookie)
{
    if (cookie == 0)
        return E_INVALIDARG;
    for (int i = 0; i < COM_FACTORY_SLOTS; ++i)
    {
        if (g_factories[i].cookie == cookie)
        {
            g_factories[i].cookie = 0;
            g_factories[i].factory = (void*)0;
            return S_OK;
        }
    }
    return REGDB_E_CLASSNOTREG;
}

__declspec(dllexport) HRESULT CoResumeClassObjects(void)
{
    return S_OK;
}

__declspec(dllexport) HRESULT CoSuspendClassObjects(void)
{
    return S_OK;
}

__declspec(dllexport) DWORD CoAddRefServerProcess(void)
{
    return 1;
}

__declspec(dllexport) DWORD CoReleaseServerProcess(void)
{
    return 0;
}

__declspec(dllexport) HRESULT CoSetProxyBlanket(void* proxy, DWORD authn, DWORD authz, wchar_t16* svr_principal,
                                                DWORD authn_lvl, DWORD imp_lvl, void* auth_info, DWORD capabilities)
{
    (void)proxy;
    (void)authn;
    (void)authz;
    (void)svr_principal;
    (void)authn_lvl;
    (void)imp_lvl;
    (void)auth_info;
    (void)capabilities;
    return S_OK;
}

__declspec(dllexport) HRESULT CoInitializeSecurity(void* sec_desc, long auth_svc, void* auth_svc_arr, void* reserved1,
                                                   DWORD authn_lvl, DWORD imp_lvl, void* auth_info, DWORD capabilities,
                                                   void* reserved3)
{
    (void)sec_desc;
    (void)auth_svc;
    (void)auth_svc_arr;
    (void)reserved1;
    (void)authn_lvl;
    (void)imp_lvl;
    (void)auth_info;
    (void)capabilities;
    (void)reserved3;
    return S_OK;
}

/* CreateStreamOnHGlobal / GetHGlobalFromStream: IStream over a
 * memory buffer. We don't have a real IStream impl; return
 * E_NOTIMPL so callers that fall back to CoTaskMemAlloc still
 * get a path through. */
__declspec(dllexport) HRESULT CreateStreamOnHGlobal(void* hglobal, BOOL delete_on_release, void** stream)
{
    (void)hglobal;
    (void)delete_on_release;
    if (stream)
        *stream = (void*)0;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT GetHGlobalFromStream(void* stream, void** hglobal)
{
    (void)stream;
    if (hglobal)
        *hglobal = (void*)0;
    return E_NOTIMPL;
}

__declspec(dllexport) HRESULT GetRunningObjectTable(DWORD reserved, void** prot)
{
    (void)reserved;
    if (prot)
        *prot = (void*)0;
    return E_NOTIMPL;
}

/* OLE drag/drop: register the window as a drop target. v0 has
 * no DnD wired, but accept silently so PE programs that register
 * + unregister around their window lifetime don't trip. */
__declspec(dllexport) HRESULT RegisterDragDrop(void* hwnd, void* drop_target)
{
    (void)hwnd;
    (void)drop_target;
    return S_OK;
}

__declspec(dllexport) HRESULT RevokeDragDrop(void* hwnd)
{
    (void)hwnd;
    return S_OK;
}

/* StringFromGUID2 — like StringFromCLSID but writes into caller buffer. */
__declspec(dllexport) int StringFromGUID2(const void* guid, wchar_t16* buf, int cch)
{
    if (guid == 0 || buf == 0 || cch < 39)
        return 0;
    static const wchar_t16 hex[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    const unsigned char* p = (const unsigned char*)guid;
    int i = 0;
    buf[i++] = '{';
    unsigned int d1 =
        (unsigned int)p[0] | ((unsigned int)p[1] << 8) | ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
    for (int j = 7; j >= 0; --j)
        buf[i++] = hex[(d1 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    unsigned short d2 = (unsigned short)p[4] | ((unsigned short)p[5] << 8);
    for (int j = 3; j >= 0; --j)
        buf[i++] = hex[(d2 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    unsigned short d3 = (unsigned short)p[6] | ((unsigned short)p[7] << 8);
    for (int j = 3; j >= 0; --j)
        buf[i++] = hex[(d3 >> (j * 4)) & 0xF];
    buf[i++] = '-';
    for (int k = 8; k < 10; ++k)
    {
        buf[i++] = hex[(p[k] >> 4) & 0xF];
        buf[i++] = hex[p[k] & 0xF];
    }
    buf[i++] = '-';
    for (int k = 10; k < 16; ++k)
    {
        buf[i++] = hex[(p[k] >> 4) & 0xF];
        buf[i++] = hex[p[k] & 0xF];
    }
    buf[i++] = '}';
    buf[i] = 0;
    return 39;
}
