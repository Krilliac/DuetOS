/*
 * userland/libs/dinput8/dinput8.c — DuetOS DirectInput 8 v0.
 *
 * Provides the IDirectInput8 + IDirectInputDevice8 COM surface so PEs
 * that initialise input via DirectInput don't crash. v0 reports zero
 * connected joysticks and returns empty key/mouse state buffers; the
 * keyboard/mouse path that real apps depend on is GetAsyncKeyState +
 * GetCursorPos (in user32) which we already implement, so this DLL
 * is mostly a probe-satisfier.
 *
 * Exports:
 *   DirectInput8Create
 *
 * Build: tools/build/build-stub-dll.sh (base 0x10270000).
 */

#include "../dx_shared.h"

/* IID_IDirectInput8W = {bf798031-483a-4da2-aa99-5d64ed369700} */
static const DxGuid kIID_IDirectInput8W = {
    0xbf798031, 0x483a, 0x4da2, {0xaa, 0x99, 0x5d, 0x64, 0xed, 0x36, 0x97, 0x00}};
/* IID_IDirectInput8A = {bf798030-483a-4da2-aa99-5d64ed369700} */
static const DxGuid kIID_IDirectInput8A = {
    0xbf798030, 0x483a, 0x4da2, {0xaa, 0x99, 0x5d, 0x64, 0xed, 0x36, 0x97, 0x00}};
/* IID_IDirectInputDevice8W = {54d41081-dc15-4833-a41b-748f73a38179} */
static const DxGuid kIID_IDirectInputDevice8W = {
    0x54d41081, 0xdc15, 0x4833, {0xa4, 0x1b, 0x74, 0x8f, 0x73, 0xa3, 0x81, 0x79}};

/* ---------------------------------------------------------------- *
 * IDirectInputDevice8 — IUnknown(3) + 28 device methods.           *
 * v0 implements:                                                    *
 *   slot 6  GetCapabilities (zero-fill)                             *
 *   slot 7  EnumObjects (no objects)                                *
 *   slot 9  Acquire / 10 Unacquire                                  *
 *   slot 10 GetDeviceState (zero-fill)                              *
 *   slot 11 GetDeviceData (no buffered)                             *
 * Most others → DX_HSTUB.                                           *
 * ---------------------------------------------------------------- */

#define DIDEV_VTBL_SLOTS 31

typedef struct DiDeviceImpl
{
    void* const* lpVtbl;
    ULONG refcount;
    UINT format_size; /* size requested by SetDataFormat */
} DiDeviceImpl;

static HRESULT didev_QueryInterface(DiDeviceImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirectInputDevice8W))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG didev_AddRef(DiDeviceImpl* self)
{
    return ++self->refcount;
}
static ULONG didev_Release(DiDeviceImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT didev_GetCapabilities(DiDeviceImpl* self, void* caps)
{
    (void)self;
    if (caps)
        dx_memzero(caps, 24); /* DIDEVCAPS, leading dwSize is enough */
    return DX_S_OK;
}
static HRESULT didev_SetDataFormat(DiDeviceImpl* self, const void* fmt)
{
    (void)fmt;
    self->format_size = 256; /* enough for keyboard/mouse buffer */
    return DX_S_OK;
}
static HRESULT didev_SetCooperativeLevel(DiDeviceImpl* self, HWND h, DWORD f)
{
    (void)self;
    (void)h;
    (void)f;
    return DX_S_OK;
}
static HRESULT didev_Acquire(DiDeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static HRESULT didev_Unacquire(DiDeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}
static HRESULT didev_GetDeviceState(DiDeviceImpl* self, DWORD size, void* data)
{
    (void)self;
    if (data && size > 0 && size < 4096)
        dx_memzero(data, size);
    return DX_S_OK;
}
static HRESULT didev_GetDeviceData(DiDeviceImpl* self, DWORD obj_size, void* rg, DWORD* in_out, DWORD flags)
{
    (void)self;
    (void)obj_size;
    (void)rg;
    (void)flags;
    if (in_out)
        *in_out = 0; /* no buffered events */
    return DX_S_OK;
}
static HRESULT didev_Poll(DiDeviceImpl* self)
{
    (void)self;
    return DX_S_OK;
}

static void* g_didev_vtbl[DIDEV_VTBL_SLOTS];
static void didev_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DIDEV_VTBL_SLOTS; ++i)
        g_didev_vtbl[i] = DX_HSTUB;
    g_didev_vtbl[0] = (void*)didev_QueryInterface;
    g_didev_vtbl[1] = (void*)didev_AddRef;
    g_didev_vtbl[2] = (void*)didev_Release;
    g_didev_vtbl[3] = (void*)didev_GetCapabilities;
    g_didev_vtbl[9] = (void*)didev_SetDataFormat;
    g_didev_vtbl[10] = (void*)didev_GetDeviceState;
    g_didev_vtbl[11] = (void*)didev_GetDeviceData;
    g_didev_vtbl[12] = (void*)didev_Acquire;
    g_didev_vtbl[13] = (void*)didev_Unacquire;
    g_didev_vtbl[14] = (void*)didev_SetCooperativeLevel;
    g_didev_vtbl[25] = (void*)didev_Poll;
}

static DiDeviceImpl* didev_alloc(void)
{
    didev_init_vtbl_once();
    DiDeviceImpl* d = (DiDeviceImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return NULL;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_didev_vtbl;
    d->refcount = 1;
    return d;
}

/* ---------------------------------------------------------------- *
 * IDirectInput8 — IUnknown(3) + 12 methods                         *
 *   slot 3  CreateDevice                                            *
 *   slot 4  EnumDevices (no devices)                                *
 *   slot 5  GetDeviceStatus                                         *
 *   slot 6  RunControlPanel                                         *
 *   slot 7  Initialize                                              *
 * ---------------------------------------------------------------- */

#define DI_VTBL_SLOTS 12

typedef struct DiImpl
{
    void* const* lpVtbl;
    ULONG refcount;
} DiImpl;

static HRESULT di_QueryInterface(DiImpl* self, REFIID riid, void** out)
{
    if (!out)
        return DX_E_POINTER;
    if (dx_guid_eq(riid, &kIID_IUnknown) || dx_guid_eq(riid, &kIID_IDirectInput8W) ||
        dx_guid_eq(riid, &kIID_IDirectInput8A))
    {
        self->refcount++;
        *out = self;
        return DX_S_OK;
    }
    *out = NULL;
    return DX_E_NOINTERFACE;
}
static ULONG di_AddRef(DiImpl* self)
{
    return ++self->refcount;
}
static ULONG di_Release(DiImpl* self)
{
    if (--self->refcount == 0)
    {
        dx_heap_free(self);
        return 0;
    }
    return self->refcount;
}
static HRESULT di_CreateDevice(DiImpl* self, REFIID guid, void** dev_out, void* unk)
{
    (void)self;
    (void)guid;
    (void)unk;
    if (!dev_out)
        return DX_E_POINTER;
    DiDeviceImpl* d = didev_alloc();
    if (!d)
    {
        *dev_out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *dev_out = d;
    return DX_S_OK;
}
static HRESULT di_EnumDevices(DiImpl* self, DWORD type, void* cb, void* ctx, DWORD flags)
{
    (void)self;
    (void)type;
    (void)cb;
    (void)ctx;
    (void)flags;
    /* No devices to enumerate. */
    return DX_S_OK;
}
static HRESULT di_GetDeviceStatus(DiImpl* self, REFIID guid)
{
    (void)self;
    (void)guid;
    return DX_S_OK;
}
static HRESULT di_Initialize(DiImpl* self, HMODULE inst, DWORD ver)
{
    (void)self;
    (void)inst;
    (void)ver;
    return DX_S_OK;
}

static void* g_di_vtbl[DI_VTBL_SLOTS];
static void di_init_vtbl_once(void)
{
    static int g_inited = 0;
    if (g_inited)
        return;
    g_inited = 1;
    for (int i = 0; i < DI_VTBL_SLOTS; ++i)
        g_di_vtbl[i] = DX_HSTUB;
    g_di_vtbl[0] = (void*)di_QueryInterface;
    g_di_vtbl[1] = (void*)di_AddRef;
    g_di_vtbl[2] = (void*)di_Release;
    g_di_vtbl[3] = (void*)di_CreateDevice;
    g_di_vtbl[4] = (void*)di_EnumDevices;
    g_di_vtbl[5] = (void*)di_GetDeviceStatus;
    g_di_vtbl[7] = (void*)di_Initialize;
}

static DiImpl* di_alloc(void)
{
    di_init_vtbl_once();
    DiImpl* d = (DiImpl*)dx_heap_alloc(sizeof(*d));
    if (!d)
        return NULL;
    dx_memzero(d, sizeof(*d));
    d->lpVtbl = g_di_vtbl;
    d->refcount = 1;
    return d;
}

__declspec(dllexport) HRESULT DirectInput8Create(HMODULE inst, DWORD ver, REFIID riid, void** out, void* unk)
{
    (void)inst;
    (void)ver;
    (void)riid;
    (void)unk;
    dx_gfx_trace(5);
    if (!out)
        return DX_E_POINTER;
    DiImpl* d = di_alloc();
    if (!d)
    {
        *out = NULL;
        return DX_E_OUTOFMEMORY;
    }
    *out = d;
    return DX_S_OK;
}
